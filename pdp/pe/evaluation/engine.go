package evaluation

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
	"time"

	"pdp/config"
	"pdp/models"
	perisk "pdp/pe/risk"
)

// AccessContext is the normalized, side-effect-free input evaluated by PE.
// PA is responsible for loading rules, user attributes, risk signals, and
// device data before calling the engine.
type AccessContext struct {
	Request             models.AccessRequest
	Rules               []*models.PolicyRule
	UserRole            string
	UserEmail           string
	DirectoryUserID     string
	DirectoryUserName   string
	DirectoryGroupIDs   []string
	DirectoryGroupNames []string
	FailedAttempts      int
	Now                 time.Time
	GeoVelocity         float64
	IsImpossibleTravel  bool
}

// Engine is the Policy Engine. It evaluates normalized access context and
// returns a deterministic decision without creating sessions, provisioning
// Gateways, signing certificates, or writing audit records.
type Engine struct {
	riskConfig config.RiskConfig
}

func NewEngine(riskConfigs ...config.RiskConfig) *Engine {
	cfg := &config.Config{}
	if len(riskConfigs) > 0 {
		cfg.Risk = riskConfigs[0]
	}
	cfg.ApplyDefaults()
	return &Engine{riskConfig: cfg.Risk}
}

// Evaluate processes a normalized access context against enabled policy rules.
// Rules are evaluated in priority order by PA/store before they reach PE.
func (e *Engine) Evaluate(ctx AccessContext) *models.AccessDecision {
	req := ctx.Request
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}

	log.Printf("[PE] Evaluating access: user=%s resource=%s:%d protocol=%s",
		req.Username, req.Resource, req.ResourcePort, req.Protocol)

	riskCtx := models.RiskContext{
		UserID:             req.UserID,
		SourceIP:           req.SourceIP,
		DeviceHealth:       req.DeviceHealth,
		FailedAttempts:     ctx.FailedAttempts,
		TimeOfDay:          now,
		Protocol:           req.Protocol,
		GeoVelocity:        ctx.GeoVelocity,
		IsImpossibleTravel: ctx.IsImpossibleTravel,
		AnomalyAlerts:      req.AnomalyAlerts,
		AnomalyScore:       req.AnomalyScore,
	}
	riskScore := perisk.CalculateRiskScore(riskCtx, e.riskConfig)

	for _, rule := range ctx.Rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		if e.matchesRule(rule, ctx, now) {
			log.Printf("[PE] Rule matched: %s (%s) -> action=%s", rule.Name, rule.ID, rule.Action)

			decision := &models.AccessDecision{
				Decision:    rule.Action,
				Reason:      fmt.Sprintf("Matched policy: %s", rule.Name),
				RiskScore:   riskScore,
				MatchedRule: rule.ID,
			}
			if rule.Action == "allow" {
				decision.Policies = []string{req.Resource}
			}
			return decision
		}
	}

	return e.defaultDecision(req, riskScore)
}

func (e *Engine) matchesRule(rule *models.PolicyRule, ctx AccessContext, now time.Time) bool {
	req := ctx.Request
	cond := rule.Conditions

	if len(cond.AllowedRoles) > 0 {
		if strings.TrimSpace(ctx.UserRole) == "" || !containsString(cond.AllowedRoles, ctx.UserRole) {
			return false
		}
	}

	if len(cond.AllowedUsers) > 0 {
		if !containsAnyString(cond.AllowedUsers, req.UserID, req.Username, ctx.UserEmail, ctx.DirectoryUserID, ctx.DirectoryUserName) {
			return false
		}
	}

	if len(cond.AllowedGroups) > 0 {
		if !intersectsString(cond.AllowedGroups, append(ctx.DirectoryGroupIDs, ctx.DirectoryGroupNames...)) {
			return false
		}
	}

	if len(cond.AllowedIPs) > 0 {
		if !matchesIPList(req.SourceIP, cond.AllowedIPs) {
			return false
		}
	}

	if len(cond.BlockedIPs) > 0 {
		if matchesIPList(req.SourceIP, cond.BlockedIPs) {
			return false
		}
	}

	if !matchesEndpointTrust(cond, req) {
		return false
	}

	loc := time.UTC
	if cond.Timezone != "" {
		if tz, err := time.LoadLocation(cond.Timezone); err == nil {
			loc = tz
		} else {
			log.Printf("[PE] Invalid timezone %q, falling back to UTC", cond.Timezone)
		}
	}
	ruleNow := now.In(loc)

	if cond.DateRangeStart != "" {
		if start, err := time.Parse("2006-01-02", cond.DateRangeStart); err == nil {
			if ruleNow.Before(start) {
				return false
			}
		}
	}
	if cond.DateRangeEnd != "" {
		if end, err := time.Parse("2006-01-02", cond.DateRangeEnd); err == nil {
			if ruleNow.After(end.Add(24 * time.Hour)) {
				return false
			}
		}
	}

	if len(cond.BlockedDates) > 0 {
		todayStr := ruleNow.Format("2006-01-02")
		for _, blocked := range cond.BlockedDates {
			if blocked == todayStr {
				return false
			}
		}
	}

	if cond.AllowedTimeStart != "" && cond.AllowedTimeEnd != "" {
		if !isWithinTimeWindowTZ(cond.AllowedTimeStart, cond.AllowedTimeEnd, ruleNow) {
			return false
		}
	}

	if len(cond.AllowedDays) > 0 {
		today := ruleNow.Weekday().String()
		if !containsString(cond.AllowedDays, today) {
			return false
		}
	}

	if len(cond.TargetResources) > 0 {
		if !containsString(cond.TargetResources, req.Resource) && !containsString(cond.TargetResources, req.AppID) {
			return false
		}
	}

	if len(cond.TargetPorts) > 0 {
		if !containsInt(cond.TargetPorts, req.ResourcePort) {
			return false
		}
	}

	if !matchesProcessConditions(cond, rule.Action, req.Process) {
		return false
	}

	if cond.MinHealthScore > 0 && req.DeviceHealth != nil {
		if req.DeviceHealth.OverallScore < cond.MinHealthScore {
			return false
		}
	}

	if len(cond.RequiredChecks) > 0 && req.DeviceHealth != nil {
		for _, reqCheck := range cond.RequiredChecks {
			found := false
			for _, check := range req.DeviceHealth.Checks {
				if strings.EqualFold(check.Name, reqCheck) {
					found = true
					if cond.RequiredCheckStatus != "" && check.Status != cond.RequiredCheckStatus {
						return false
					}
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

func (e *Engine) defaultDecision(req models.AccessRequest, riskScore int) *models.AccessDecision {
	log.Printf("[PE] Default decision: DENY (no matching rule, risk=%d)", riskScore)
	return &models.AccessDecision{
		Decision:  "deny",
		Reason:    "No matching access rule - denied by zero-trust default",
		RiskScore: riskScore,
	}
}

func containsString(slice []string, item string) bool {
	item = strings.TrimSpace(item)
	if item == "" {
		return false
	}
	for _, s := range slice {
		if strings.EqualFold(strings.TrimSpace(s), item) {
			return true
		}
	}
	return false
}

func containsAnyString(slice []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if containsString(slice, candidate) {
			return true
		}
	}
	return false
}

func intersectsString(left, right []string) bool {
	for _, candidate := range right {
		if containsString(left, candidate) {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}

func matchesProcessConditions(cond models.RuleConditions, action string, process *models.ProcessIdentity) bool {
	if cond.RequireProcessIdentity && process == nil {
		return false
	}
	if len(cond.AllowedProcessNames) == 0 && len(cond.BlockedProcessNames) == 0 &&
		len(cond.AllowedProcessHashes) == 0 && len(cond.BlockedProcessHashes) == 0 {
		return true
	}
	if process == nil {
		return false
	}

	blockedNameMatch := len(cond.BlockedProcessNames) > 0 && processNameMatches(cond.BlockedProcessNames, process)
	blockedHashMatch := len(cond.BlockedProcessHashes) > 0 && processHashMatches(cond.BlockedProcessHashes, process.SHA256)
	if strings.EqualFold(action, "deny") && (len(cond.BlockedProcessNames) > 0 || len(cond.BlockedProcessHashes) > 0) {
		if !blockedNameMatch && !blockedHashMatch {
			return false
		}
	} else if blockedNameMatch || blockedHashMatch {
		return false
	}
	if len(cond.AllowedProcessNames) > 0 && !processNameMatches(cond.AllowedProcessNames, process) {
		return false
	}
	if len(cond.AllowedProcessHashes) > 0 && !processHashMatches(cond.AllowedProcessHashes, process.SHA256) {
		return false
	}
	return true
}

func matchesEndpointTrust(cond models.RuleConditions, req models.AccessRequest) bool {
	policy := strings.ToLower(strings.TrimSpace(cond.EndpointTrustPolicy))
	if policy == "" || policy == "allow_all" || policy == "skip" {
		return true
	}
	if len(cond.EndpointTrustBypassIPs) > 0 && matchesIPList(req.SourceIP, cond.EndpointTrustBypassIPs) {
		return true
	}
	if cond.BlockCompromisedEndpoints && endpointHasStatus(req.DeviceHealth, []string{"compromised", "secure_endpoint", "endpoint_protection"}, []string{"critical", "fail", "failed", "compromised"}) {
		return false
	}
	if policy == "require_trusted" && !endpointIsTrusted(req.DeviceHealth) {
		return false
	}
	if cond.TreatMobileEndpointsDifferently && isMobileOS(req.DeviceHealth) {
		mobilePolicy := strings.ToLower(strings.TrimSpace(cond.MobileEndpointTrustPolicy))
		if mobilePolicy == "require_trusted" && !endpointIsTrusted(req.DeviceHealth) {
			return false
		}
	}
	return true
}

func endpointIsTrusted(report *models.DeviceHealthReport) bool {
	return endpointHasStatus(
		report,
		[]string{"trusted_endpoint", "managed_device", "device_trust", "endpoint_trust"},
		[]string{"pass", "ok", "healthy", "trusted", "managed"},
	)
}

func endpointHasStatus(report *models.DeviceHealthReport, names, statuses []string) bool {
	if report == nil {
		return false
	}
	for _, check := range report.Checks {
		if containsString(names, check.Name) && containsString(statuses, check.Status) {
			return true
		}
	}
	return false
}

func isMobileOS(report *models.DeviceHealthReport) bool {
	if report == nil {
		return false
	}
	os := strings.ToLower(report.OS)
	return strings.Contains(os, "ios") || strings.Contains(os, "android") || strings.Contains(os, "ipad")
}

func processNameMatches(allowed []string, process *models.ProcessIdentity) bool {
	if process == nil {
		return false
	}
	candidates := []string{process.Name, process.Path}
	if process.Path != "" {
		candidates = append(candidates, filepath.Base(process.Path))
	}
	for _, candidate := range candidates {
		if containsString(allowed, candidate) {
			return true
		}
	}
	return false
}

func processHashMatches(allowed []string, hash string) bool {
	if strings.TrimSpace(hash) == "" {
		return false
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(hash)) {
			return true
		}
	}
	return false
}

func matchesIPList(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			if cidr == ipStr {
				return true
			}
			continue
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isWithinTimeWindowTZ(startStr, endStr string, now time.Time) bool {
	currentMinutes := now.Hour()*60 + now.Minute()
	start := parseTimeMinutes(startStr)
	end := parseTimeMinutes(endStr)

	if start == -1 || end == -1 {
		return true
	}
	if start <= end {
		return currentMinutes >= start && currentMinutes <= end
	}
	return currentMinutes >= start || currentMinutes <= end
}

func parseTimeMinutes(s string) int {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return -1
	}
	h, m := 0, 0
	for _, c := range parts[0] {
		h = h*10 + int(c-'0')
	}
	for _, c := range parts[1] {
		m = m*10 + int(c-'0')
	}
	return h*60 + m
}
