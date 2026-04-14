package policy

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"cloud/models"
	"cloud/store"
)

// Engine is the Policy Engine (PE) that evaluates access requests
// against defined policy rules and contextual risk factors.
// It implements conditional access logic inspired by Zero Trust principles.
type Engine struct {
	store *store.Store
	Geo   *GeoLocator
}

// NewEngine creates a new Policy Engine
func NewEngine(s *store.Store) *Engine {
	return &Engine{
		store: s,
		Geo:   NewGeoLocator(s),
	}
}

// Evaluate processes an access request against all enabled policy rules.
// Rules are evaluated in priority order (lower priority number = higher precedence).
// The first matching rule determines the access decision.
// If no rules match, a default risk-based decision is made.
func (e *Engine) Evaluate(req models.AccessRequest) *models.AccessDecision {
	log.Printf("[PE] Evaluating access: user=%s resource=%s:%d protocol=%s",
		req.Username, req.Resource, req.ResourcePort, req.Protocol)

	// Calculate risk score based on contextual factors
	riskCtx := models.RiskContext{
		UserID:         req.UserID,
		SourceIP:       req.SourceIP,
		DeviceHealth:   req.DeviceHealth,
		FailedAttempts: e.store.GetFailedAttempts(req.Username),
		TimeOfDay:      time.Now(),
		Protocol:       req.Protocol,
		AnomalyAlerts:  req.AnomalyAlerts,
		AnomalyScore:   req.AnomalyScore,
	}

	// Geo-velocity / impossible travel check
	if e.Geo != nil && req.SourceIP != "" && req.UserID != "" {
		geoResult := e.Geo.CheckImpossibleTravel(req.UserID, req.SourceIP)
		riskCtx.GeoVelocity = geoResult.SpeedKmH
		riskCtx.IsImpossibleTravel = geoResult.IsImpossible
	}

	riskScore := CalculateRiskScore(riskCtx)

	// Get all rules sorted by priority
	rules := e.store.ListPolicyRules()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if e.matchesRule(rule, req, riskScore) {
			log.Printf("[PE] Rule matched: %s (%s) → action=%s", rule.Name, rule.ID, rule.Action)

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

	// No explicit rule matched — apply default risk-based decision
	return e.defaultDecision(req, riskScore)
}

// matchesRule checks if a request matches all conditions of a rule
func (e *Engine) matchesRule(rule *models.PolicyRule, req models.AccessRequest, riskScore int) bool {
	cond := rule.Conditions

	// Check user roles
	if len(cond.AllowedRoles) > 0 {
		// We need to look up the user's role
		user, exists := e.store.GetUser(req.UserID)
		if !exists {
			return false
		}
		if !containsString(cond.AllowedRoles, user.Role) {
			return false
		}
	}

	// Check specific allowed users
	if len(cond.AllowedUsers) > 0 {
		if !containsString(cond.AllowedUsers, req.UserID) {
			return false
		}
	}

	// Check IP allowlist
	if len(cond.AllowedIPs) > 0 {
		if !matchesIPList(req.SourceIP, cond.AllowedIPs) {
			return false
		}
	}

	// Check IP blocklist
	if len(cond.BlockedIPs) > 0 {
		if matchesIPList(req.SourceIP, cond.BlockedIPs) {
			return false
		}
	}

	// Resolve timezone for time-based checks
	loc := time.UTC
	if cond.Timezone != "" {
		if tz, err := time.LoadLocation(cond.Timezone); err == nil {
			loc = tz
		} else {
			log.Printf("[PE] Invalid timezone %q, falling back to UTC", cond.Timezone)
		}
	}
	now := time.Now().In(loc)

	// Check date range (rule only active between these dates)
	if cond.DateRangeStart != "" {
		if start, err := time.Parse("2006-01-02", cond.DateRangeStart); err == nil {
			if now.Before(start) {
				return false
			}
		}
	}
	if cond.DateRangeEnd != "" {
		if end, err := time.Parse("2006-01-02", cond.DateRangeEnd); err == nil {
			// End date is inclusive — add 1 day
			if now.After(end.Add(24 * time.Hour)) {
				return false
			}
		}
	}

	// Check blocked dates (holidays, maintenance windows)
	if len(cond.BlockedDates) > 0 {
		todayStr := now.Format("2006-01-02")
		for _, blocked := range cond.BlockedDates {
			if blocked == todayStr {
				return false
			}
		}
	}

	// Check time-based conditions
	if cond.AllowedTimeStart != "" && cond.AllowedTimeEnd != "" {
		if !isWithinTimeWindowTZ(cond.AllowedTimeStart, cond.AllowedTimeEnd, now) {
			return false
		}
	}

	// Check allowed days of week
	if len(cond.AllowedDays) > 0 {
		today := now.Weekday().String()
		if !containsString(cond.AllowedDays, today) {
			return false
		}
	}

	// Check target resources (match by resource address or app ID)
	if len(cond.TargetResources) > 0 {
		if !containsString(cond.TargetResources, req.Resource) && !containsString(cond.TargetResources, req.AppID) {
			return false
		}
	}

	// Check target ports
	if len(cond.TargetPorts) > 0 {
		if !containsInt(cond.TargetPorts, req.ResourcePort) {
			return false
		}
	}

	// Check device health score
	if cond.MinHealthScore > 0 && req.DeviceHealth != nil {
		if req.DeviceHealth.OverallScore < cond.MinHealthScore {
			return false
		}
	}

	// Check required health checks
	if len(cond.RequiredChecks) > 0 && req.DeviceHealth != nil {
		for _, reqCheck := range cond.RequiredChecks {
			found := false
			for _, check := range req.DeviceHealth.Checks {
				if strings.EqualFold(check.Name, reqCheck) {
					found = true
					if cond.RequiredCheckStatus != "" && check.Status != cond.RequiredCheckStatus {
						return false // check exists but status doesn't match
					}
					break
				}
			}
			if !found {
				return false // required check not present
			}
		}
	}

	// Check risk threshold
	if cond.MaxRiskScore > 0 {
		if riskScore > cond.MaxRiskScore {
			return false
		}
	}

	return true
}

// defaultDecision applies when no explicit rule matches
func (e *Engine) defaultDecision(req models.AccessRequest, riskScore int) *models.AccessDecision {
	// Risk-based default decision
	switch {
	case riskScore >= 80:
		log.Printf("[PE] Default decision: DENY (risk=%d)", riskScore)
		return &models.AccessDecision{
			Decision:  "deny",
			Reason:    fmt.Sprintf("High risk score (%d/100) — access denied by default policy", riskScore),
			RiskScore: riskScore,
		}
	case riskScore >= 50:
		log.Printf("[PE] Default decision: MFA_REQUIRED (risk=%d)", riskScore)
		return &models.AccessDecision{
			Decision:  "mfa_required",
			Reason:    fmt.Sprintf("Elevated risk score (%d/100) — additional verification required", riskScore),
			RiskScore: riskScore,
		}
	default:
		log.Printf("[PE] Default decision: DENY (risk=%d, zero-trust default)", riskScore)
		return &models.AccessDecision{
			Decision:  "deny",
			Reason:    fmt.Sprintf("No matching policy rule (risk=%d/100) — denied by zero-trust default", riskScore),
			RiskScore: riskScore,
		}
	}
}

// ─────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
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

// matchesIPList checks if the given IP matches any CIDR range in the list
func matchesIPList(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range cidrs {
		// Handle plain IPs (without CIDR notation)
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

// isWithinTimeWindowTZ checks if the given time is within a time window
func isWithinTimeWindowTZ(startStr, endStr string, now time.Time) bool {
	currentMinutes := now.Hour()*60 + now.Minute()

	start := parseTimeMinutes(startStr)
	end := parseTimeMinutes(endStr)

	if start == -1 || end == -1 {
		return true // invalid time format, don't restrict
	}

	if start <= end {
		return currentMinutes >= start && currentMinutes <= end
	}
	// Wrapping around midnight (e.g., 22:00 - 06:00)
	return currentMinutes >= start || currentMinutes <= end
}

// parseTimeMinutes converts "HH:MM" to minutes since midnight
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
