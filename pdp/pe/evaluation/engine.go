package evaluation

import (
	"bytes"
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
	Request               models.AccessRequest
	Rules                 []*models.PolicyRule
	Auth                  models.AuthContext
	UserRole              string
	UserEmail             string
	DirectoryUserID       string
	DirectoryUserName     string
	DirectoryGroupIDs     []string
	DirectoryGroupNames   []string
	FailedAttempts        int
	UserMFAEnabled        bool
	SourceCountry         string
	SourceCountryCode     string
	SourceLocationKnown   bool
	Now                   time.Time
	GeoVelocity           float64
	IsNewDevice           bool
	IsNewLocation         bool
	IsImpossibleTravel    bool
	IsUserBaselineAnomaly bool
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
// Rules are evaluated in deterministic policy-layer order by PA/store before
// they reach PE.
func (e *Engine) Evaluate(ctx AccessContext) *models.AccessDecision {
	req := ctx.Request
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}

	log.Printf("[PE] Evaluating access: user=%s resource=%s:%d protocol=%s",
		req.Username, req.Resource, req.ResourcePort, req.Protocol)

	riskCtx := models.RiskContext{
		UserID:                req.UserID,
		SourceIP:              req.SourceIP,
		DeviceHealth:          req.DeviceHealth,
		FailedAttempts:        ctx.FailedAttempts,
		IsNewDevice:           ctx.IsNewDevice,
		IsNewLocation:         ctx.IsNewLocation,
		TimeOfDay:             now,
		Protocol:              req.Protocol,
		GeoVelocity:           ctx.GeoVelocity,
		IsImpossibleTravel:    ctx.IsImpossibleTravel,
		IsUserBaselineAnomaly: ctx.IsUserBaselineAnomaly,
		AnomalyAlerts:         req.AnomalyAlerts,
		AnomalyScore:          req.AnomalyScore,
	}
	riskScore := perisk.CalculateRiskScore(riskCtx, e.riskConfig)
	observedAccess := accessConditionsFromContext(ctx)

	matchedRules := make([]*models.PolicyRule, 0)
	stepUpRules := make([]*models.PolicyRule, 0)
	var allowRule *models.PolicyRule
	var sessionControls models.SessionPolicyControls

	for _, rule := range ctx.Rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		if !e.matchesRuleScope(rule, ctx, now, riskScore, observedAccess) {
			continue
		}

		matchedRules = append(matchedRules, rule)
		sessionControls = mergeSessionControls(sessionControls, rule.Conditions.Session)

		if !matchesHealthRequirements(rule.Conditions, req.DeviceHealth) {
			log.Printf("[PE] Rule matched but device health failed: %s (%s)", rule.Name, rule.ID)
			return &models.AccessDecision{
				Decision:         models.DecisionDeny,
				Reason:           fmt.Sprintf("Device health requirements failed by policy: %s", rule.Name),
				RiskScore:        riskScore,
				AccessConditions: observedAccess,
				SessionControls:  sessionControls,
				MatchedRule:      rule.ID,
			}
		}

		action := effectivePolicyAction(rule, ctx)
		log.Printf("[PE] Rule matched: %s (%s) -> action=%s", rule.Name, rule.ID, action)

		switch action {
		case models.DecisionDeny:
			return &models.AccessDecision{
				Decision:         models.DecisionDeny,
				Reason:           fmt.Sprintf("Blocked by policy: %s", rule.Name),
				RiskScore:        riskScore,
				AccessConditions: observedAccess,
				SessionControls:  sessionControls,
				MatchedRule:      rule.ID,
			}
		case models.DecisionStepUpRequired:
			stepUpRules = append(stepUpRules, rule)
		case models.DecisionAllow:
			if allowRule == nil {
				allowRule = rule
			}
		}
	}

	if len(matchedRules) == 0 {
		return e.defaultDecision(req, riskScore, observedAccess)
	}

	if len(stepUpRules) > 0 {
		requirement := combinedStepUpRequirementFromRules(stepUpRules, req.Resource)
		decision := &models.AccessDecision{
			Decision:         models.DecisionStepUpRequired,
			Reason:           fmt.Sprintf("Step-up verification required by %d matching policy rule(s)", len(stepUpRules)),
			RiskScore:        riskScore,
			AccessConditions: observedAccess,
			SessionControls:  sessionControls,
			MatchedRule:      requirement.PolicyID,
		}
		if stepUpSatisfied(ctx.Auth, requirement, now) {
			decision.Decision = models.DecisionAllow
			decision.Reason = fmt.Sprintf("Step-up verification already satisfies %d matching policy rule(s)", len(stepUpRules))
			decision.Policies = []string{req.Resource}
			decision.StepUp = &models.StepUpRequirement{
				AlreadySatisfied:  true,
				Methods:           append([]string(nil), requirement.Methods...),
				RequiredACR:       requirement.RequiredACR,
				MinStrength:       requirement.MinStrength,
				MaxAgeSeconds:     requirement.MaxAgeSeconds,
				CompletedMethod:   ctx.Auth.StepUpMethod,
				CompletedStrength: effectiveStepUpStrength(ctx.Auth),
			}
			if !ctx.Auth.StepUpVerifiedAt.IsZero() {
				decision.StepUp.CompletedAtUnix = ctx.Auth.StepUpVerifiedAt.UTC().Unix()
			}
		} else {
			decision.StepUp = requirement
		}
		return decision
	}

	if allowRule != nil {
		return &models.AccessDecision{
			Decision:         models.DecisionAllow,
			Reason:           fmt.Sprintf("Allowed by %d matching policy rule(s)", len(matchedRules)),
			RiskScore:        riskScore,
			AccessConditions: observedAccess,
			SessionControls:  sessionControls,
			MatchedRule:      allowRule.ID,
			Policies:         []string{req.Resource},
		}
	}

	return e.defaultDecision(req, riskScore, observedAccess)
}

func effectivePolicyAction(rule *models.PolicyRule, ctx AccessContext) string {
	if rule == nil {
		return models.DecisionDeny
	}
	action, ok := models.NormalizePolicyAction(rule.Action)
	if !ok {
		action = models.DecisionDeny
	}
	authPolicy, hasAuthPolicy := models.NormalizeAuthenticationPolicy(rule.Conditions.Authentication.Policy)
	if hasAuthPolicy {
		if authAction, ok := models.PolicyActionForAuthenticationPolicy(authPolicy); ok {
			action = authAction
		}
	}
	networkAction, hasNetworkAction := effectiveNetworkAction(rule.Conditions.Network, ctx.Request.SourceIP)
	riskAction, hasRiskAction := effectiveRiskBasedAuthAction(rule.Conditions.RiskBasedAuth, ctx)
	locationAction, hasLocationAction := effectiveUserLocationAction(
		rule.Conditions.UserLocation,
		ctx.SourceCountry,
		ctx.SourceCountryCode,
		ctx.SourceLocationKnown,
	)
	if ctx.UserMFAEnabled {
		return applyConditionalAccessActions(action, locationAction, hasLocationAction, networkAction, hasNetworkAction, riskAction, hasRiskAction)
	}
	newUserPolicy, hasNewUserPolicy := models.NormalizeNewUserPolicy(rule.Conditions.User.NewUserPolicy)
	if !hasNewUserPolicy {
		return applyConditionalAccessActions(action, locationAction, hasLocationAction, networkAction, hasNetworkAction, riskAction, hasRiskAction)
	}
	networkSkipBlockedByEnrollment := false
	switch newUserPolicy {
	case models.NewUserPolicyDeny:
		action = models.DecisionDeny
	case models.NewUserPolicyAllowWithoutMFA:
		if action == models.DecisionDeny {
			action = models.DecisionDeny
		} else {
			action = models.DecisionAllow
		}
	case models.NewUserPolicyRequireEnrollment:
		if action == models.DecisionDeny {
			action = models.DecisionDeny
		} else if hasAuthPolicy && authPolicy == models.AuthenticationPolicyBypassMFA {
			action = models.DecisionAllow
		} else if hasNetworkAction && networkAction == models.UserLocationActionSkipMFA && !rule.Conditions.Network.RequireEnrollmentFromSkipNetworks {
			action = models.DecisionAllow
		} else {
			networkSkipBlockedByEnrollment = hasNetworkAction && networkAction == models.UserLocationActionSkipMFA
			action = models.DecisionStepUpRequired
		}
	default:
	}
	if networkSkipBlockedByEnrollment {
		hasNetworkAction = false
	}
	return applyConditionalAccessActions(action, locationAction, hasLocationAction, networkAction, hasNetworkAction, riskAction, hasRiskAction)
}

func applyConditionalAccessActions(action string, locationAction string, hasLocationAction bool, networkAction string, hasNetworkAction bool, riskAction string, hasRiskAction bool) string {
	if action == models.DecisionDeny {
		return models.DecisionDeny
	}
	hasRequireMFA := false
	hasSkipMFA := false
	for _, candidate := range []struct {
		action string
		ok     bool
	}{
		{action: locationAction, ok: hasLocationAction},
		{action: networkAction, ok: hasNetworkAction},
		{action: riskAction, ok: hasRiskAction},
	} {
		if !candidate.ok {
			continue
		}
		switch candidate.action {
		case models.UserLocationActionBlock:
			return models.DecisionDeny
		case models.UserLocationActionRequireMFA:
			hasRequireMFA = true
		case models.UserLocationActionSkipMFA:
			hasSkipMFA = true
		}
	}
	if hasRequireMFA {
		return models.DecisionStepUpRequired
	}
	if hasSkipMFA {
		return models.DecisionAllow
	}
	return action
}

func effectiveUserLocationAction(policy models.UserLocationPolicyConditions, country, countryCode string, locationKnown bool) (string, bool) {
	if len(policy.Rules) == 0 &&
		strings.TrimSpace(policy.DefaultAction) == "" &&
		strings.TrimSpace(policy.UnknownLocationAction) == "" {
		return "", false
	}

	if !locationKnown || (strings.TrimSpace(country) == "" && strings.TrimSpace(countryCode) == "") {
		action, ok := models.NormalizeUserLocationAction(policy.UnknownLocationAction)
		if ok {
			return action, true
		}
		return models.UserLocationActionAllow, true
	}

	for _, rule := range policy.Rules {
		if !countryRuleMatches(rule.Countries, country, countryCode) {
			continue
		}
		action, ok := models.NormalizeUserLocationAction(rule.Action)
		if ok {
			return action, true
		}
		return models.UserLocationActionAllow, true
	}

	action, ok := models.NormalizeUserLocationAction(policy.DefaultAction)
	if ok {
		return action, true
	}
	return models.UserLocationActionAllow, true
}

func effectiveNetworkAction(policy models.NetworkPolicyConditions, sourceIP string) (string, bool) {
	if policy.AllowAllNetworks {
		return "", false
	}
	if len(policy.BlockedCIDRs) > 0 && matchesIPList(sourceIP, policy.BlockedCIDRs) {
		return models.UserLocationActionBlock, true
	}
	if len(policy.RequireMFACIDRs) > 0 && matchesIPList(sourceIP, policy.RequireMFACIDRs) {
		return models.UserLocationActionRequireMFA, true
	}
	if len(policy.SkipMFACIDRs) > 0 && matchesIPList(sourceIP, policy.SkipMFACIDRs) {
		return models.UserLocationActionSkipMFA, true
	}
	if len(policy.AllowedCIDRs) > 0 && matchesIPList(sourceIP, policy.AllowedCIDRs) {
		return models.UserLocationActionAllow, true
	}
	if policy.DenyOtherNetworks &&
		(len(policy.AllowedCIDRs) > 0 ||
			len(policy.SkipMFACIDRs) > 0 ||
			len(policy.RequireMFACIDRs) > 0) {
		return models.UserLocationActionBlock, true
	}
	return "", false
}

func effectiveRiskBasedAuthAction(policy models.RiskBasedAuthPolicyConditions, ctx AccessContext) (string, bool) {
	if !policy.RequireMFAOnRisk {
		return "", false
	}
	signals := policy.Signals
	if len(signals) == 0 {
		signals = []string{"new_location", "unrealistic_travel", "user_baseline_anomaly"}
	}
	matchAny := !strings.EqualFold(strings.TrimSpace(policy.MatchMode), "all")
	matched := false
	for _, signal := range signals {
		observed := riskBasedAuthSignalObserved(signal, ctx)
		if matchAny && observed {
			return models.UserLocationActionRequireMFA, true
		}
		if !matchAny && !observed {
			return "", false
		}
		matched = matched || observed
	}
	if !matchAny && len(signals) > 0 {
		return models.UserLocationActionRequireMFA, true
	}
	if matched {
		return models.UserLocationActionRequireMFA, true
	}
	return "", false
}

func riskBasedAuthSignalObserved(signal string, ctx AccessContext) bool {
	switch normalizeHealthToken(signal) {
	case "new_location":
		return ctx.IsNewLocation
	case "unrealistic_travel", "impossible_travel":
		return ctx.IsImpossibleTravel
	case "user_baseline_anomaly", "baseline_anomaly", "user_baseline":
		return ctx.IsUserBaselineAnomaly
	default:
		return false
	}
}

func countryRuleMatches(configured []string, country, countryCode string) bool {
	observed := []string{country, countryCode}
	for _, candidate := range configured {
		for _, value := range observed {
			if normalizeCountryToken(candidate) == normalizeCountryToken(value) && normalizeCountryToken(value) != "" {
				return true
			}
		}
	}
	return false
}

func normalizeCountryToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, "_", "")
	return value
}

func (e *Engine) matchesRule(rule *models.PolicyRule, ctx AccessContext, now time.Time, riskScore int, observedAccess models.AccessConditions) bool {
	return e.matchesRuleScope(rule, ctx, now, riskScore, observedAccess) &&
		matchesHealthRequirements(rule.Conditions, ctx.Request.DeviceHealth)
}

func (e *Engine) matchesRuleScope(rule *models.PolicyRule, ctx AccessContext, now time.Time, riskScore int, observedAccess models.AccessConditions) bool {
	req := ctx.Request
	cond := rule.Conditions

	if !matchesAccessConditions(cond.AccessConditions, observedAccess, cond.AccessMatchMode) {
		return false
	}

	if !matchesRiskConditions(cond.Risk, riskScore, observedAccess, ctx, req) {
		return false
	}

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

	return true
}

func (e *Engine) defaultDecision(req models.AccessRequest, riskScore int, observedAccess models.AccessConditions) *models.AccessDecision {
	log.Printf("[PE] Default decision: DENY (no matching rule, risk=%d)", riskScore)
	return &models.AccessDecision{
		Decision:         models.DecisionDeny,
		Reason:           "No matching access rule - denied by zero-trust default",
		RiskScore:        riskScore,
		AccessConditions: observedAccess,
	}
}

func stepUpRequirementFromRule(rule *models.PolicyRule, resourceID string) *models.StepUpRequirement {
	if rule == nil {
		return &models.StepUpRequirement{
			Methods:       models.StepUpMethods(nil),
			RequiredACR:   models.DefaultStepUpACR,
			MaxAgeSeconds: models.DefaultStepUpMaxAgeSeconds,
			ResourceID:    resourceID,
		}
	}
	cond := rule.Conditions
	requirement := &models.StepUpRequirement{
		Methods:       models.StepUpMethods(cond.Authentication.StepUpMethods),
		RequiredACR:   models.DefaultStepUpACR,
		MaxAgeSeconds: models.DefaultStepUpMaxAgeSeconds,
		PolicyID:      rule.ID,
		ResourceID:    resourceID,
	}
	return requirement
}

func combinedStepUpRequirementFromRules(rules []*models.PolicyRule, resourceID string) *models.StepUpRequirement {
	if len(rules) == 0 {
		return stepUpRequirementFromRule(nil, resourceID)
	}

	requirement := stepUpRequirementFromRule(rules[0], resourceID)
	methods := append([]string(nil), requirement.Methods...)
	requiredACR := models.StepUpACR(requirement.RequiredACR)
	maxAge := models.StepUpMaxAgeSeconds(requirement.MaxAgeSeconds)
	minStrength := models.StepUpMinStrength(requirement.MinStrength)
	attachment := normalizeAttachment(requirement.WebAuthnAttachment)
	allowedAAGUIDs := append([]string(nil), requirement.AllowedAAGUIDs...)

	for _, rule := range rules[1:] {
		next := stepUpRequirementFromRule(rule, resourceID)
		methods = mergeStepUpMethods(methods, next.Methods)
		if acr := models.StepUpACR(next.RequiredACR); strings.TrimSpace(requiredACR) == "" {
			requiredACR = acr
		}
		if nextMaxAge := models.StepUpMaxAgeSeconds(next.MaxAgeSeconds); nextMaxAge > 0 && nextMaxAge < maxAge {
			maxAge = nextMaxAge
		}
		if nextStrength := models.StepUpMinStrength(next.MinStrength); stepUpStrengthRank(nextStrength) > stepUpStrengthRank(minStrength) {
			minStrength = nextStrength
		}
		if attachment == "" || attachment == "any" {
			attachment = normalizeAttachment(next.WebAuthnAttachment)
		}
		allowedAAGUIDs = mergeStringsCaseInsensitive(allowedAAGUIDs, next.AllowedAAGUIDs)
	}

	requirement.Methods = models.StepUpMethods(methods)
	requirement.RequiredACR = requiredACR
	requirement.MaxAgeSeconds = maxAge
	requirement.MinStrength = minStrength
	requirement.WebAuthnAttachment = attachment
	requirement.AllowedAAGUIDs = allowedAAGUIDs
	return requirement
}

func mergeStepUpMethods(left, right []string) []string {
	return mergeStringsCaseInsensitive(models.StepUpMethods(left), models.StepUpMethods(right))
}

func mergeStringsCaseInsensitive(left, right []string) []string {
	merged := make([]string, 0, len(left)+len(right))
	for _, values := range [][]string{left, right} {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" || containsString(merged, value) {
				continue
			}
			merged = append(merged, value)
		}
	}
	return merged
}

func normalizeSessionControls(controls models.SessionPolicyControls) models.SessionPolicyControls {
	if controls.MaxAgeSeconds < 0 {
		controls.MaxAgeSeconds = 0
	}
	if controls.RevalidateEverySeconds < 0 {
		controls.RevalidateEverySeconds = 0
	}
	return controls
}

func mergeSessionControls(current, next models.SessionPolicyControls) models.SessionPolicyControls {
	current = normalizeSessionControls(current)
	next = normalizeSessionControls(next)
	if next.MaxAgeSeconds > 0 && (current.MaxAgeSeconds == 0 || next.MaxAgeSeconds < current.MaxAgeSeconds) {
		current.MaxAgeSeconds = next.MaxAgeSeconds
	}
	if next.RevalidateEverySeconds > 0 && (current.RevalidateEverySeconds == 0 || next.RevalidateEverySeconds < current.RevalidateEverySeconds) {
		current.RevalidateEverySeconds = next.RevalidateEverySeconds
	}
	current.RevokeOnPostureChange = current.RevokeOnPostureChange || next.RevokeOnPostureChange
	current.RevokeOnRiskIncrease = current.RevokeOnRiskIncrease || next.RevokeOnRiskIncrease
	return current
}

func stepUpSatisfied(auth models.AuthContext, requirement *models.StepUpRequirement, now time.Time) bool {
	if requirement == nil {
		return false
	}
	if auth.StepUpVerifiedAt.IsZero() {
		return false
	}
	requiredACR := models.StepUpACR(requirement.RequiredACR)
	if !strings.EqualFold(strings.TrimSpace(auth.ACR), requiredACR) {
		return false
	}
	requiredMethods := requirement.Methods
	if len(requiredMethods) == 0 {
		return false
	}
	authMethods := append([]string(nil), auth.AMR...)
	if strings.TrimSpace(auth.StepUpMethod) != "" {
		authMethods = append(authMethods, auth.StepUpMethod)
	}
	if !intersectsString(authMethods, requiredMethods) {
		return false
	}
	actualStrength := effectiveStepUpStrength(auth)
	if models.StepUpMinStrength(requirement.MinStrength) == models.StepUpStrengthApprovedHardwareKey &&
		aaguidAllowed(requirement.AllowedAAGUIDs, auth.StepUpAAGUID) {
		actualStrength = models.StepUpStrengthApprovedHardwareKey
	}
	if !stepUpStrengthSatisfies(actualStrength, requirement.MinStrength) {
		return false
	}
	if !stepUpAttachmentSatisfies(auth.StepUpAttachment, requirement.WebAuthnAttachment) {
		return false
	}
	if len(requirement.AllowedAAGUIDs) > 0 && !aaguidAllowed(requirement.AllowedAAGUIDs, auth.StepUpAAGUID) {
		return false
	}
	if !auth.StepUpExpiresAt.IsZero() {
		return now.Before(auth.StepUpExpiresAt)
	}
	maxAge := time.Duration(models.StepUpMaxAgeSeconds(requirement.MaxAgeSeconds)) * time.Second
	return now.Sub(auth.StepUpVerifiedAt) <= maxAge
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

func accessConditionsFromContext(ctx AccessContext) models.AccessConditions {
	req := ctx.Request
	return models.AccessConditions{
		Location: models.LocationAccessConditions{
			NewLocation:         ctx.IsNewLocation,
			ImpossibleTravel:    ctx.IsImpossibleTravel,
			UserBaselineAnomaly: ctx.IsUserBaselineAnomaly,
		},
		Connection: models.ConnectionAccessConditions{
			SensitiveProtocol: sensitiveProtocol(req),
		},
	}
}

func matchesAccessConditions(required, observed models.AccessConditions, mode string) bool {
	if required.Empty() {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(mode), "any") {
		return (required.Location.NewLocation && observed.Location.NewLocation) ||
			(required.Location.ImpossibleTravel && observed.Location.ImpossibleTravel) ||
			(required.Location.UserBaselineAnomaly && observed.Location.UserBaselineAnomaly) ||
			(required.Connection.SensitiveProtocol && observed.Connection.SensitiveProtocol)
	}
	if required.Location.NewLocation && !observed.Location.NewLocation {
		return false
	}
	if required.Location.ImpossibleTravel && !observed.Location.ImpossibleTravel {
		return false
	}
	if required.Location.UserBaselineAnomaly && !observed.Location.UserBaselineAnomaly {
		return false
	}
	if required.Connection.SensitiveProtocol && !observed.Connection.SensitiveProtocol {
		return false
	}
	return true
}

func matchesRiskConditions(required models.RiskPolicyConditions, riskScore int, observedAccess models.AccessConditions, ctx AccessContext, req models.AccessRequest) bool {
	if required.MinScore > 0 && riskScore < required.MinScore {
		return false
	}
	if required.MaxScore > 0 && riskScore > required.MaxScore {
		return false
	}
	if len(required.Levels) > 0 && !containsString(required.Levels, riskLevel(riskScore)) {
		return false
	}
	for _, signal := range required.Signals {
		if !riskSignalObserved(signal, observedAccess, ctx, req) {
			return false
		}
	}
	return true
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func riskSignalObserved(signal string, observedAccess models.AccessConditions, ctx AccessContext, req models.AccessRequest) bool {
	switch normalizeHealthToken(signal) {
	case "new_location":
		return observedAccess.Location.NewLocation
	case "impossible_travel":
		return observedAccess.Location.ImpossibleTravel
	case "unrealistic_travel":
		return observedAccess.Location.ImpossibleTravel
	case "user_baseline_anomaly", "baseline_anomaly", "user_baseline":
		return ctx.IsUserBaselineAnomaly
	case "new_device":
		return ctx.IsNewDevice
	case "device_non_compliant", "non_compliant_device", "not_compliant_device":
		return deviceNonCompliant(req.DeviceHealth)
	case "compromised_endpoint":
		return compromisedEndpoint(req.DeviceHealth)
	case "sensitive_protocol":
		return observedAccess.Connection.SensitiveProtocol
	case "failed_attempts":
		return ctx.FailedAttempts > 0
	case "anomaly", "anomaly_alert":
		return req.AnomalyScore > 0 || len(req.AnomalyAlerts) > 0
	case "anonymous_network", "anonymous", "tor", "vpn", "proxy":
		return anomalyAlertObserved(req.AnomalyAlerts, signal)
	default:
		return anomalyAlertObserved(req.AnomalyAlerts, signal)
	}
}

func anomalyAlertObserved(alerts []string, signal string) bool {
	normalizedSignal := normalizeHealthToken(signal)
	for _, alert := range alerts {
		if normalizeHealthToken(alert) == normalizedSignal {
			return true
		}
	}
	return false
}

func sensitiveProtocol(req models.AccessRequest) bool {
	switch strings.ToLower(strings.TrimSpace(req.Protocol)) {
	case "ssh", "rdp":
		return true
	}
	return req.ResourcePort == 22 || req.ResourcePort == 3389
}

func deviceNonCompliant(report *models.DeviceHealthReport) bool {
	if report == nil {
		return false
	}
	for _, check := range report.Checks {
		if healthCheckStatusIn(check.Status, []string{"critical", "fail", "failed", "error", "unhealthy", "non_compliant", "non-compliant", "not_compliant", "compromised"}) {
			return true
		}
	}
	return false
}

func compromisedEndpoint(report *models.DeviceHealthReport) bool {
	if report == nil {
		return false
	}
	if endpointHasStatus(report, []string{"compromised", "secure_endpoint", "endpoint_protection", "edr", "xdr"}, []string{"critical", "fail", "failed", "compromised"}) {
		return true
	}
	for _, check := range report.Checks {
		if healthCheckStatusIn(check.Status, []string{"compromised"}) {
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

func matchesHealthRequirements(cond models.RuleConditions, report *models.DeviceHealthReport) bool {
	requiredChecks := cond.DevicePosture.RequiredChecks
	requiredStatus := cond.DevicePosture.RequiredStatus
	if len(requiredChecks) == 0 {
		return true
	}
	if report == nil {
		return false
	}
	for _, reqCheck := range requiredChecks {
		found := false
		for _, check := range report.Checks {
			if strings.EqualFold(check.Name, reqCheck) {
				found = true
				if requiredStatus != "" && !strings.EqualFold(check.Status, requiredStatus) {
					return false
				}
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func effectiveStepUpStrength(auth models.AuthContext) string {
	if strength := models.StepUpMinStrength(auth.StepUpStrength); strength != "" {
		return strength
	}
	if containsString(auth.AMR, "totp") || strings.EqualFold(auth.StepUpMethod, "totp") {
		return models.StepUpStrengthOTP
	}
	if containsString(auth.AMR, "webauthn") || strings.EqualFold(auth.StepUpMethod, "webauthn") {
		if strings.EqualFold(strings.TrimSpace(auth.StepUpAttachment), "cross_platform") {
			return models.StepUpStrengthHardwareKey
		}
		return models.StepUpStrengthPhishingResistant
	}
	return ""
}

func stepUpStrengthSatisfies(actual, required string) bool {
	required = models.StepUpMinStrength(required)
	if required == "" {
		return true
	}
	actual = models.StepUpMinStrength(actual)
	if actual == "" {
		return false
	}
	return stepUpStrengthRank(actual) >= stepUpStrengthRank(required)
}

func stepUpStrengthRank(strength string) int {
	switch models.StepUpMinStrength(strength) {
	case models.StepUpStrengthOTP:
		return 1
	case models.StepUpStrengthPhishingResistant:
		return 2
	case models.StepUpStrengthHardwareKey:
		return 3
	case models.StepUpStrengthApprovedHardwareKey:
		return 4
	default:
		return 0
	}
}

func stepUpAttachmentSatisfies(actual, required string) bool {
	required = normalizeAttachment(required)
	if required == "" || required == "any" {
		return true
	}
	return normalizeAttachment(actual) == required
}

func normalizeAttachment(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	return value
}

func aaguidAllowed(allowed []string, actual string) bool {
	actual = normalizeAAGUID(actual)
	if actual == "" {
		return false
	}
	for _, candidate := range allowed {
		if normalizeAAGUID(candidate) == actual {
			return true
		}
	}
	return false
}

func normalizeAAGUID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "")
	return value
}

func endpointHasStatus(report *models.DeviceHealthReport, names, statuses []string) bool {
	if report == nil {
		return false
	}
	for _, check := range report.Checks {
		if healthCheckNameIn(check.Name, names) && healthCheckStatusIn(check.Status, statuses) {
			return true
		}
	}
	return false
}

func healthCheckNameIn(value string, names []string) bool {
	value = normalizeHealthToken(value)
	if value == "" {
		return false
	}
	for _, name := range names {
		if normalizeHealthToken(name) == value {
			return true
		}
	}
	return false
}

func healthCheckStatusIn(value string, statuses []string) bool {
	value = normalizeHealthToken(value)
	if value == "" {
		return false
	}
	for _, status := range statuses {
		if normalizeHealthToken(status) == value {
			return true
		}
	}
	return false
}

func normalizeHealthToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
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

	for _, entry := range cidrs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "-") && !strings.Contains(entry, "/") {
			if ipInRange(ip, entry) {
				return true
			}
			continue
		}
		if !strings.Contains(entry, "/") {
			if parsed := net.ParseIP(entry); parsed != nil && parsed.Equal(ip) {
				return true
			}
			continue
		}

		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func ipInRange(ip net.IP, entry string) bool {
	parts := strings.Split(entry, "-")
	if len(parts) != 2 {
		return false
	}
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return false
	}
	family := ipFamily(start)
	if family == 0 || ipFamily(end) != family || ipFamily(ip) != family {
		return false
	}
	ipBytes := ip.To16()
	startBytes := start.To16()
	endBytes := end.To16()
	if family == 4 {
		ipBytes = ip.To4()
		startBytes = start.To4()
		endBytes = end.To4()
	}
	if bytes.Compare(startBytes, endBytes) > 0 {
		startBytes, endBytes = endBytes, startBytes
	}
	return bytes.Compare(ipBytes, startBytes) >= 0 && bytes.Compare(ipBytes, endBytes) <= 0
}

func ipFamily(ip net.IP) int {
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	if ip.To16() != nil {
		return 6
	}
	return 0
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
