package evaluation

import (
	"strings"

	"pdp/models"
)

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
