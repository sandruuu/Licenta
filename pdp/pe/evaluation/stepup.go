package evaluation

import (
	"strings"
	"time"

	"pdp/models"
)

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
