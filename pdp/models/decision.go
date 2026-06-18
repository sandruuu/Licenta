package models

import (
	"strings"
	"time"
)

const (
	DecisionAllow          = "allow"
	DecisionDeny           = "deny"
	DecisionStepUpRequired = "step_up_required"
)

const (
	NewUserPolicyRequireEnrollment = "require_enrollment"
	NewUserPolicyAllowWithoutMFA   = "allow_without_mfa"
	NewUserPolicyDeny              = "deny"
)

const (
	AuthenticationPolicyEnforceMFA = "enforce_mfa"
	AuthenticationPolicyBypassMFA  = "bypass_mfa"
	AuthenticationPolicyDeny       = "deny"
)

const (
	UserLocationActionAllow      = "allow"
	UserLocationActionRequireMFA = "require_mfa"
	UserLocationActionSkipMFA    = "skip_mfa"
	UserLocationActionBlock      = "block"
)

const (
	DefaultStepUpACR           = "urn:trustcloud:loa:2"
	DefaultStepUpMaxAgeSeconds = 600
)

const (
	StepUpStrengthOTP                 = "otp"
	StepUpStrengthPhishingResistant   = "phishing_resistant"
	StepUpStrengthHardwareKey         = "hardware_key"
	StepUpStrengthApprovedHardwareKey = "approved_hardware_key"
)

// NormalizePolicyAction accepts only the canonical policy action values used by
// the access decision contract.
func NormalizePolicyAction(action string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case DecisionAllow:
		return DecisionAllow, true
	case DecisionDeny:
		return DecisionDeny, true
	case DecisionStepUpRequired:
		return DecisionStepUpRequired, true
	default:
		return "", false
	}
}

func NormalizeNewUserPolicy(policy string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case NewUserPolicyRequireEnrollment:
		return NewUserPolicyRequireEnrollment, true
	case NewUserPolicyAllowWithoutMFA:
		return NewUserPolicyAllowWithoutMFA, true
	case NewUserPolicyDeny:
		return NewUserPolicyDeny, true
	default:
		return "", false
	}
}

func NormalizeAuthenticationPolicy(policy string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case AuthenticationPolicyEnforceMFA:
		return AuthenticationPolicyEnforceMFA, true
	case AuthenticationPolicyBypassMFA:
		return AuthenticationPolicyBypassMFA, true
	case AuthenticationPolicyDeny:
		return AuthenticationPolicyDeny, true
	default:
		return "", false
	}
}

func NormalizeUserLocationAction(action string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", UserLocationActionAllow:
		return UserLocationActionAllow, true
	case UserLocationActionRequireMFA:
		return UserLocationActionRequireMFA, true
	case UserLocationActionSkipMFA:
		return UserLocationActionSkipMFA, true
	case UserLocationActionBlock:
		return UserLocationActionBlock, true
	default:
		return "", false
	}
}

func PolicyActionForAuthenticationPolicy(policy string) (string, bool) {
	normalized, ok := NormalizeAuthenticationPolicy(policy)
	if !ok {
		return "", false
	}
	switch normalized {
	case AuthenticationPolicyEnforceMFA:
		return DecisionStepUpRequired, true
	case AuthenticationPolicyBypassMFA:
		return DecisionAllow, true
	case AuthenticationPolicyDeny:
		return DecisionDeny, true
	default:
		return "", false
	}
}

type StepUpRequirement struct {
	ChallengeID         string    `json:"challenge_id,omitempty"`
	URL                 string    `json:"url,omitempty"`
	Methods             []string  `json:"methods,omitempty"`
	MinStrength         string    `json:"min_strength,omitempty"`
	WebAuthnAttachment  string    `json:"webauthn_attachment,omitempty"`
	AllowedAAGUIDs      []string  `json:"allowed_aaguids,omitempty"`
	RequiredACR         string    `json:"required_acr,omitempty"`
	MaxAgeSeconds       int       `json:"max_age_seconds,omitempty"`
	ExpiresAt           time.Time `json:"expires_at,omitempty"`
	Reason              string    `json:"reason,omitempty"`
	PolicyID            string    `json:"policy_id,omitempty"`
	ResourceID          string    `json:"resource_id,omitempty"`
	AlreadySatisfied    bool      `json:"already_satisfied,omitempty"`
	CompletedMethod     string    `json:"completed_method,omitempty"`
	CompletedStrength   string    `json:"completed_strength,omitempty"`
	CompletedAAGUID     string    `json:"completed_aaguid,omitempty"`
	CompletedAttachment string    `json:"completed_attachment,omitempty"`
	CompletedAtUnix     int64     `json:"completed_at_unix,omitempty"`
	VerificationNonce   string    `json:"verification_nonce,omitempty"`
}

type AuthContext struct {
	ACR              string
	AMR              []string
	StepUpVerifiedAt time.Time
	StepUpExpiresAt  time.Time
	StepUpMethod     string
	StepUpStrength   string
	StepUpAAGUID     string
	StepUpAttachment string
}

func StepUpACR(value string) string {
	if strings.TrimSpace(value) == "" {
		return DefaultStepUpACR
	}
	return strings.TrimSpace(value)
}

func StepUpMaxAgeSeconds(value int) int {
	if value <= 0 {
		return DefaultStepUpMaxAgeSeconds
	}
	return value
}

func StepUpMethods(values []string) []string {
	methods := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		method := strings.ToLower(strings.TrimSpace(value))
		if method == "" {
			continue
		}
		if method == "idp" || method == "reauth" || method == "idp_reauth" || method == "external_idp" {
			for _, defaultMethod := range []string{"totp", "webauthn"} {
				if _, ok := seen[defaultMethod]; !ok {
					seen[defaultMethod] = struct{}{}
					methods = append(methods, defaultMethod)
				}
			}
			continue
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	if len(methods) == 0 {
		methods = []string{"totp", "webauthn"}
	}
	return methods
}

func StepUpMinStrength(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case StepUpStrengthOTP:
		return StepUpStrengthOTP
	case StepUpStrengthPhishingResistant, "webauthn", "passkey", "security_key":
		return StepUpStrengthPhishingResistant
	case StepUpStrengthHardwareKey, "cross_platform", "roaming":
		return StepUpStrengthHardwareKey
	case StepUpStrengthApprovedHardwareKey, "approved_key", "approved_security_key":
		return StepUpStrengthApprovedHardwareKey
	default:
		return ""
	}
}
