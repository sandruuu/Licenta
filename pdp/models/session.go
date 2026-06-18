package models

import "time"

// Session represents an active authorized session.
type Session struct {
	ID                     string    `json:"id"`
	UserID                 string    `json:"user_id"`
	Username               string    `json:"username"`
	DeviceID               string    `json:"device_id"`
	SourceIP               string    `json:"source_ip"`
	Resource               string    `json:"resource"`
	GatewayID              string    `json:"gateway_id,omitempty"`
	Protocol               string    `json:"protocol"`
	RiskSignals            []string  `json:"risk_signals,omitempty"`
	OrganizationID         string    `json:"organization_id,omitempty"`
	PolicyID               string    `json:"policy_id,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	LastActivity           time.Time `json:"last_activity"`
	RevalidateAfter        time.Time `json:"revalidate_after,omitempty"`
	StepUpACR              string    `json:"step_up_acr,omitempty"`
	StepUpMethod           string    `json:"step_up_method,omitempty"`
	StepUpStrength         string    `json:"step_up_strength,omitempty"`
	StepUpAAGUID           string    `json:"step_up_aaguid,omitempty"`
	StepUpAttachment       string    `json:"step_up_attachment,omitempty"`
	StepUpVerifiedAt       time.Time `json:"step_up_verified_at,omitempty"`
	StepUpExpiresAt        time.Time `json:"step_up_expires_at,omitempty"`
	SessionMaxAgeSeconds   int       `json:"session_max_age_seconds,omitempty"`
	RevalidateEverySeconds int       `json:"revalidate_every_seconds,omitempty"`
	RevokeOnPostureChange  bool      `json:"revoke_on_posture_change,omitempty"`
	Revoked                bool      `json:"revoked"`
}
