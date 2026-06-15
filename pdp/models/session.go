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
	RiskScore              int       `json:"risk_score"`
	OrganizationID         string    `json:"organization_id,omitempty"`
	PolicyID               string    `json:"policy_id,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	LastActivity           time.Time `json:"last_activity"`
	RevalidateAfter        time.Time `json:"revalidate_after,omitempty"`
	SessionMaxAgeSeconds   int       `json:"session_max_age_seconds,omitempty"`
	RevalidateEverySeconds int       `json:"revalidate_every_seconds,omitempty"`
	RevokeOnPostureChange  bool      `json:"revoke_on_posture_change,omitempty"`
	RevokeOnRiskIncrease   bool      `json:"revoke_on_risk_increase,omitempty"`
	Revoked                bool      `json:"revoked"`
}
