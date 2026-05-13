package models

import "time"

// Session represents an active authorized session.
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	DeviceID     string    `json:"device_id"`
	SourceIP     string    `json:"source_ip"`
	Resource     string    `json:"resource"`
	GatewayID    string    `json:"gateway_id,omitempty"`
	Protocol     string    `json:"protocol"`
	RiskScore    int       `json:"risk_score"`
	TenantID     string    `json:"tenant_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastActivity time.Time `json:"last_activity"`
	Revoked      bool      `json:"revoked"`
}

// PendingAuthSession represents a browser-based login session.
type PendingAuthSession struct {
	ID           string              `json:"id"`
	DeviceID     string              `json:"device_id"`
	Hostname     string              `json:"hostname"`
	Status       string              `json:"status"`
	AuthToken    string              `json:"auth_token,omitempty"`
	MFAToken     string              `json:"mfa_token,omitempty"`
	UserID       string              `json:"user_id,omitempty"`
	Username     string              `json:"username,omitempty"`
	DeviceHealth *DeviceHealthReport `json:"device_health,omitempty"`
	CreatedAt    time.Time           `json:"created_at"`
	ExpiresAt    time.Time           `json:"expires_at"`
}

// StartAuthSessionRequest is sent by the connect app to initiate browser auth.
type StartAuthSessionRequest struct {
	DeviceID     string              `json:"device_id"`
	Hostname     string              `json:"hostname"`
	DeviceHealth *DeviceHealthReport `json:"device_health,omitempty"`
}

// StartAuthSessionResponse contains the session ID and browser URL.
type StartAuthSessionResponse struct {
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url"`
	ExpiresIn int    `json:"expires_in"`
}

// AuthSessionStatusResponse is returned when the connect app polls status.
type AuthSessionStatusResponse struct {
	Status    string `json:"status"`
	AuthToken string `json:"auth_token,omitempty"`
	Message   string `json:"message,omitempty"`
}
