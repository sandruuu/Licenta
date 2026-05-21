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
