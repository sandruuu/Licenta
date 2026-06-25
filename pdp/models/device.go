package models

import "time"

// DeviceHealthReport is the computed posture summary derived from device data.
type DeviceHealthReport struct {
	DeviceID       string        `json:"device_id"`
	Hostname       string        `json:"hostname"`
	OS             string        `json:"os"`
	Checks         []HealthCheck `json:"checks"`
	ReportedAt     time.Time     `json:"reported_at"`
	OrganizationID string        `json:"organization_id,omitempty"`
}

// DeviceDataReport is the normalized raw device data payload used by policies.
type DeviceDataReport struct {
	DeviceID       string        `json:"device_id"`
	UserID         string        `json:"user_id,omitempty"`
	Username       string        `json:"username,omitempty"`
	AgentSessionID string        `json:"agent_session_id,omitempty"`
	Hostname       string        `json:"hostname"`
	OS             string        `json:"os"`
	Checks         []HealthCheck `json:"checks"`
	CollectedAt    time.Time     `json:"collected_at"`
	ReportedAt     time.Time     `json:"reported_at"`
	OrganizationID string        `json:"organization_id,omitempty"`
}

// HealthCheck is a single device health check result.
type HealthCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details"`
}

// DeviceUser represents a user-device association.
type DeviceUser struct {
	DeviceID string    `json:"device_id"`
	UserID   string    `json:"user_id"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	BoundAt  time.Time `json:"bound_at"`
}
