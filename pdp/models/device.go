package models

import "time"

// DeviceHealthReport is sent by the device-health app via the gateway.
type DeviceHealthReport struct {
	DeviceID     string        `json:"device_id"`
	Hostname     string        `json:"hostname"`
	OS           string        `json:"os"`
	Checks       []HealthCheck `json:"checks"`
	OverallScore int           `json:"overall_score"`
	ReportedAt   time.Time     `json:"reported_at"`
	TenantID     string        `json:"tenant_id,omitempty"`
}

// DevicePostureReport is the normalized posture payload used by policies.
type DevicePostureReport struct {
	DeviceID    string        `json:"device_id"`
	Hostname    string        `json:"hostname"`
	OS          string        `json:"os"`
	Checks      []HealthCheck `json:"checks"`
	CollectedAt time.Time     `json:"collected_at"`
	ReportedAt  time.Time     `json:"reported_at"`
	TenantID    string        `json:"tenant_id,omitempty"`
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
