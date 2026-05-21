package contracts

import "time"

const (
	DevicePostureStatusGood        = "good"
	DevicePostureStatusWarning     = "warning"
	DevicePostureStatusCritical    = "critical"
	DevicePostureStatusUnavailable = "unavailable"
)

type DevicePostureReport struct {
	DeviceID    string               `json:"device_id,omitempty"`
	Hostname    string               `json:"hostname,omitempty"`
	OS          string               `json:"os,omitempty"`
	Checks      []DevicePostureCheck `json:"checks"`
	CollectedAt time.Time            `json:"collected_at,omitempty"`
}

type DevicePostureCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Description string            `json:"description,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
}

type ActiveSession struct {
	ID         string    `json:"id"`
	ResourceID string    `json:"resource_id"`
	FQDN       string    `json:"fqdn"`
	Protocol   string    `json:"protocol"`
	Port       int       `json:"port"`
	State      string    `json:"state"`
	UserSID    string    `json:"user_sid,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	BytesIn    int64     `json:"bytes_in,omitempty"`
	BytesOut   int64     `json:"bytes_out,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

type AccessEvent struct {
	ID         string            `json:"id"`
	Decision   string            `json:"decision"`
	Reason     string            `json:"reason,omitempty"`
	Source     string            `json:"source,omitempty"`
	ResourceID string            `json:"resource_id,omitempty"`
	FQDN       string            `json:"fqdn,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	Port       int               `json:"port,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	OccurredAt time.Time         `json:"occurred_at,omitempty"`
}
