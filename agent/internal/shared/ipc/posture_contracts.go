package ipc

import "time"

type DevicePostureRequest struct{}

const (
	DevicePostureStatusGood        = "good"
	DevicePostureStatusWarning     = "warning"
	DevicePostureStatusCritical    = "critical"
	DevicePostureStatusUnavailable = "unavailable"
)

type DevicePostureReport struct {
	DeviceID    string               `json:"device_id,omitempty"`
	Hostname    string               `json:"hostname"`
	OS          string               `json:"os"`
	Checks      []DevicePostureCheck `json:"checks"`
	CollectedAt time.Time            `json:"collected_at"`
}

type DevicePostureCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details,omitempty"`
}
