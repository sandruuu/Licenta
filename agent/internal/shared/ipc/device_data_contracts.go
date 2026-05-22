package ipc

import "time"

type DeviceDataRequest struct{}

const (
	DeviceDataStatusGood        = "good"
	DeviceDataStatusWarning     = "warning"
	DeviceDataStatusCritical    = "critical"
	DeviceDataStatusUnavailable = "unavailable"
)

type DeviceDataReport struct {
	DeviceID    string            `json:"device_id,omitempty"`
	Hostname    string            `json:"hostname"`
	OS          string            `json:"os"`
	Checks      []DeviceDataCheck `json:"checks"`
	CollectedAt time.Time         `json:"collected_at"`
}

type DeviceDataCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details,omitempty"`
}
