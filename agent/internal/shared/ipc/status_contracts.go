package ipc

import "time"

type PingRequest struct {
	Message     string    `json:"message"`
	TrayPID     int       `json:"tray_pid"`
	TrayUser    string    `json:"tray_user,omitempty"`
	TrayUserSID string    `json:"tray_user_sid,omitempty"`
	SentAt      time.Time `json:"sent_at"`
}

type PingResponse struct {
	Message        string    `json:"message"`
	Echo           string    `json:"echo"`
	Protocol       string    `json:"protocol"`
	PipeName       string    `json:"pipe_name"`
	ServiceState   string    `json:"service_state"`
	ServicePID     int       `json:"service_pid"`
	ServiceUser    string    `json:"service_user,omitempty"`
	ServiceUserSID string    `json:"service_user_sid,omitempty"`
	ReceivedAt     time.Time `json:"received_at"`
}

type StatusRequest struct{}

type DashboardRequest struct{}

type AgentStatus struct {
	ServiceState          string          `json:"service_state"`
	ServicePID            int             `json:"service_pid"`
	ServiceUser           string          `json:"service_user,omitempty"`
	ServiceUserSID        string          `json:"service_user_sid,omitempty"`
	EnrollmentState       EnrollmentState `json:"enrollment_state"`
	EnrollmentDeviceID    string          `json:"enrollment_device_id,omitempty"`
	EnrollmentLastError   string          `json:"enrollment_last_error,omitempty"`
	DeviceDataStatus      string          `json:"device_data_status,omitempty"`
	DeviceDataCheckCount  int             `json:"device_data_check_count,omitempty"`
	DeviceDataCollectedAt time.Time       `json:"device_data_collected_at,omitempty"`
	DeviceDataLastError   string          `json:"device_data_last_error,omitempty"`
	ReportedAt            time.Time       `json:"reported_at"`
}
