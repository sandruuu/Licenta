package ipc

import "time"

type AgentDashboard struct {
	Connection  DashboardConnection `json:"connection"`
	Status      AgentStatus         `json:"status"`
	Enrollment  EnrollmentInfo      `json:"enrollment"`
	UserSession UserSessionInfo     `json:"user_session"`
	Catalog     CatalogInfo         `json:"catalog,omitempty"`
	DeviceData  DeviceDataReport    `json:"device_data"`
	ReportedAt  time.Time           `json:"reported_at"`
}

type DashboardConnection struct {
	State        string `json:"state"`
	Message      string `json:"message,omitempty"`
	ServiceState string `json:"service_state,omitempty"`
}

type EnrollmentInfo struct {
	State     EnrollmentState `json:"state"`
	DeviceID  string          `json:"device_id,omitempty"`
	Message   string          `json:"message,omitempty"`
	LastError string          `json:"last_error,omitempty"`
}
