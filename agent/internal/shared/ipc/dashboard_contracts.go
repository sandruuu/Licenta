package ipc

import "time"

type AgentDashboard struct {
	Connection     DashboardConnection `json:"connection"`
	Status         AgentStatus         `json:"status"`
	Enrollment     EnrollmentInfo      `json:"enrollment"`
	Certificate    CertificateInfo     `json:"certificate"`
	User           AuthenticatedUser   `json:"user"`
	Posture        DevicePostureReport `json:"posture"`
	Resources      []CatalogResource   `json:"resources"`
	ActiveSessions []ActiveSession     `json:"active_sessions"`
	AccessEvents   []AccessEvent       `json:"access_events"`
	ReportedAt     time.Time           `json:"reported_at"`
}

type DashboardConnection struct {
	State        string `json:"state"`
	Message      string `json:"message,omitempty"`
	ServiceState string `json:"service_state,omitempty"`
	SessionState string `json:"session_state,omitempty"`
	CatalogState string `json:"catalog_state,omitempty"`
	NetworkState string `json:"network_state,omitempty"`
}

type EnrollmentInfo struct {
	State          EnrollmentState `json:"state"`
	DeviceID       string          `json:"device_id,omitempty"`
	DeviceIDSource string          `json:"device_id_source,omitempty"`
	ActiveUserSID  string          `json:"active_user_sid,omitempty"`
	KeyName        string          `json:"key_name,omitempty"`
	KeyExists      bool            `json:"key_exists"`
	KeyProvider    string          `json:"key_provider,omitempty"`
	Nonce          string          `json:"nonce,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
}

type CertificateInfo struct {
	SHA256       string    `json:"sha256,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	SerialNumber string    `json:"serial_number,omitempty"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Valid        bool      `json:"valid"`
	LastError    string    `json:"last_error,omitempty"`
}

type AuthenticatedUser struct {
	UserSID              string    `json:"user_sid,omitempty"`
	AuthorizedUserSID    string    `json:"authorized_user_sid,omitempty"`
	Email                string    `json:"email,omitempty"`
	SessionState         string    `json:"session_state,omitempty"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at,omitempty"`
}

type CatalogResource struct {
	FQDN       string    `json:"fqdn"`
	ResourceID string    `json:"resource_id,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Port       int       `json:"port,omitempty"`
	Status     string    `json:"status,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

type CatalogResourcesResponse struct {
	Resources  []CatalogResource `json:"resources"`
	ReportedAt time.Time         `json:"reported_at"`
}

type ActiveSession struct {
	ID         string    `json:"id"`
	ResourceID string    `json:"resource_id,omitempty"`
	FQDN       string    `json:"fqdn,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Port       int       `json:"port,omitempty"`
	State      string    `json:"state"`
	UserSID    string    `json:"user_sid,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	BytesIn    int64     `json:"bytes_in,omitempty"`
	BytesOut   int64     `json:"bytes_out,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

type ActiveSessionsResponse struct {
	Sessions   []ActiveSession `json:"sessions"`
	ReportedAt time.Time       `json:"reported_at"`
}

type AccessEvent struct {
	ID         string            `json:"id"`
	Decision   string            `json:"decision"`
	Reason     string            `json:"reason"`
	Source     string            `json:"source,omitempty"`
	ResourceID string            `json:"resource_id,omitempty"`
	FQDN       string            `json:"fqdn,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	Port       int               `json:"port,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
}

type AccessEventsResponse struct {
	Events     []AccessEvent `json:"events"`
	ReportedAt time.Time     `json:"reported_at"`
}
