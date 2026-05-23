package ipc

import "time"

const (
	UserSessionStateSignedOut      = "SIGNED_OUT"
	UserSessionStateAuthenticating = "AUTHENTICATING"
	UserSessionStateAuthenticated  = "AUTHENTICATED"
	UserSessionStateFailed         = "FAILED"
)

type StartUserLoginInteractiveRequest struct{}

type StartUserLoginInteractiveResponse struct {
	Started             bool      `json:"started"`
	AuthURL             string    `json:"auth_url,omitempty"`
	SessionRequestID    string    `json:"session_request_id,omitempty"`
	State               string    `json:"state"`
	Message             string    `json:"message,omitempty"`
	ExpiresAt           time.Time `json:"expires_at,omitempty"`
	PollIntervalSeconds int       `json:"poll_interval_seconds,omitempty"`
	ReportedAt          time.Time `json:"reported_at"`
}

type LogoutUserSessionRequest struct{}

type LogoutUserSessionResponse struct {
	LoggedOut  bool      `json:"logged_out"`
	State      string    `json:"state"`
	ReportedAt time.Time `json:"reported_at"`
}

type UserSessionInfo struct {
	State       string    `json:"state"`
	SessionID   string    `json:"session_id,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	Email       string    `json:"email,omitempty"`
	Message     string    `json:"message,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

type CatalogInfo struct {
	Version     string            `json:"version,omitempty"`
	Resources   []CatalogResource `json:"resources,omitempty"`
	TTLSeconds  int               `json:"ttl_seconds,omitempty"`
	PolicyEpoch string            `json:"policy_epoch,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
}

type CatalogResource struct {
	ResourceID  string `json:"resource_id"`
	DisplayName string `json:"display_name,omitempty"`
	FQDN        string `json:"fqdn,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Port        int    `json:"port,omitempty"`
	AccessMode  string `json:"access_mode,omitempty"`
}
