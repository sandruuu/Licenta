package models

import "time"

// Session represents a session shared across microservices via the session store
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	DeviceID     string    `json:"device_id"`
	SourceIP     string    `json:"source_ip"`
	AuthToken    string    `json:"auth_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	CloudSession string    `json:"cloud_session"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastActivity time.Time `json:"last_activity"`
	Active       bool      `json:"active"`
}

// LogEntry is a structured log record sent to the syslog aggregator
type LogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	Service   string            `json:"service"` // "portal", "admin", "sessionstore"
	Level     string            `json:"level"`   // "info", "warn", "error", "debug"
	Event     string            `json:"event"`   // machine-readable event type
	Message   string            `json:"message"` // human-readable description
	Fields    map[string]string `json:"fields,omitempty"`
}

// EnrollmentRequest is sent from admin to cloud during enrollment
type EnrollmentRequest struct {
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
	FQDN   string `json:"fqdn"`
	Name   string `json:"name,omitempty"`
}

// EnrollmentResponse is returned by cloud after enrollment
type EnrollmentResponse struct {
	Status           string `json:"status"`
	GatewayID        string `json:"gateway_id"`
	CertPEM          string `json:"cert_pem,omitempty"`
	CAPEM            string `json:"ca_pem,omitempty"`
	OIDCClientID     string `json:"oidc_client_id,omitempty"`
	OIDCClientSecret string `json:"oidc_client_secret,omitempty"`
	OIDCAuthURL      string `json:"oidc_auth_url,omitempty"`
	OIDCTokenURL     string `json:"oidc_token_url,omitempty"`
	Message          string `json:"message"`
}

// ResourceConfig defines an internal resource accessible through the gateway
type ResourceConfig struct {
	Name            string         `json:"name"`
	Type            string         `json:"type"`
	InternalIP      string         `json:"internal_ip"`
	TunnelIP        string         `json:"tunnel_ip"`
	Port            int            `json:"port"`
	Protocol        string         `json:"protocol"`
	MFARequired     bool           `json:"mfa_required"`
	ExternalURL     string         `json:"external_url,omitempty"`
	InternalURL     string         `json:"internal_url,omitempty"`
	InternalHosts   []InternalHost `json:"internal_hosts,omitempty"`
	SessionDuration int            `json:"session_duration,omitempty"`
	CertSource      string         `json:"cert_source,omitempty"`
	PassHeaders     bool           `json:"pass_headers,omitempty"`
	CreatedAt       string         `json:"created_at,omitempty"`
}

// InternalHost defines a backend host for SSH/RDP applications
type InternalHost struct {
	Host  string `json:"host"`
	Ports string `json:"ports"`
}

// AdminStats for the admin dashboard
type AdminStats struct {
	ActiveSessions int              `json:"active_sessions"`
	TotalResources int              `json:"total_resources"`
	UptimeSeconds  int64            `json:"uptime_seconds"`
	PortalStatus   string           `json:"portal_status"`
	StoreStatus    string           `json:"store_status"`
	SyslogStatus   string           `json:"syslog_status"`
	SetupComplete  bool             `json:"setup_complete"`
	Enrolled       bool             `json:"enrolled"`
	CGNATEnabled   bool             `json:"cgnat_enabled"`
	MTLSConfigured bool             `json:"mtls_configured"`
	IdPConfigured  bool             `json:"idp_configured"`
	Resources      []ResourceConfig `json:"resources"`
}

// SetupRequest is the first-boot wizard payload
type SetupRequest struct {
	AdminEmail    string `json:"admin_email"`
	AdminPassword string `json:"admin_password"`
}

// LoginRequest for admin console local authentication
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse returned after admin login
type LoginResponse struct {
	Status    string `json:"status"`
	Token     string `json:"token,omitempty"`
	CsrfToken string `json:"csrf_token,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CSRRequest to generate a Certificate Signing Request for mTLS
type CSRRequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
}

// CSRResponse returns the generated CSR PEM
type CSRResponse struct {
	CSRPEM  string `json:"csr_pem"`
	KeyPath string `json:"key_path"`
}

// AuthSourceUpdate for configuring the primary IdP
type AuthSourceUpdate struct {
	Mode         string `json:"mode,omitempty"`
	Hostname     string `json:"hostname"`
	AuthURL      string `json:"auth_url"`
	TokenURL     string `json:"token_url"`
	UserInfoURL  string `json:"userinfo_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	Scopes       string `json:"scopes"`
}

// CGNATUpdate for configuring the CGNAT address pool
type CGNATUpdate struct {
	Enabled    bool   `json:"enabled"`
	PoolStart  string `json:"pool_start"`
	PoolEnd    string `json:"pool_end"`
	SubnetMask string `json:"subnet_mask"`
}
