package models

import "time"

// ─────────────────────────────────────────────
// User & Authentication
// ─────────────────────────────────────────────

// User represents a registered user in the identity provider
type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	PasswordHash string   `json:"password_hash"`
	TOTPSecret   string   `json:"totp_secret,omitempty"` // base32-encoded TOTP secret
	MFAMethods   []string `json:"mfa_methods"`           // configured MFA methods: "totp", "webauthn", "push"
	Role         string   `json:"role"`                  // "admin", "user"
	Disabled     bool     `json:"disabled"`

	// Federation: set when user was auto-provisioned from an external IdP
	ExternalSubject string `json:"external_subject,omitempty"` // external IdP subject (sub claim)
	AuthSource      string `json:"auth_source,omitempty"`      // "builtin", "keycloak", etc.

	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

// MFAEnabled returns true if the user has at least one MFA method configured.
func (u *User) MFAEnabled() bool {
	return len(u.MFAMethods) > 0
}

// LoginRequest represents the primary authentication request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is returned after primary authentication succeeds
type LoginResponse struct {
	Status     string   `json:"status"` // "authenticated", "denied"
	Message    string   `json:"message"`
	AuthToken  string   `json:"auth_token,omitempty"` // JWT with MFADone=false (always issued on success)
	UserID     string   `json:"user_id"`
	MFAMethods []string `json:"mfa_methods,omitempty"` // available MFA methods for the user
}

// MFAVerifyRequest is sent to complete the MFA step-up during resource access.
// Method selects the MFA type; the corresponding field must be populated.
type MFAVerifyRequest struct {
	MFAToken string `json:"mfa_token"`           // temporary MFA-scoped token
	Method   string `json:"method"`              // "totp", "webauthn", "push"
	TOTPCode string `json:"totp_code,omitempty"` // 6-digit TOTP code (when method="totp")
}

// MFAVerifyResponse is returned after successful MFA verification
type MFAVerifyResponse struct {
	Status    string `json:"status"` // "authenticated", "denied"
	Message   string `json:"message"`
	AuthToken string `json:"auth_token,omitempty"` // final JWT
}

// MFAStepUpRequest is sent by the login page when the policy engine requires MFA.
// The browser submits the user's existing auth token (MFADone=false) to receive
// a temporary MFA token and the list of configured MFA methods.
type MFAStepUpRequest struct {
	AuthToken     string `json:"auth_token"`                // JWT with MFADone=false
	OIDCSessionID string `json:"oidc_session_id,omitempty"` // OIDC session (for callback tracking)
}

// MFAStepUpResponse tells the login page which MFA methods are available
// and provides a temporary MFA token for the verification step.
type MFAStepUpResponse struct {
	Status     string   `json:"status"` // "mfa_required", "denied"
	Message    string   `json:"message"`
	MFAToken   string   `json:"mfa_token,omitempty"`   // temporary token for VerifyMFA
	MFAMethods []string `json:"mfa_methods,omitempty"` // configured methods: "totp", "webauthn", "push"
}

// MFAEnrollResponse is returned when enrolling in MFA
type MFAEnrollResponse struct {
	Secret    string `json:"secret"`      // base32-encoded TOTP secret
	QRCodeURL string `json:"qr_code_url"` // otpauth:// URI for QR code
	Message   string `json:"message"`
}

// RegisterRequest represents a new user registration
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ─────────────────────────────────────────────
// Device Health
// ─────────────────────────────────────────────

// DeviceHealthReport is sent by the device-health-app via the gateway
type DeviceHealthReport struct {
	DeviceID     string        `json:"device_id"`
	Hostname     string        `json:"hostname"`
	OS           string        `json:"os"`
	Checks       []HealthCheck `json:"checks"`
	OverallScore int           `json:"overall_score"`
	ReportedAt   time.Time     `json:"reported_at"`
}

// HealthCheck is a single device health check result
type HealthCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"` // "good", "warning", "critical"
	Description string            `json:"description"`
	Details     map[string]string `json:"details"`
}

// ─────────────────────────────────────────────
// Policy Engine
// ─────────────────────────────────────────────

// PolicyRule defines a conditional access rule
type PolicyRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Priority    int            `json:"priority"` // lower = higher priority
	Enabled     bool           `json:"enabled"`
	Conditions  RuleConditions `json:"conditions"`
	Action      string         `json:"action"` // "allow", "deny", "mfa_required", "restrict"
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// RuleConditions defines the conditions under which a policy rule applies
type RuleConditions struct {
	// Device health requirements
	MinHealthScore      int      `json:"min_health_score,omitempty"`      // 0-100
	RequiredChecks      []string `json:"required_checks,omitempty"`       // e.g. ["Firewall", "Antivirus"]
	RequiredCheckStatus string   `json:"required_check_status,omitempty"` // "good", "warning"

	// User context
	AllowedRoles []string `json:"allowed_roles,omitempty"` // e.g. ["admin", "user"]
	AllowedUsers []string `json:"allowed_users,omitempty"` // specific user IDs

	// Network context
	AllowedIPs []string `json:"allowed_ips,omitempty"` // CIDR ranges
	BlockedIPs []string `json:"blocked_ips,omitempty"` // CIDR ranges

	// Time context
	AllowedTimeStart string   `json:"allowed_time_start,omitempty"` // "09:00"
	AllowedTimeEnd   string   `json:"allowed_time_end,omitempty"`   // "17:00"
	AllowedDays      []string `json:"allowed_days,omitempty"`       // ["Monday", "Tuesday", ...]
	Timezone         string   `json:"timezone,omitempty"`           // IANA tz e.g. "Europe/Bucharest" (default: UTC)
	BlockedDates     []string `json:"blocked_dates,omitempty"`      // Specific dates to block: ["2025-12-25", "2025-01-01"]
	DateRangeStart   string   `json:"date_range_start,omitempty"`   // "2025-06-01" — rule active from this date
	DateRangeEnd     string   `json:"date_range_end,omitempty"`     // "2025-09-30" — rule active until this date

	// Resource context
	TargetResources []string `json:"target_resources,omitempty"` // resource IDs
	TargetPorts     []int    `json:"target_ports,omitempty"`     // port numbers

	// Risk threshold
	MaxRiskScore int `json:"max_risk_score,omitempty"` // 0-100
}

// AccessRequest is sent by the gateway when a user tries to access a resource
type AccessRequest struct {
	UserID       string              `json:"user_id"`
	Username     string              `json:"username"`
	DeviceID     string              `json:"device_id"`
	SourceIP     string              `json:"source_ip"`
	Resource     string              `json:"resource"` // target resource identifier
	ResourcePort int                 `json:"resource_port"`
	Protocol     string              `json:"protocol"`         // "rdp", "ssh", "https"
	AuthToken    string              `json:"auth_token"`       // JWT token
	AppID        string              `json:"app_id,omitempty"` // cloud resource ID for per-app policy matching
	DeviceHealth *DeviceHealthReport `json:"device_health,omitempty"`

	// Anomaly signals forwarded by the gateway PEP
	AnomalyAlerts []string `json:"anomaly_alerts,omitempty"` // e.g. ["brute_force","connection_flood"]
	AnomalyScore  int      `json:"anomaly_score,omitempty"`  // gateway-side anomaly score (0-25)
}

// AccessDecision is the policy engine's response
type AccessDecision struct {
	Decision    string   `json:"decision"` // "allow", "deny", "mfa_required", "restrict"
	Reason      string   `json:"reason"`
	RiskScore   int      `json:"risk_score"`   // 0-100, higher = riskier
	MatchedRule string   `json:"matched_rule"` // ID of the rule that triggered the decision
	Policies    []string `json:"policies"`     // list of allowed resources/actions
	SessionID   string   `json:"session_id,omitempty"`
	ExpiresAt   int64    `json:"expires_at,omitempty"` // Unix timestamp
}

// RiskContext contains all the contextual information used for risk scoring
type RiskContext struct {
	UserID             string
	SourceIP           string
	DeviceHealth       *DeviceHealthReport
	FailedAttempts     int
	IsNewDevice        bool
	IsNewLocation      bool
	TimeOfDay          time.Time
	Protocol           string
	GeoVelocity        float64 // estimated travel speed in km/h (0 = unknown)
	IsImpossibleTravel bool    // true if speed > 900 km/h

	// Anomaly signals from gateway behavioral detector
	AnomalyAlerts []string // active alert types (e.g. "brute_force")
	AnomalyScore  int      // gateway-computed score (0-25)
}

// LoginLocation records where a user logged in from (IP geolocation).
type LoginLocation struct {
	UserID    string    `json:"user_id"`
	SourceIP  string    `json:"source_ip"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	City      string    `json:"city"`
	Country   string    `json:"country"`
	Timestamp time.Time `json:"timestamp"`
}

// ─────────────────────────────────────────────
// WebAuthn / Passkeys
// ─────────────────────────────────────────────

// WebAuthnCredential stores a WebAuthn credential linked to a user.
// CredentialJSON holds the serialised webauthn.Credential (go-webauthn lib).
type WebAuthnCredential struct {
	ID             string    `json:"id"`              // unique row ID
	UserID         string    `json:"user_id"`         // owning user
	CredentialID   string    `json:"credential_id"`   // base64url-encoded credential ID from authenticator
	CredentialJSON string    `json:"credential_json"` // JSON-serialised webauthn.Credential
	Name           string    `json:"name"`            // friendly label ("YubiKey 5", "iPhone")
	CreatedAt      time.Time `json:"created_at"`
}

// ─────────────────────────────────────────────
// Push MFA
// ─────────────────────────────────────────────

// PushChallenge represents a push-based MFA approval request.
// Created when the browser initiates a push MFA flow; the device-health-app
// polls for pending challenges and the user approves or denies on-device.
type PushChallenge struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	DeviceID    string    `json:"device_id"`
	SourceIP    string    `json:"source_ip"`
	Status      string    `json:"status"` // "pending", "approved", "denied", "expired"
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RespondedAt time.Time `json:"responded_at,omitempty"`
}

// ─────────────────────────────────────────────
// Sessions & Audit
// ─────────────────────────────────────────────

// Session represents an active authorized session
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	DeviceID     string    `json:"device_id"`
	SourceIP     string    `json:"source_ip"`
	Resource     string    `json:"resource"`
	Protocol     string    `json:"protocol"`
	RiskScore    int       `json:"risk_score"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastActivity time.Time `json:"last_activity"`
	Revoked      bool      `json:"revoked"`
}

// AuditEntry represents an entry in the audit log
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"` // "login", "mfa_verify", "access_request", "session_revoked", etc.
	UserID    string    `json:"user_id,omitempty"`
	Username  string    `json:"username,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Decision  string    `json:"decision,omitempty"`
	Details   string    `json:"details"`
	Success   bool      `json:"success"`
}

// ─────────────────────────────────────────────
// Resources / Applications (PDP managed)
// ─────────────────────────────────────────────

// Resource represents a protected application/service managed by the PDP.
// Each resource has a type (ssh, rdp, web, gateway) and associated TLS certificate.
type Resource struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Type        string            `json:"type"`                   // "ssh", "rdp", "web", "gateway"
	Host        string            `json:"host"`                   // internal hostname or IP
	Port        int               `json:"port"`                   // service port
	ExternalURL string            `json:"external_url,omitempty"` // public-facing URL (for web)
	Enabled     bool              `json:"enabled"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`

	// Per-app credentials (Duo-style integration)
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`

	// TLS Certificate
	CertMode   string `json:"cert_mode"`             // "manual", "vault-signed", "letsencrypt"
	CertPEM    string `json:"cert_pem,omitempty"`    // PEM-encoded certificate
	KeyPEM     string `json:"key_pem,omitempty"`     // PEM-encoded private key
	CertExpiry string `json:"cert_expiry,omitempty"` // ISO8601 expiration date
	CertDomain string `json:"cert_domain,omitempty"` // domain for the certificate

	// Access control
	AllowedRoles []string `json:"allowed_roles,omitempty"` // roles that can access
	RequireMFA   bool     `json:"require_mfa"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ─────────────────────────────────────────────
// Dashboard Statistics
// ─────────────────────────────────────────────

// DashboardStats provides overview metrics for the admin dashboard
type DashboardStats struct {
	TotalUsers     int `json:"total_users"`
	ActiveSessions int `json:"active_sessions"`
	TotalResources int `json:"total_resources"`
	TotalPolicies  int `json:"total_policies"`
	RecentDenials  int `json:"recent_denials"`
	AverageRisk    int `json:"average_risk"`
	HealthyDevices int `json:"healthy_devices"`
	TotalDevices   int `json:"total_devices"`
}

// ─────────────────────────────────────────────
// Browser Auth Sessions (Duo-like flow)
// ─────────────────────────────────────────────

// PendingAuthSession represents a browser-based login session.
// The connect-app creates one, opens the browser to the cloud login page,
// and polls until the user completes authentication.
type PendingAuthSession struct {
	ID           string              `json:"id"`
	DeviceID     string              `json:"device_id"`
	Hostname     string              `json:"hostname"`
	Status       string              `json:"status"` // "pending", "authenticated", "mfa_required", "denied", "expired"
	AuthToken    string              `json:"auth_token,omitempty"`
	MFAToken     string              `json:"mfa_token,omitempty"`
	UserID       string              `json:"user_id,omitempty"`
	Username     string              `json:"username,omitempty"`
	DeviceHealth *DeviceHealthReport `json:"device_health,omitempty"`
	CreatedAt    time.Time           `json:"created_at"`
	ExpiresAt    time.Time           `json:"expires_at"`
}

// StartAuthSessionRequest is sent by connect-app to initiate browser auth
type StartAuthSessionRequest struct {
	DeviceID     string              `json:"device_id"`
	Hostname     string              `json:"hostname"`
	DeviceHealth *DeviceHealthReport `json:"device_health,omitempty"`
}

// StartAuthSessionResponse contains the session ID and browser URL
type StartAuthSessionResponse struct {
	SessionID string `json:"session_id"`
	AuthURL   string `json:"auth_url"`
	ExpiresIn int    `json:"expires_in"` // seconds
}

// AuthSessionStatusResponse is returned when connect-app polls session status
type AuthSessionStatusResponse struct {
	Status    string `json:"status"` // "pending", "authenticated", "denied", "expired"
	AuthToken string `json:"auth_token,omitempty"`
	Message   string `json:"message,omitempty"`
}

// ─────────────────────────────────────────────
// Generic API Response
// ─────────────────────────────────────────────

// APIResponse is a generic API response wrapper
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ─────────────────────────────────────────────
// Device Enrollment
// ─────────────────────────────────────────────

// DeviceEnrollment represents a device certificate enrollment request/record
type DeviceEnrollment struct {
	ID                   string    `json:"id"`
	DeviceID             string    `json:"device_id"`
	Component            string    `json:"component"` // "health" or "tunnel"
	Hostname             string    `json:"hostname"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint,omitempty"` // SHA-256 of the device's public key
	CertFingerprint      string    `json:"cert_fingerprint,omitempty"`
	CertSerial           string    `json:"cert_serial,omitempty"`
	Status               string    `json:"status"` // "pending", "approved", "revoked"
	CSRPEM               string    `json:"csr_pem,omitempty"`
	CertPEM              string    `json:"cert_pem,omitempty"`
	EnrolledAt           time.Time `json:"enrolled_at"`
	ExpiresAt            time.Time `json:"expires_at,omitempty"`
	ApprovedBy           string    `json:"approved_by,omitempty"`
	UserID               string    `json:"user_id,omitempty"`
	Username             string    `json:"username,omitempty"`
}

// EnrollmentRequest is sent by a device agent to request certificate enrollment
type EnrollmentRequest struct {
	DeviceID             string `json:"device_id"`
	Component            string `json:"component"` // "health" or "tunnel"
	Hostname             string `json:"hostname"`
	CSRPEM               string `json:"csr_pem"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"` // SHA-256 of device public key
}

// EnrollmentResponse is returned after enrollment request or approval
type EnrollmentResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Message string `json:"message,omitempty"`
}

// PendingEnrollSession is an ephemeral browser-based enrollment session (5-min TTL).
// Connect-app creates it, user authenticates in browser, Cloud auto-signs CSR.
type PendingEnrollSession struct {
	ID                   string    `json:"id"`
	DeviceID             string    `json:"device_id"`
	Component            string    `json:"component"` // "health" or "tunnel"
	Hostname             string    `json:"hostname"`
	CSRPEM               string    `json:"csr_pem"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	Status               string    `json:"status"` // "pending", "authenticated", "denied"
	AuthToken            string    `json:"auth_token,omitempty"`
	UserID               string    `json:"user_id,omitempty"`
	Username             string    `json:"username,omitempty"`
	CertPEM              string    `json:"cert_pem,omitempty"`
	CAPEM                string    `json:"ca_pem,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

// ─────────────────────────────────────────────
// Device-User Binding
// ─────────────────────────────────────────────

// DeviceUser represents a user-device association.
// The "owner" role is set at enrollment; "user" roles are added at each access session.
type DeviceUser struct {
	DeviceID string    `json:"device_id"`
	UserID   string    `json:"user_id"`
	Username string    `json:"username"`
	Role     string    `json:"role"` // "owner" (enrolled the device) or "user" (accessed via device)
	BoundAt  time.Time `json:"bound_at"`
}

// ─────────────────────────────────────────────
// Gateway Registration (Zscaler-style enrollment)
// ─────────────────────────────────────────────

// Gateway represents a registered gateway (PEP) in the cloud (PDP).
// Gateways are created by admins and enrolled using one-time tokens.
type Gateway struct {
	ID   string `json:"id"`
	Name string `json:"name"` // human-readable name, e.g. "HQ Gateway"
	FQDN string `json:"fqdn"` // public FQDN, e.g. "gateway.company.com"

	// Enrollment
	EnrollmentToken string `json:"enrollment_token,omitempty"` // one-time token (hex, 32 bytes)
	TokenExpiresAt  string `json:"token_expires_at,omitempty"` // ISO8601
	Status          string `json:"status"`                     // "pending", "enrolled", "revoked"

	// mTLS certificate info (after enrollment)
	CertPEM         string `json:"cert_pem,omitempty"`
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
	CertSerial      string `json:"cert_serial,omitempty"`
	CertExpiresAt   string `json:"cert_expires_at,omitempty"`

	// OIDC client (auto-created at enrollment)
	OIDCClientID     string `json:"oidc_client_id,omitempty"`
	OIDCClientSecret string `json:"oidc_client_secret,omitempty"`

	// Network
	ListenAddr string `json:"listen_addr,omitempty"`
	PublicIP   string `json:"public_ip,omitempty"`

	// Assigned resources (IDs of resources this gateway serves)
	AssignedResources []string `json:"assigned_resources,omitempty"`

	// Identity Broker: per-gateway authentication mode
	AuthMode         string            `json:"auth_mode"`                   // "builtin" (default) or "federated"
	FederationConfig *FederationConfig `json:"federation_config,omitempty"` // nil when AuthMode="builtin"

	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
}

// FederationConfig holds the external OIDC IdP configuration for a gateway.
// When a gateway uses "federated" auth mode, cloud redirects users to this
// external IdP instead of showing the built-in login form.
type FederationConfig struct {
	Issuer        string            `json:"issuer"`                  // e.g. "https://keycloak.company.com/realms/master"
	ClientID      string            `json:"client_id"`               // OIDC client registered in external IdP
	ClientSecret  string            `json:"client_secret,omitempty"` // optional for public clients using PKCE
	Scopes        string            `json:"scopes"`                  // default "openid profile email"
	ClaimMapping  map[string]string `json:"claim_mapping,omitempty"` // e.g. {"username": "preferred_username", "email": "email"}
	AutoDiscovery bool              `json:"auto_discovery"`          // use .well-known/openid-configuration
}

// GatewayEnrollRequest is sent by the gateway during enrollment.
type GatewayEnrollRequest struct {
	Token  string `json:"token"`   // one-time enrollment token
	CSRPEM string `json:"csr_pem"` // PEM-encoded CSR for mTLS cert
	FQDN   string `json:"fqdn"`    // gateway's public FQDN
	Name   string `json:"name,omitempty"`
}

// GatewayEnrollResponse is returned after successful enrollment.
type GatewayEnrollResponse struct {
	Status           string `json:"status"` // "enrolled"
	GatewayID        string `json:"gateway_id"`
	CertPEM          string `json:"cert_pem"` // signed mTLS client certificate
	CAPEM            string `json:"ca_pem"`   // CA certificate for verifying cloud
	OIDCClientID     string `json:"oidc_client_id"`
	OIDCClientSecret string `json:"oidc_client_secret"`
	OIDCAuthURL      string `json:"oidc_auth_url"`  // e.g. "https://cloud:8443/auth/authorize"
	OIDCTokenURL     string `json:"oidc_token_url"` // e.g. "https://cloud:8443/auth/token"
	Message          string `json:"message,omitempty"`
}

// GatewayResourceSync is a resource entry returned during gateway resource sync.
type GatewayResourceSync struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AllowedRoles []string `json:"allowed_roles,omitempty"`
	RequireMFA   bool     `json:"require_mfa"`
	Enabled      bool     `json:"enabled"`
}
