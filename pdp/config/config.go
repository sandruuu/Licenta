package config

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// RuntimeConfig holds operational knobs for PDP runtime behavior.
type RuntimeConfig struct {
	StoreAutoSaveInterval      time.Duration `json:"store_auto_save_interval"`
	SessionCleanupInterval     time.Duration `json:"session_cleanup_interval"`
	EnrollmentCleanupInterval  time.Duration `json:"enrollment_cleanup_interval"`
	CertificateRenewBefore     time.Duration `json:"certificate_renew_before"`
	PKIRenewCheckInterval      time.Duration `json:"pki_renew_check_interval"`
	HTTPReadTimeout            time.Duration `json:"http_read_timeout"`
	HTTPReadHeaderTimeout      time.Duration `json:"http_read_header_timeout"`
	HTTPWriteTimeout           time.Duration `json:"http_write_timeout"`
	HTTPIdleTimeout            time.Duration `json:"http_idle_timeout"`
	HTTPShutdownTimeout        time.Duration `json:"http_shutdown_timeout"`
	ReadinessDrainDelay        time.Duration `json:"readiness_drain_delay"`
	EventBufferSize            int           `json:"event_buffer_size"`
	CatalogTTLSeconds          int           `json:"catalog_ttl_seconds"`
	AuthRateLimitWindow        time.Duration `json:"auth_rate_limit_window"`
	AuthRateLimitMax           int           `json:"auth_rate_limit_max"`
	OIDCEnrollmentTokenTTL     time.Duration `json:"oidc_enrollment_token_ttl"`
	WebAuthnChallengeTTL       time.Duration `json:"webauthn_challenge_ttl"`
	WebAuthnCleanupInterval    time.Duration `json:"webauthn_cleanup_interval"`
	FederationCacheTTL         time.Duration `json:"federation_cache_ttl"`
	FederationHTTPTimeout      time.Duration `json:"federation_http_timeout"`
	BrowserAuthSessionTTL      time.Duration `json:"browser_auth_session_ttl"`
	AdminAccessTokenTTL        time.Duration `json:"admin_access_token_ttl"`
	AdminSessionIdleTTL        time.Duration `json:"admin_session_idle_ttl"`
	AdminSessionAbsoluteTTL    time.Duration `json:"admin_session_absolute_ttl"`
	AgentSessionAccessTokenTTL time.Duration `json:"agent_session_access_token_ttl"`
	AgentSessionIdleTTL        time.Duration `json:"agent_session_idle_ttl"`
	AgentSessionAbsoluteTTL    time.Duration `json:"agent_session_absolute_ttl"`
	CSRFCookieMaxAgeSeconds    int           `json:"csrf_cookie_max_age_seconds"`
	EnrollRateLimitWindow      time.Duration `json:"enroll_rate_limit_window"`
	EnrollRateLimitMax         int           `json:"enroll_rate_limit_max"`
	GatewayRevokeTimeout       time.Duration `json:"gateway_revoke_timeout"`
	ResourceSessionRenewBefore time.Duration `json:"resource_session_renew_before"`
}

// PublicDashboardConfig is safe to expose to the React dashboard.
type PublicDashboardConfig struct {
	FederatedCallbackURL    string            `json:"federated_callback_url"`
	OIDCDefaultScopes       string            `json:"oidc_default_scopes"`
	OIDCDefaultClaimMapping map[string]string `json:"oidc_default_claim_mapping"`
	ResourceDefaultPorts    map[string]int    `json:"resource_default_ports"`
}

// GatewayConfig controls gateway lifecycle defaults.
type GatewayConfig struct {
	CertificateValidityDays int           `json:"certificate_validity_days"`
	EnrollmentTokenTTL      time.Duration `json:"enrollment_token_ttl"`
}

// EnrollmentConfig controls endpoint enrollment defaults.
type EnrollmentConfig struct {
	CertificateValidityDays int           `json:"certificate_validity_days"`
	BrowserSessionTTL       time.Duration `json:"browser_session_ttl"`
}

// GeoConfig controls external IP geolocation behavior.
type GeoConfig struct {
	ProviderURL              string        `json:"provider_url"`
	HTTPTimeout              time.Duration `json:"http_timeout"`
	CacheTTL                 time.Duration `json:"cache_ttl"`
	CacheMaxEntries          int           `json:"cache_max_entries"`
	SameAreaDistanceKM       float64       `json:"same_area_distance_km"`
	SuspiciousTravelSpeedKMH float64       `json:"suspicious_travel_speed_kmh"`
	ImpossibleTravelSpeedKMH float64       `json:"impossible_travel_speed_kmh"`
}

// Config holds all PDP service configuration
type Config struct {
	// Server settings
	ListenAddr   string   `json:"listen_addr"`   // e.g. ":8443"
	PDPFQDN      string   `json:"pdp_fqdn"`      // FQDN for self-enrollment CSR (e.g. "pdp")
	TLSDNSNames  []string `json:"tls_dns_names"` // Additional DNS SANs for the PDP TLS certificate
	PublicOrigin string   `json:"public_origin"` // Browser origin used to derive public callback, WebAuthn and CORS defaults
	TLSCert      string   `json:"tls_cert"`      // Path where the PDP TLS certificate is stored
	MTLSCA       string   `json:"mtls_ca"`       // Path where the issuer CA certificate is stored

	// Vault PKI settings (certificate signing backend)
	PKIURL         string        `json:"pki_url"`          // Vault base URL (e.g. "https://vault:8200")
	PKIToken       string        `json:"pki_token"`        // Vault token used by PDP for signing/revocation
	PKIPath        string        `json:"pki_path"`         // Vault PKI mount path (e.g. "pki_int")
	PKIRolePDP     string        `json:"pki_role_pdp"`     // Vault role for PDP self-enrollment TLS cert
	PKIRoleDevice  string        `json:"pki_role_device"`  // Vault role for device certificates
	PKIRoleGateway string        `json:"pki_role_gateway"` // Vault role for gateway mTLS certificates
	PKITransitKey  string        `json:"pki_transit_key"`  // Vault Transit key used for PDP private key encryption
	PKICAFile      string        `json:"pki_ca_file"`      // Optional CA file for Vault server TLS verification
	PKIServerName  string        `json:"pki_server_name"`  // Optional SNI/hostname override for Vault TLS
	PKITimeout     time.Duration `json:"pki_timeout"`      // HTTP timeout for PKI API calls

	// JWT settings
	JWTTransitKey       string `json:"jwt_transit_key"`        // Vault Transit key used for JWT signing key encryption
	JWTKeyEncryptedPath string `json:"jwt_key_encrypted_path"` // Vault Transit encrypted JWT signing key path

	// TOTP settings
	TOTPIssuer                string `json:"totp_issuer"`                   // issuer name shown in authenticator apps
	MFATransitKey             string `json:"mfa_transit_key"`               // optional Vault Transit key for MFA secret wrapping
	MFASecretKeyEncryptedPath string `json:"mfa_secret_key_encrypted_path"` // Vault Transit encrypted MFA data key path

	// Session settings
	SessionExpiry time.Duration `json:"session_expiry"` // session lifetime
	MaxSessions   int           `json:"max_sessions"`   // max sessions per user

	// Security settings
	MaxLoginAttempts int           `json:"max_login_attempts"` // before lockout
	LockoutDuration  time.Duration `json:"lockout_duration"`   // lockout period

	// Data persistence
	DataDir string `json:"data_dir"` // directory for data files and Vault Transit encrypted key

	// Database settings
	DatabaseURL         string `json:"database_url"`           // PostgreSQL connection URL
	RedisURL            string `json:"redis_url"`              // Redis connection URL for runtime state
	PDPKeyEncryptedPath string `json:"pdp_key_encrypted_path"` // Vault Transit encrypted PDP key path

	WebAuthnRPID      string `json:"webauthn_rp_id"`      // Relying Party ID (domain, e.g. "pdp.lab.local")
	WebAuthnRPName    string `json:"webauthn_rp_name"`    // Display name shown to user
	WebAuthnRPOrigins string `json:"webauthn_rp_origins"` // Comma-separated allowed origins (e.g. "https://pdp.lab.local:8443")

	// CORS settings
	CORSOrigins []string `json:"cors_origins"` // Allowed CORS origins for browser clients.

	Runtime    RuntimeConfig         `json:"runtime"`
	Public     PublicDashboardConfig `json:"public"`
	Gateway    GatewayConfig         `json:"gateway"`
	Enrollment EnrollmentConfig      `json:"enrollment"`
	Geo        GeoConfig             `json:"geo"`
}

// LoadFromFile loads configuration from the PDP JSON configuration file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	cfg.ApplyEnvironmentOverrides()
	return &cfg, nil
}

// PublicConfig returns the subset of configuration safe for browser clients.
func (c *Config) PublicConfig() PublicDashboardConfig {
	return c.Public
}

// CertificateDNSNames returns the complete, de-duplicated SAN set for the PDP server certificate.
func (c *Config) CertificateDNSNames() []string {
	if c == nil {
		return nil
	}
	names := make([]string, 0, len(c.TLSDNSNames)+1)
	names = append(names, c.PDPFQDN)
	names = append(names, c.TLSDNSNames...)
	return uniqueTrimmedStrings(names)
}

func uniqueTrimmedStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}
