package config

import (
	"encoding/json"
	"os"
	"time"
)

// RuntimeConfig holds operational knobs that used to live as literals in code.
type RuntimeConfig struct {
	StoreAutoSaveInterval   time.Duration `json:"store_auto_save_interval"`
	SessionCleanupInterval  time.Duration `json:"session_cleanup_interval"`
	CertificateRenewBefore  time.Duration `json:"certificate_renew_before"`
	PKIRenewCheckInterval   time.Duration `json:"pki_renew_check_interval"`
	HTTPReadTimeout         time.Duration `json:"http_read_timeout"`
	HTTPReadHeaderTimeout   time.Duration `json:"http_read_header_timeout"`
	HTTPWriteTimeout        time.Duration `json:"http_write_timeout"`
	HTTPIdleTimeout         time.Duration `json:"http_idle_timeout"`
	EventBufferSize         int           `json:"event_buffer_size"`
	CatalogTTLSeconds       int           `json:"catalog_ttl_seconds"`
	AuthRateLimitWindow     time.Duration `json:"auth_rate_limit_window"`
	AuthRateLimitMax        int           `json:"auth_rate_limit_max"`
	OIDCAuthorizeSessionTTL time.Duration `json:"oidc_authorize_session_ttl"`
	OIDCAuthCodeTTL         time.Duration `json:"oidc_auth_code_ttl"`
	OIDCRefreshTokenTTL     time.Duration `json:"oidc_refresh_token_ttl"`
	OIDCCleanupInterval     time.Duration `json:"oidc_cleanup_interval"`
	OIDCEnrollmentTokenTTL  time.Duration `json:"oidc_enrollment_token_ttl"`
	WebAuthnChallengeTTL    time.Duration `json:"webauthn_challenge_ttl"`
	WebAuthnCleanupInterval time.Duration `json:"webauthn_cleanup_interval"`
	FederationCacheTTL      time.Duration `json:"federation_cache_ttl"`
	FederationHTTPTimeout   time.Duration `json:"federation_http_timeout"`
	BrowserAuthSessionTTL   time.Duration `json:"browser_auth_session_ttl"`
	CSRFCookieMaxAgeSeconds int           `json:"csrf_cookie_max_age_seconds"`
	EnrollRateLimitWindow   time.Duration `json:"enroll_rate_limit_window"`
	EnrollRateLimitMax      int           `json:"enroll_rate_limit_max"`
	GatewayRevokeTimeout    time.Duration `json:"gateway_revoke_timeout"`
}

// BootstrapAdminConfig controls optional first-admin creation.
type BootstrapAdminConfig struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// PublicDashboardConfig is safe to expose to the React dashboard.
type PublicDashboardConfig struct {
	DeviceHealthAgentURL    string            `json:"device_health_agent_url"`
	DeviceHealthTimeoutMS   int               `json:"device_health_timeout_ms"`
	DeviceHealthRetryMS     int               `json:"device_health_retry_ms"`
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

// RiskConfig controls the numeric risk-score model used by PE.
type RiskConfig struct {
	PostureCriticalAfter        time.Duration  `json:"posture_critical_after"`
	PostureStaleAfter           time.Duration  `json:"posture_stale_after"`
	PostureCriticalPoints       int            `json:"posture_critical_points"`
	PostureStalePoints          int            `json:"posture_stale_points"`
	NoDeviceHealthPoints        int            `json:"no_device_health_points"`
	HealthExcellentMin          int            `json:"health_excellent_min"`
	HealthGoodMin               int            `json:"health_good_min"`
	HealthFairMin               int            `json:"health_fair_min"`
	HealthGoodPoints            int            `json:"health_good_points"`
	HealthFairPoints            int            `json:"health_fair_points"`
	HealthPoorPoints            int            `json:"health_poor_points"`
	CriticalCheckPoints         map[string]int `json:"critical_check_points"`
	FailedAttemptsHigh          int            `json:"failed_attempts_high"`
	FailedAttemptsMedium        int            `json:"failed_attempts_medium"`
	FailedAttemptsLow           int            `json:"failed_attempts_low"`
	FailedAttemptsHighPoints    int            `json:"failed_attempts_high_points"`
	FailedAttemptsMediumPoints  int            `json:"failed_attempts_medium_points"`
	FailedAttemptsLowPoints     int            `json:"failed_attempts_low_points"`
	BusinessHoursStart          int            `json:"business_hours_start"`
	BusinessHoursEnd            int            `json:"business_hours_end"`
	BusinessDays                []string       `json:"business_days"`
	OutsideBusinessPoints       int            `json:"outside_business_points"`
	NightHoursStart             int            `json:"night_hours_start"`
	NightHoursEnd               int            `json:"night_hours_end"`
	NightHoursPoints            int            `json:"night_hours_points"`
	NewDevicePoints             int            `json:"new_device_points"`
	NewLocationPoints           int            `json:"new_location_points"`
	ProtocolPoints              map[string]int `json:"protocol_points"`
	UnknownProtocolPoints       int            `json:"unknown_protocol_points"`
	ImpossibleTravelPoints      int            `json:"impossible_travel_points"`
	SuspiciousGeoVelocityKMH    float64        `json:"suspicious_geo_velocity_kmh"`
	SuspiciousGeoVelocityPoints int            `json:"suspicious_geo_velocity_points"`
	MaxAnomalyPoints            int            `json:"max_anomaly_points"`
	MaxScore                    int            `json:"max_score"`
}

// Config holds all PDP service configuration
type Config struct {
	// Server settings
	ListenAddr string `json:"listen_addr"` // e.g. ":8443"
	PDPFQDN    string `json:"pdp_fqdn"`    // FQDN for self-enrollment CSR (e.g. "pdp")
	TLSCert    string `json:"tls_cert"`    // Path where the PDP TLS certificate is stored
	MTLSCA     string `json:"mtls_ca"`     // Path where the issuer CA certificate is stored

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
	JWTExpiry           time.Duration `json:"jwt_expiry"`             // token lifetime
	MFATokenExpiry      time.Duration `json:"mfa_token_expiry"`       // MFA temporary token lifetime
	JWTTransitKey       string        `json:"jwt_transit_key"`        // Vault Transit key used for JWT signing key encryption
	JWTKeyEncryptedPath string        `json:"jwt_key_encrypted_path"` // Vault Transit encrypted JWT signing key path

	// TOTP settings
	TOTPIssuer string `json:"totp_issuer"` // issuer name shown in authenticator apps

	// Session settings
	SessionExpiry time.Duration `json:"session_expiry"` // session lifetime
	MaxSessions   int           `json:"max_sessions"`   // max sessions per user

	// Security settings
	MaxLoginAttempts int           `json:"max_login_attempts"` // before lockout
	LockoutDuration  time.Duration `json:"lockout_duration"`   // lockout period

	// Data persistence
	DataDir string `json:"data_dir"` // directory for data files and Vault Transit encrypted key

	// Database settings
	DatabasePath        string `json:"database_path"`          // SQLite database path
	PDPKeyEncryptedPath string `json:"pdp_key_encrypted_path"` // Vault Transit encrypted PDP key path

	WebAuthnRPID      string `json:"webauthn_rp_id"`      // Relying Party ID (domain, e.g. "pdp.lab.local")
	WebAuthnRPName    string `json:"webauthn_rp_name"`    // Display name shown to user
	WebAuthnRPOrigins string `json:"webauthn_rp_origins"` // Comma-separated allowed origins (e.g. "https://pdp.lab.local:8443")

	// CORS settings
	CORSOrigins []string `json:"cors_origins"` // Additional allowed CORS origins (localhost always allowed)

	Runtime        RuntimeConfig         `json:"runtime"`
	BootstrapAdmin BootstrapAdminConfig  `json:"bootstrap_admin"`
	Public         PublicDashboardConfig `json:"public"`
	Gateway        GatewayConfig         `json:"gateway"`
	Enrollment     EnrollmentConfig      `json:"enrollment"`
	Geo            GeoConfig             `json:"geo"`
	Risk           RiskConfig            `json:"risk"`
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
	return &cfg, nil
}

// PublicConfig returns the subset of configuration safe for browser clients.
func (c *Config) PublicConfig() PublicDashboardConfig {
	return c.Public
}

// ApplyDefaults fills defensive fallback values for programmatic tests and
// older config files. Runtime deployments should keep these values explicit in
// config.json.
func (c *Config) ApplyDefaults() {
	if c == nil {
		return
	}
	if c.Runtime.EventBufferSize <= 0 {
		c.Runtime.EventBufferSize = 64
	}
	if c.Runtime.CatalogTTLSeconds <= 0 {
		c.Runtime.CatalogTTLSeconds = 300
	}
	if c.Runtime.PKIRenewCheckInterval <= 0 {
		c.Runtime.PKIRenewCheckInterval = 6 * time.Hour
	}
	if c.Runtime.OIDCEnrollmentTokenTTL <= 0 {
		c.Runtime.OIDCEnrollmentTokenTTL = 5 * time.Minute
	}
	if c.Runtime.WebAuthnChallengeTTL <= 0 {
		c.Runtime.WebAuthnChallengeTTL = 5 * time.Minute
	}
	if c.Runtime.WebAuthnCleanupInterval <= 0 {
		c.Runtime.WebAuthnCleanupInterval = 2 * time.Minute
	}
	if c.Runtime.FederationCacheTTL <= 0 {
		c.Runtime.FederationCacheTTL = 6 * time.Hour
	}
	if c.Runtime.FederationHTTPTimeout <= 0 {
		c.Runtime.FederationHTTPTimeout = 10 * time.Second
	}
	if c.Runtime.BrowserAuthSessionTTL <= 0 {
		c.Runtime.BrowserAuthSessionTTL = 5 * time.Minute
	}
	if c.Runtime.CSRFCookieMaxAgeSeconds <= 0 {
		c.Runtime.CSRFCookieMaxAgeSeconds = 3600
	}
	if c.Runtime.EnrollRateLimitWindow <= 0 {
		c.Runtime.EnrollRateLimitWindow = time.Minute
	}
	if c.Runtime.EnrollRateLimitMax <= 0 {
		c.Runtime.EnrollRateLimitMax = 5
	}
	if c.Runtime.GatewayRevokeTimeout <= 0 {
		c.Runtime.GatewayRevokeTimeout = 5 * time.Second
	}
	if c.Gateway.CertificateValidityDays <= 0 {
		c.Gateway.CertificateValidityDays = 7
	}
	if c.Gateway.EnrollmentTokenTTL <= 0 {
		c.Gateway.EnrollmentTokenTTL = time.Hour
	}
	if c.Enrollment.CertificateValidityDays <= 0 {
		c.Enrollment.CertificateValidityDays = 1
	}
	if c.Enrollment.BrowserSessionTTL <= 0 {
		c.Enrollment.BrowserSessionTTL = 5 * time.Minute
	}
	if c.Geo.ProviderURL == "" {
		c.Geo.ProviderURL = "https://ipapi.co/{ip}/json/"
	}
	if c.Geo.HTTPTimeout <= 0 {
		c.Geo.HTTPTimeout = 3 * time.Second
	}
	if c.Geo.CacheTTL <= 0 {
		c.Geo.CacheTTL = time.Hour
	}
	if c.Geo.CacheMaxEntries <= 0 {
		c.Geo.CacheMaxEntries = 10000
	}
	if c.Geo.SameAreaDistanceKM <= 0 {
		c.Geo.SameAreaDistanceKM = 50
	}
	if c.Geo.SuspiciousTravelSpeedKMH <= 0 {
		c.Geo.SuspiciousTravelSpeedKMH = 500
	}
	if c.Geo.ImpossibleTravelSpeedKMH <= 0 {
		c.Geo.ImpossibleTravelSpeedKMH = 900
	}
	if c.Risk.PostureCriticalAfter <= 0 {
		c.Risk.PostureCriticalAfter = 30 * time.Minute
	}
	if c.Risk.PostureStaleAfter <= 0 {
		c.Risk.PostureStaleAfter = 10 * time.Minute
	}
	if c.Risk.PostureCriticalPoints <= 0 {
		c.Risk.PostureCriticalPoints = 30
	}
	if c.Risk.PostureStalePoints <= 0 {
		c.Risk.PostureStalePoints = 15
	}
	if c.Risk.NoDeviceHealthPoints <= 0 {
		c.Risk.NoDeviceHealthPoints = 25
	}
	if c.Risk.HealthExcellentMin <= 0 {
		c.Risk.HealthExcellentMin = 80
	}
	if c.Risk.HealthGoodMin <= 0 {
		c.Risk.HealthGoodMin = 60
	}
	if c.Risk.HealthFairMin <= 0 {
		c.Risk.HealthFairMin = 40
	}
	if c.Risk.HealthGoodPoints <= 0 {
		c.Risk.HealthGoodPoints = 10
	}
	if c.Risk.HealthFairPoints <= 0 {
		c.Risk.HealthFairPoints = 20
	}
	if c.Risk.HealthPoorPoints <= 0 {
		c.Risk.HealthPoorPoints = 35
	}
	if len(c.Risk.CriticalCheckPoints) == 0 {
		c.Risk.CriticalCheckPoints = map[string]int{
			"Firewall":        5,
			"Antivirus":       5,
			"Disk Encryption": 3,
			"Password & Lock": 2,
		}
	}
	if c.Risk.FailedAttemptsHigh <= 0 {
		c.Risk.FailedAttemptsHigh = 5
	}
	if c.Risk.FailedAttemptsMedium <= 0 {
		c.Risk.FailedAttemptsMedium = 3
	}
	if c.Risk.FailedAttemptsLow <= 0 {
		c.Risk.FailedAttemptsLow = 1
	}
	if c.Risk.FailedAttemptsHighPoints <= 0 {
		c.Risk.FailedAttemptsHighPoints = 20
	}
	if c.Risk.FailedAttemptsMediumPoints <= 0 {
		c.Risk.FailedAttemptsMediumPoints = 10
	}
	if c.Risk.FailedAttemptsLowPoints <= 0 {
		c.Risk.FailedAttemptsLowPoints = 5
	}
	if c.Risk.BusinessHoursEnd <= c.Risk.BusinessHoursStart {
		c.Risk.BusinessHoursStart = 8
		c.Risk.BusinessHoursEnd = 18
	}
	if len(c.Risk.BusinessDays) == 0 {
		c.Risk.BusinessDays = []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
	}
	if c.Risk.OutsideBusinessPoints <= 0 {
		c.Risk.OutsideBusinessPoints = 10
	}
	if c.Risk.NightHoursEnd <= c.Risk.NightHoursStart {
		c.Risk.NightHoursStart = 0
		c.Risk.NightHoursEnd = 6
	}
	if c.Risk.NightHoursPoints <= 0 {
		c.Risk.NightHoursPoints = 5
	}
	if c.Risk.NewDevicePoints <= 0 {
		c.Risk.NewDevicePoints = 10
	}
	if c.Risk.NewLocationPoints <= 0 {
		c.Risk.NewLocationPoints = 5
	}
	if len(c.Risk.ProtocolPoints) == 0 {
		c.Risk.ProtocolPoints = map[string]int{
			"rdp":   10,
			"ssh":   5,
			"http":  0,
			"https": 0,
		}
	}
	if c.Risk.UnknownProtocolPoints <= 0 {
		c.Risk.UnknownProtocolPoints = 5
	}
	if c.Risk.ImpossibleTravelPoints <= 0 {
		c.Risk.ImpossibleTravelPoints = 30
	}
	if c.Risk.SuspiciousGeoVelocityKMH <= 0 {
		c.Risk.SuspiciousGeoVelocityKMH = 500
	}
	if c.Risk.SuspiciousGeoVelocityPoints <= 0 {
		c.Risk.SuspiciousGeoVelocityPoints = 15
	}
	if c.Risk.MaxAnomalyPoints <= 0 {
		c.Risk.MaxAnomalyPoints = 25
	}
	if c.Risk.MaxScore <= 0 {
		c.Risk.MaxScore = 100
	}
}
