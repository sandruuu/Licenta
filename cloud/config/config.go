package config

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

// Config holds all cloud service configuration
type Config struct {
	// Server settings
	ListenAddr string `json:"listen_addr"` // e.g. ":8443"
	TLSCert    string `json:"tls_cert"`
	TLSKey     string `json:"tls_key"`
	MTLSCA     string `json:"mtls_ca,omitempty"` // CA for verifying mTLS client certs (gateway/device)

	// Vault PKI settings (certificate signing backend)
	PKIURL          string        `json:"pki_url,omitempty"`           // Vault base URL (e.g. "https://vault:8200")
	PKIToken        string        `json:"pki_token,omitempty"`         // Vault token used by cloud for signing/revocation operations
	PKIPath         string        `json:"pki_path,omitempty"`          // Vault PKI mount path (e.g. "pki_int")
	PKIRoleDevice   string        `json:"pki_role_device,omitempty"`   // Vault role for tunnel device certificates
	PKIRoleHealth   string        `json:"pki_role_health,omitempty"`   // Vault role for health device certificates
	PKIRoleGateway  string        `json:"pki_role_gateway,omitempty"`  // Vault role for gateway mTLS certificates
	PKIRoleResource string        `json:"pki_role_resource,omitempty"` // Vault role for backend resource TLS certificates
	PKICAFile       string        `json:"pki_ca_file,omitempty"`       // Optional CA file for Vault server TLS verification
	PKIServerName   string        `json:"pki_server_name,omitempty"`   // Optional SNI/hostname override for Vault TLS
	PKITimeout      time.Duration `json:"pki_timeout,omitempty"`       // HTTP timeout for PKI API calls

	// JWT settings
	JWTSecret      string        `json:"jwt_secret"`
	JWTExpiry      time.Duration `json:"jwt_expiry"`       // token lifetime
	MFATokenExpiry time.Duration `json:"mfa_token_expiry"` // MFA temporary token lifetime

	// TOTP settings
	TOTPIssuer string `json:"totp_issuer"` // issuer name shown in authenticator apps

	// Session settings
	SessionExpiry time.Duration `json:"session_expiry"` // session lifetime
	MaxSessions   int           `json:"max_sessions"`   // max sessions per user

	// Security settings
	MaxLoginAttempts int           `json:"max_login_attempts"` // before lockout
	LockoutDuration  time.Duration `json:"lockout_duration"`   // lockout period

	// Data persistence
	DataDir string `json:"data_dir"` // directory for JSON data files

	// Database settings
	DatabasePath string `json:"database_path"` // SQLite database path (default: <data_dir>/ztna.db)

	// WebAuthn / Passkeys
	WebAuthnRPID      string `json:"webauthn_rp_id"`      // Relying Party ID (domain, e.g. "cloud.lab.local")
	WebAuthnRPName    string `json:"webauthn_rp_name"`    // Display name shown to user (default: "ZTNA Cloud")
	WebAuthnRPOrigins string `json:"webauthn_rp_origins"` // Comma-separated allowed origins (e.g. "https://cloud.lab.local:8443")

	// CORS settings
	CORSOrigins []string `json:"cors_origins,omitempty"` // Additional allowed CORS origins (localhost always allowed)
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:       ":8443",
		JWTSecret:        "",
		JWTExpiry:        1 * time.Hour,
		MFATokenExpiry:   5 * time.Minute,
		PKIPath:          "pki_int",
		PKIRoleDevice:    "ztna-device",
		PKIRoleHealth:    "ztna-device-health",
		PKIRoleGateway:   "ztna-gateway",
		PKIRoleResource:  "ztna-resource",
		PKITimeout:       10 * time.Second,
		TOTPIssuer:       "ZTNA-Cloud",
		SessionExpiry:    8 * time.Hour,
		MaxSessions:      5,
		MaxLoginAttempts: 5,
		LockoutDuration:  15 * time.Minute,
		DataDir:          "./data",
		WebAuthnRPName:   "ZTNA Cloud",
	}
}

// LoadFromFile loads configuration from a JSON file, then applies env var overrides.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.ApplyEnvOverrides()
	return cfg, nil
}

// ApplyEnvOverrides overrides config values with environment variables when set.
// Supported: JWT_SECRET, DATA_DIR, LISTEN_ADDR, TLS_CERT, TLS_KEY
func (c *Config) ApplyEnvOverrides() {
	overrides := map[string]*string{
		"JWT_SECRET":        &c.JWTSecret,
		"DATA_DIR":          &c.DataDir,
		"LISTEN_ADDR":       &c.ListenAddr,
		"TLS_CERT":          &c.TLSCert,
		"TLS_KEY":           &c.TLSKey,
		"MTLS_CA":           &c.MTLSCA,
		"PKI_URL":           &c.PKIURL,
		"PKI_TOKEN":         &c.PKIToken,
		"PKI_PATH":          &c.PKIPath,
		"PKI_ROLE_DEVICE":   &c.PKIRoleDevice,
		"PKI_ROLE_HEALTH":   &c.PKIRoleHealth,
		"PKI_ROLE_GATEWAY":  &c.PKIRoleGateway,
		"PKI_ROLE_RESOURCE": &c.PKIRoleResource,
		"PKI_CA_FILE":       &c.PKICAFile,
		"PKI_SERVER_NAME":   &c.PKIServerName,
		"DATABASE_PATH":     &c.DatabasePath,
		"TOTP_ISSUER":       &c.TOTPIssuer,
	}

	for env, field := range overrides {
		if val := os.Getenv(env); val != "" {
			*field = val
			log.Printf("[CONFIG] Override from env: %s", env)
		}
	}

	if val := os.Getenv("PKI_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err != nil {
			log.Printf("[CONFIG] Invalid PKI_TIMEOUT value %q: %v", val, err)
		} else {
			c.PKITimeout = d
			log.Printf("[CONFIG] Override from env: PKI_TIMEOUT")
		}
	}
}

// SaveToFile saves configuration to a JSON file
func (c *Config) SaveToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
