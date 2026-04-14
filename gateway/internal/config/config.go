package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all gateway (PEP) configuration
type Config struct {
	// Server settings
	ListenAddr string `json:"listen_addr"`    // TLS listener for connect-app connections
	FQDN       string `json:"fqdn,omitempty"` // public FQDN, e.g. "gateway.company.com"

	// TLS settings — public SSL cert for user-facing HTTPS (port 443)
	TLSCert           string `json:"tls_cert"`
	TLSKey            string `json:"tls_key"`
	TLSCA             string `json:"tls_ca"`                // CA for client certificate validation (optional)
	ClientCA          string `json:"client_ca,omitempty"`   // CA for connect-app client certs (optional)
	CloudCA           string `json:"cloud_ca,omitempty"`    // CA for validating cloud server certs (optional)
	RequireClientCert bool   `json:"require_client_cert"`   // require client certs on the portal listener
	LetsEncrypt       bool   `json:"letsencrypt,omitempty"` // use Let's Encrypt for auto-cert

	// mTLS settings — mutual TLS for Gateway↔Cloud authentication
	MTLSCert string `json:"mtls_cert,omitempty"` // signed client cert from cloud CA
	MTLSKey  string `json:"mtls_key,omitempty"`  // private key for mTLS
	MTLSCSR  string `json:"mtls_csr,omitempty"`  // pending CSR (before cloud signs it)

	// Cloud service (PA + PE + IdP) connection
	CloudURL        string `json:"cloud_url"`                   // e.g. "https://localhost:8443"
	CloudCertSHA256 string `json:"cloud_cert_sha256,omitempty"` // SHA-256 fingerprint of cloud TLS cert for pinning
	EnrollmentToken string `json:"enrollment_token,omitempty"`  // one-time token for cloud enrollment (cleared after enrollment)

	// Primary Authentication Source (IdP / OIDC)
	AuthSource *AuthSourceConfig `json:"auth_source,omitempty"`

	// CGNAT address pool (100.64.0.0/10) for TUN interface
	CGNAT *CGNATConfig `json:"cgnat,omitempty"`

	// DNS settings for internal resolution
	InternalDNS string `json:"internal_dns"` // upstream DNS for internal resources

	// Resource definitions — each maps a CGNAT tunnel IP to a real internal IP
	Resources []Resource `json:"resources"`

	// Session settings
	SessionTimeout int `json:"session_timeout"` // seconds

	// First-boot setup
	Setup *SetupConfig `json:"setup,omitempty"`

	// DevMode allows running without TLS for local development.
	// When false (default), the admin server refuses to start without TLS certs.
	DevMode bool `json:"dev_mode,omitempty"`
}

// AuthSourceConfig defines the primary authentication source (IdP via OIDC)
// When a user arrives at the portal without a valid session, the portal
// redirects (HTTP 302) to AuthURL for authentication.
type AuthSourceConfig struct {
	Hostname           string `json:"hostname"`             // e.g. "login.ztna.company.com"
	AuthURL            string `json:"auth_url"`             // OIDC authorization endpoint
	TokenURL           string `json:"token_url"`            // OIDC token endpoint
	UserInfoURL        string `json:"userinfo_url"`         // OIDC userinfo endpoint
	ClientID           string `json:"client_id"`            // OIDC client ID
	ClientSecret       string `json:"client_secret"`        // OIDC client secret
	RedirectURI        string `json:"redirect_uri"`         // callback URI on the gateway
	Scopes             string `json:"scopes"`               // e.g. "openid profile email"
	CallbackListenAddr string `json:"callback_listen_addr"` // HTTP(S) listen address for callback (default ":443")
}

// CGNATConfig defines the Carrier-Grade NAT address pool (100.64.0.0/10)
// used for TUN interface addresses to avoid collisions with user LANs.
type CGNATConfig struct {
	Enabled    bool   `json:"enabled"`
	PoolStart  string `json:"pool_start"`  // e.g. "100.64.0.1"
	PoolEnd    string `json:"pool_end"`    // e.g. "100.127.255.254"
	SubnetMask string `json:"subnet_mask"` // e.g. "255.192.0.0" (/10)
}

// SetupConfig stores the first-boot local admin account
// This is a LOCAL account only for the admin console — NOT an IdP user.
type SetupConfig struct {
	Completed           bool   `json:"completed"`
	AdminEmail          string `json:"admin_email"`
	AdminPassHash       string `json:"admin_pass_hash"` // bcrypt hash
	SetupDate           string `json:"setup_date,omitempty"`
	SetupToken          string `json:"setup_token,omitempty"`            // one-time token for securing the setup wizard
	SetupTokenCreatedAt string `json:"setup_token_created_at,omitempty"` // RFC3339 timestamp for token expiration
}

// Resource defines an internal resource accessible through the gateway.
// TunnelIP is the CGNAT address (100.64.x.x) that connect-app uses to reach this resource.
// The portal maps TunnelIP → InternalIP transparently.
type Resource struct {
	Name        string `json:"name"`         // human-readable name
	Type        string `json:"type"`         // "web", "ssh", "rdp"
	InternalIP  string `json:"internal_ip"`  // real IP behind gateway (legacy / web backend)
	TunnelIP    string `json:"tunnel_ip"`    // CGNAT address (100.64.x.x) for TUN routing
	Port        int    `json:"port"`         // target port (legacy)
	Protocol    string `json:"protocol"`     // "rdp", "ssh", "https", "tcp"
	MFARequired bool   `json:"mfa_required"` // override: always require MFA
	Enabled     bool   `json:"enabled"`      // active/disabled toggle (default true)

	// Cloud link (Duo-style per-app credentials)
	CloudAppID    string `json:"cloud_app_id,omitempty"`    // resource ID from cloud
	CloudClientID string `json:"cloud_client_id,omitempty"` // per-app ClientID
	CloudSecret   string `json:"cloud_secret,omitempty"`    // per-app ClientSecret
	Description   string `json:"description,omitempty"`     // from cloud

	// Extended fields (DNG-style)
	ExternalURL     string         `json:"external_url,omitempty"`     // public URL users access
	InternalURL     string         `json:"internal_url,omitempty"`     // backend URL (web apps)
	InternalHosts   []InternalHost `json:"internal_hosts,omitempty"`   // host list (SSH/RDP)
	SessionDuration int            `json:"session_duration,omitempty"` // minutes (default 480)
	CertSource      string         `json:"cert_source,omitempty"`      // "upload", "letsencrypt", "gateway"
	CertPEM         string         `json:"cert_pem,omitempty"`         // uploaded cert PEM
	KeyPEM          string         `json:"key_pem,omitempty"`          // uploaded key PEM
	PassHeaders     bool           `json:"pass_headers,omitempty"`     // forward auth headers (web)
	CreatedAt       string         `json:"created_at,omitempty"`
}

// InternalHost defines a backend host for SSH/RDP applications
type InternalHost struct {
	Host  string `json:"host"`  // hostname, IP, CIDR, or wildcard
	Ports string `json:"ports"` // e.g. "22", "22,2222", "4000-5000"
}

// DefaultConfig returns a configuration with sensible defaults.
// AuthSource is nil by default — it is populated automatically by DeriveAuthEndpoints()
// from CloudURL and FQDN after config is loaded, or set during enrollment/setup wizard.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:  ":9443",
		InternalDNS: "",
		CGNAT: &CGNATConfig{
			Enabled:    true,
			PoolStart:  "100.64.0.2",
			PoolEnd:    "100.127.255.254",
			SubnetMask: "255.192.0.0",
		},
		Resources:      []Resource{},
		SessionTimeout: 28800, // 8 hours
	}
}

// LoadFromFile loads configuration from a JSON file, then applies env var overrides,
// and finally derives any missing OIDC endpoints from CloudURL and FQDN.
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
	cfg.DeriveAuthEndpoints()
	return cfg, nil
}

// DeriveAuthEndpoints auto-populates empty AuthSource fields from CloudURL and FQDN.
// It only fills in fields that are not already set, so explicit config values are preserved.
// Called after LoadFromFile and whenever CloudURL or FQDN changes at runtime.
func (c *Config) DeriveAuthEndpoints() {
	if c.CloudURL == "" {
		return // nothing to derive from
	}

	if c.AuthSource == nil {
		c.AuthSource = &AuthSourceConfig{}
	}
	as := c.AuthSource

	base := strings.TrimRight(c.CloudURL, "/")

	if as.Hostname == "" {
		if parsed, err := url.Parse(c.CloudURL); err == nil {
			as.Hostname = parsed.Host
		}
	}
	if as.AuthURL == "" {
		as.AuthURL = base + "/auth/authorize"
	}
	if as.TokenURL == "" {
		as.TokenURL = base + "/auth/token"
	}
	if as.UserInfoURL == "" {
		as.UserInfoURL = base + "/auth/userinfo"
	}
	if as.RedirectURI == "" && c.FQDN != "" {
		as.RedirectURI = "https://" + c.FQDN + "/auth/callback"
	}
	if as.Scopes == "" {
		as.Scopes = "openid profile email"
	}
	if as.CallbackListenAddr == "" {
		as.CallbackListenAddr = ":443"
	}
}

// ApplyEnvOverrides overrides config values with environment variables when set.
// Supported: CLOUD_URL, LISTEN_ADDR, INTERNAL_DNS
func (c *Config) ApplyEnvOverrides() {
	overrides := map[string]*string{
		"CLOUD_URL":    &c.CloudURL,
		"LISTEN_ADDR":  &c.ListenAddr,
		"INTERNAL_DNS": &c.InternalDNS,
		"TLS_CERT":     &c.TLSCert,
		"TLS_KEY":      &c.TLSKey,
		"TLS_CA":       &c.TLSCA,
		"CLIENT_CA":    &c.ClientCA,
		"CLOUD_CA":     &c.CloudCA,
		"MTLS_CERT":    &c.MTLSCert,
		"MTLS_KEY":     &c.MTLSKey,
	}

	for env, field := range overrides {
		if val := os.Getenv(env); val != "" {
			*field = val
			log.Printf("[CONFIG] Override from env: %s", env)
		}
	}

	if val := os.Getenv("REQUIRE_CLIENT_CERT"); val != "" {
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			log.Printf("[CONFIG] Invalid REQUIRE_CLIENT_CERT value: %s", val)
		} else {
			c.RequireClientCert = parsed
			log.Printf("[CONFIG] Override from env: REQUIRE_CLIENT_CERT")
		}
	}
}

// AtomicWriteFile writes data to a file atomically: write temp → fsync → rename.
// Prevents corruption if a crash occurs mid-write (e.g. during cert renewal).
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

// SaveToFile saves configuration to a JSON file atomically (write temp → fsync → rename).
func (c *Config) SaveToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

// IsSetupComplete checks if the first-boot setup wizard has been completed.
// Uses state-based detection: setup is complete only when an admin account
// actually exists (email + password hash), not just the boolean flag.
func (c *Config) IsSetupComplete() bool {
	return c.Setup != nil && c.Setup.Completed &&
		c.Setup.AdminEmail != "" && c.Setup.AdminPassHash != ""
}

// GenerateSetupToken creates a cryptographically random 32-character hex token
// used to secure the setup wizard. The token is printed in container logs at
// first boot and must be entered in the wizard UI to proceed.
func (c *Config) GenerateSetupToken() string {
	if c.Setup == nil {
		c.Setup = &SetupConfig{}
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Printf("[CONFIG] WARNING: failed to generate random setup token: %v", err)
		return ""
	}
	c.Setup.SetupToken = hex.EncodeToString(b)
	c.Setup.SetupTokenCreatedAt = time.Now().Format(time.RFC3339)
	return c.Setup.SetupToken
}

// insecureAPIKeys is a set of known placeholder/example API key values
// that must never be used in production.
var insecureAPIKeys = map[string]bool{
	"gateway-shared-secret-change-me":                true,
	"ztna-gateway-api-key-change-in-production-2024": true,
	"CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32":    true,
	"change-me":   true,
	"changeme":    true,
	"placeholder": true,
}

// ValidateSecrets checks that no placeholder or weak secrets are configured.
// Returns a list of warnings. In production mode any warning is fatal.
func (c *Config) ValidateSecrets() []string {
	var warnings []string

	if c.AuthSource != nil && c.AuthSource.ClientSecret != "" {
		if insecureAPIKeys[c.AuthSource.ClientSecret] {
			warnings = append(warnings, "auth_source.client_secret contains a known placeholder value")
		}
	}

	return warnings
}

// ValidatePasswordStrength checks that a password meets complexity requirements:
// minimum 8 characters, at least one uppercase, one lowercase, one digit, one special character.
func ValidatePasswordStrength(password string) string {
	if len(password) < 8 {
		return "Password must be at least 8 characters"
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if !hasUpper {
		return "Password must contain at least one uppercase letter"
	}
	if !hasLower {
		return "Password must contain at least one lowercase letter"
	}
	if !hasDigit {
		return "Password must contain at least one digit"
	}
	if !hasSpecial {
		return "Password must contain at least one special character"
	}
	return ""
}

// IsSetupTokenExpired returns true if the setup token was created more than 30 minutes ago.
func (c *Config) IsSetupTokenExpired() bool {
	if c.Setup == nil || c.Setup.SetupTokenCreatedAt == "" {
		return false // no timestamp means legacy token, allow it
	}
	created, err := time.Parse(time.RFC3339, c.Setup.SetupTokenCreatedAt)
	if err != nil {
		return false
	}
	return time.Since(created) > 30*time.Minute
}
