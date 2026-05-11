package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr string `json:"listen_addr"`
	FQDN       string `json:"fqdn,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`

	TLSCert           string `json:"tls_cert,omitempty"`
	TLSKey            string `json:"tls_key,omitempty"`
	TLSCA             string `json:"tls_ca,omitempty"`
	ClientCA          string `json:"client_ca,omitempty"`
	CloudCA           string `json:"cloud_ca,omitempty"`
	RequireClientCert bool   `json:"require_client_cert"`
	LetsEncrypt       bool   `json:"letsencrypt,omitempty"`
	AutocertCacheDir  string `json:"autocert_cache_dir,omitempty"`
	AutocertHTTPAddr  string `json:"autocert_http_addr,omitempty"`

	MTLSCert string `json:"mtls_cert,omitempty"`
	MTLSKey  string `json:"mtls_key,omitempty"`
	MTLSCSR  string `json:"mtls_csr,omitempty"`

	CloudURL        string              `json:"cloud_url"`
	CloudCertSHA256 string              `json:"cloud_cert_sha256,omitempty"`
	EnrollmentToken string              `json:"enrollment_token,omitempty"`
	ControlPlane    *ControlPlaneConfig `json:"control_plane,omitempty"`

	PKIURL         string `json:"pki_url,omitempty"`
	PKIToken       string `json:"pki_token,omitempty"`
	PKIPath        string `json:"pki_path,omitempty"`
	PKIRoleGateway string `json:"pki_role_gateway,omitempty"`

	DevMode               bool `json:"dev_mode,omitempty"`
	MaxRelayBandwidthMbps int  `json:"max_relay_bandwidth_mbps,omitempty"`
}

type ControlPlaneConfig struct {
	Enabled             bool   `json:"enabled,omitempty"`
	PAURL               string `json:"pa_url,omitempty"`
	GatewayID           string `json:"gateway_id,omitempty"`
	GatewayEndpoint     string `json:"gateway_endpoint,omitempty"`
	ServerName          string `json:"server_name,omitempty"`
	CAFile              string `json:"ca_file,omitempty"`
	CertFile            string `json:"cert_file,omitempty"`
	KeyFile             string `json:"key_file,omitempty"`
	ReconnectMinSeconds int    `json:"reconnect_min_seconds,omitempty"`
	ReconnectMaxSeconds int    `json:"reconnect_max_seconds,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:            ":9443",
		RequireClientCert:     true,
		PKIPath:               "pki_int",
		PKIRoleGateway:        "ztna-gateway",
		AutocertCacheDir:      "certs/autocert",
		AutocertHTTPAddr:      ":80",
		MaxRelayBandwidthMbps: 400,
		ControlPlane: &ControlPlaneConfig{
			Enabled:             true,
			ReconnectMinSeconds: 1,
			ReconnectMaxSeconds: 30,
		},
	}
}

func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("config path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.ApplyEnvOverrides()
	if err := cfg.ResolveSecretRefs(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) SaveToFile(path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWriteFile(path, append(data, '\n'), 0o600)
}

func (cfg *Config) ApplyEnvOverrides() {
	setString(&cfg.ListenAddr, "GATEWAY_LISTEN_ADDR")
	setString(&cfg.FQDN, "GATEWAY_FQDN")
	setString(&cfg.TenantID, "GATEWAY_TENANT_ID")
	setString(&cfg.TLSCert, "GATEWAY_TLS_CERT")
	setString(&cfg.TLSKey, "GATEWAY_TLS_KEY")
	setString(&cfg.TLSCA, "GATEWAY_TLS_CA")
	setString(&cfg.ClientCA, "GATEWAY_CLIENT_CA")
	setString(&cfg.CloudCA, "GATEWAY_CLOUD_CA")
	setString(&cfg.MTLSCert, "GATEWAY_MTLS_CERT")
	setString(&cfg.MTLSKey, "GATEWAY_MTLS_KEY")
	setString(&cfg.MTLSCSR, "GATEWAY_MTLS_CSR")
	setString(&cfg.CloudURL, "CLOUD_URL")
	setString(&cfg.CloudCertSHA256, "CLOUD_CERT_SHA256")
	setString(&cfg.EnrollmentToken, "GATEWAY_ENROLLMENT_TOKEN")
	setString(&cfg.PKIURL, "PKI_URL")
	setString(&cfg.PKIToken, "PKI_TOKEN")
	setString(&cfg.PKIPath, "PKI_PATH")
	setString(&cfg.PKIRoleGateway, "PKI_ROLE_GATEWAY")
	setBool(&cfg.RequireClientCert, "GATEWAY_REQUIRE_CLIENT_CERT")
	setBool(&cfg.LetsEncrypt, "GATEWAY_LETSENCRYPT")
	setBool(&cfg.DevMode, "GATEWAY_DEV_MODE")
	setInt(&cfg.MaxRelayBandwidthMbps, "GATEWAY_MAX_RELAY_BANDWIDTH_MBPS")

	if cfg.ControlPlane == nil {
		cfg.ControlPlane = &ControlPlaneConfig{}
	}
	setBool(&cfg.ControlPlane.Enabled, "GATEWAY_CONTROL_ENABLED")
	setString(&cfg.ControlPlane.PAURL, "GATEWAY_CONTROL_PA_URL")
	setString(&cfg.ControlPlane.GatewayID, "GATEWAY_ID")
	setString(&cfg.ControlPlane.GatewayEndpoint, "GATEWAY_ENDPOINT")
	setString(&cfg.ControlPlane.ServerName, "GATEWAY_CONTROL_SERVER_NAME")
	setString(&cfg.ControlPlane.CAFile, "GATEWAY_CONTROL_CA_FILE")
	setString(&cfg.ControlPlane.CertFile, "GATEWAY_CONTROL_CERT_FILE")
	setString(&cfg.ControlPlane.KeyFile, "GATEWAY_CONTROL_KEY_FILE")
	setInt(&cfg.ControlPlane.ReconnectMinSeconds, "GATEWAY_CONTROL_RECONNECT_MIN_SECONDS")
	setInt(&cfg.ControlPlane.ReconnectMaxSeconds, "GATEWAY_CONTROL_RECONNECT_MAX_SECONDS")
}

func (cfg *Config) ResolveSecretRefs() error {
	secretFields := []*string{&cfg.PKIToken, &cfg.EnrollmentToken}
	for _, field := range secretFields {
		resolved, err := resolveSecretRef(*field)
		if err != nil {
			return err
		}
		*field = resolved
	}
	return nil
}

func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return fmt.Errorf("path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func resolveSecretRef(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "file:") {
		return value, nil
	}
	data, err := os.ReadFile(strings.TrimPrefix(value, "file:"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func setString(target *string, key string) {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		*target = value
	}
}

func setBool(target *bool, key string) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return
	}
	parsed, err := strconv.ParseBool(value)
	if err == nil {
		*target = parsed
	}
}

func setInt(target *int, key string) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return
	}
	parsed, err := strconv.Atoi(value)
	if err == nil {
		*target = parsed
	}
}
