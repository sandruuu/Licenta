package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) {
	t.Helper()
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, configFilename)
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	originalExecutablePath := executablePath
	executablePath = func() (string, error) {
		return filepath.Join(configDir, "ztna-agent.exe"), nil
	}
	t.Cleanup(func() {
		executablePath = originalExecutablePath
	})
}

func serviceConfigJSON(extra string) string {
	if strings.TrimSpace(extra) != "" {
		extra = ",\n" + strings.TrimSpace(extra)
	}
	return `{
  "pa_url": "https://pa.example:8443",
  "dns_server": "127.0.0.1",
  "posture_interval": "5m",
  "critical_interval": "1m",
  "heartbeat_interval": "1m",
  "posture_report_timeout": "30s",
  "catalog_interval": "2m",
  "catalog_cache_ttl": "5m",
  "catalog_retry_backoff": ["5m", "10m", "15m", "30m"],
  "access_token_expiry_skew": "30s",
  "certificate_renewal_interval": "1h",
  "certificate_renew_before": "12h",
  "certificate_renewal_timeout": "30s",
  "pa_request_timeout": "10s",
  "enrollment_rate_limit_max": 3,
  "enrollment_rate_limit_window": "1m",
  "tray_timeout": "10s",
  "tray_enrollment_timeout": "10m",
  "token_refresh_interval": "1m",
  "token_refresh_margin": "5m",
  "dashboard_refresh_interval": "30s",
  "install_timeout": "30s",
  "service_recovery_restart_delays": ["10s", "30s", "1m"]` + extra + `
}`
}

func TestLoadServiceConfigLoadsPAURLConfig(t *testing.T) {
	writeConfig(t, serviceConfigJSON(""))

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.PAURL != "https://pa.example:8443" {
		t.Fatalf("service config = %+v", config)
	}
}

func TestLoadTrayConfigLoadsPAURLConfig(t *testing.T) {
	writeConfig(t, `{
  "pa_url":"https://pa.example:8443",
  "tray_timeout":"10s",
  "tray_enrollment_timeout": "10m",
  "token_refresh_interval": "1m",
  "token_refresh_margin": "5m",
  "dashboard_refresh_interval": "30s"
}`)

	config, err := LoadTrayConfig()
	if err != nil {
		t.Fatalf("LoadTrayConfig returned error: %v", err)
	}
	if config.PAURL != "https://pa.example:8443" || config.IssuerURL != "https://pa.example:8443" || config.Timeout != 10*time.Second {
		t.Fatalf("tray config = %+v", config)
	}
}

func TestLoadTrayConfigUsesIssuerURL(t *testing.T) {
	writeConfig(t, serviceConfigJSON(`"issuer_url": "https://issuer.example"`))

	trayConfig, err := LoadTrayConfig()
	if err != nil {
		t.Fatalf("LoadTrayConfig returned error: %v", err)
	}
	if trayConfig.IssuerURL != "https://issuer.example" {
		t.Fatalf("tray config = %+v", trayConfig)
	}
}

func TestLoadServiceConfigLoadsServiceConfig(t *testing.T) {
	writeConfig(t, serviceConfigJSON(`"authorized_user_sid": "S-1-5-21-1",
  "tun": true,
  "tun_name": "ZTNA-TUN",
  "tun_ip": "100.64.0.1",
  "tun_netmask": "255.192.0.0",
  "tun_route_cidr": "100.64.0.0/10",
  "process_identity": true`))

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.AuthorizedUserSID != "S-1-5-21-1" || config.PAURL != "https://pa.example:8443" || config.DNSServer != "127.0.0.1" || config.CatalogInterval != 2*time.Minute || !config.TUNEnabled || config.TUNName != "ZTNA-TUN" || !config.ProcessIdentity {
		t.Fatalf("service config = %+v", config)
	}
}

func TestLoadTrayConfigLoadsSharedConfig(t *testing.T) {
	writeConfig(t, `{
  "authorized_user_sid": "S-1-5-21-1",
  "pa_url": "https://pa.example:8443",
  "tray_timeout": "10s",
  "tray_enrollment_timeout": "10m",
  "token_refresh_interval": "1m",
  "token_refresh_margin": "5m",
  "dashboard_refresh_interval": "30s"
}`)

	config, err := LoadTrayConfig()
	if err != nil {
		t.Fatalf("LoadTrayConfig returned error: %v", err)
	}
	if config.LocalSID != "S-1-5-21-1" || config.PAURL != "https://pa.example:8443" {
		t.Fatalf("tray config = %+v", config)
	}
}

func TestLoadServiceConfigIgnoresTrayIssuerURL(t *testing.T) {
	writeConfig(t, `{
  "pa_url": "https://pa.example:8443",
  "dns_server": "127.0.0.1",
  "posture_interval": "5m",
  "critical_interval": "1m",
  "heartbeat_interval": "1m",
  "catalog_interval": "2m",
  "certificate_renewal_interval": "1h",
  "certificate_renew_before": "12h",
  "certificate_renewal_timeout": "30s",
  "pa_request_timeout": "10s",
  "posture_report_timeout": "30s",
  "catalog_cache_ttl": "5m",
  "catalog_retry_backoff": ["5m", "10m", "15m", "30m"],
  "access_token_expiry_skew": "30s",
  "enrollment_rate_limit_max": 3,
  "enrollment_rate_limit_window": "1m",
  "issuer_url": "://invalid"
}`)

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.PAURL != "https://pa.example:8443" {
		t.Fatalf("service config = %+v", config)
	}
}

func TestLoadTrayConfigValidatesIssuerURL(t *testing.T) {
	writeConfig(t, `{
  "pa_url": "https://pa.example:8443",
  "tray_timeout": "10s",
  "tray_enrollment_timeout": "10m",
  "token_refresh_interval": "1m",
  "token_refresh_margin": "5m",
  "dashboard_refresh_interval": "30s",
  "issuer_url": "://invalid"
}`)

	if _, err := LoadTrayConfig(); err == nil {
		t.Fatal("LoadTrayConfig returned nil error")
	}
}

func TestLoadServiceConfigRequiresServiceRuntimeConfig(t *testing.T) {
	writeConfig(t, `{"pa_url":"https://pa.example:8443"}`)

	if _, err := LoadServiceConfig(); err == nil {
		t.Fatal("LoadServiceConfig returned nil error")
	}
}
