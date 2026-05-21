package app

import (
	"os"
	"path/filepath"
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
		return filepath.Join(configDir, "trust-agent.exe"), nil
	}
	t.Cleanup(func() {
		executablePath = originalExecutablePath
	})
}

func serviceConfigJSON() string {
	return `{
  "pdp_grpc_endpoint": "pdp.example.com:443",
  "pdp_tls_server_name": "pdp.example.com",
  "pdp_ca_file": "ca.pem",
  "enrollment_timeout": "10m",
  "enrollment_poll_interval": "3s",
  "tray_timeout": "10s",
  "dashboard_refresh_interval": "30s"
}`
}

func TestLoadServiceConfigLoadsServiceConfig(t *testing.T) {
	writeConfig(t, serviceConfigJSON())

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.PDPGRPCEndpoint != "pdp.example.com:443" || config.PDPTLSServerName != "pdp.example.com" || config.PDPCAFile != "ca.pem" || config.EnrollmentTimeout != 10*time.Minute || config.EnrollmentPollInterval != 3*time.Second {
		t.Fatalf("service config = %+v", config)
	}
}

func TestLoadTrayConfigLoadsTrayConfig(t *testing.T) {
	writeConfig(t, `{
  "tray_timeout":"10s",
  "dashboard_refresh_interval": "30s"
}`)

	config, err := LoadTrayConfig()
	if err != nil {
		t.Fatalf("LoadTrayConfig returned error: %v", err)
	}
	if config.Timeout != 10*time.Second || config.DashboardRefreshInterval != 30*time.Second {
		t.Fatalf("tray config = %+v", config)
	}
}

func TestLoadTrayConfigLoadsSharedConfig(t *testing.T) {
	writeConfig(t, `{
  "tray_timeout": "10s",
  "dashboard_refresh_interval": "30s"
}`)

	config, err := LoadTrayConfig()
	if err != nil {
		t.Fatalf("LoadTrayConfig returned error: %v", err)
	}
	if config.Timeout != 10*time.Second || config.DashboardRefreshInterval != 30*time.Second {
		t.Fatalf("tray config = %+v", config)
	}
}

func TestLoadServiceConfigAllowsMinimalServiceConfig(t *testing.T) {
	writeConfig(t, `{}`)

	if _, err := LoadServiceConfig(); err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
}
