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
  "device_data_sync_interval": "30m",
  "device_data_sync_change_scan_interval": "30s",
  "local_dns_listen_address": "127.0.0.1:53",
  "local_dns_server": "127.0.0.1",
  "synthetic_ip_cidr": "100.64.0.0/10",
  "harden_browser_doh": true,
  "traffic_interception_enabled": true,
  "traffic_proxy_listen_address": "127.0.0.1:18787",
  "wfp_driver_device_path": "\\\\.\\TrustAgentWfp",
  "wfp_fail_closed": true,
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
	if config.PDPGRPCEndpoint != "pdp.example.com:443" || config.PDPTLSServerName != "pdp.example.com" || config.PDPCAFile != "ca.pem" || config.EnrollmentTimeout != 10*time.Minute || config.EnrollmentPollInterval != 3*time.Second || config.DeviceDataSyncInterval != 30*time.Minute || config.DeviceDataSyncChangeScanInterval != 30*time.Second || config.LocalDNSListenAddress != "127.0.0.1:53" || config.LocalDNSServer != "127.0.0.1" || config.SyntheticIPCIDR != "100.64.0.0/10" || !config.HardenBrowserDoH || !config.TrafficInterceptionEnabled || config.TrafficProxyListenAddress != "127.0.0.1:18787" || config.WFPDriverDevicePath != `\\.\TrustAgentWfp` || !config.WFPFailClosed {
		t.Fatalf("service config = %+v", config)
	}
}

func TestLoadServiceConfigAcceptsUTF8BOM(t *testing.T) {
	writeConfig(t, "\xef\xbb\xbf"+serviceConfigJSON())

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.PDPGRPCEndpoint != "pdp.example.com:443" {
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
