package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
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
	return configDir
}

func serviceConfigJSON() string {
	return `{
  "pdp_grpc_endpoint": "pdp.example.com:443",
  "pdp_tls_server_name": "pdp.example.com",
  "pdp_ca_file": "ca.pem",
  "enrollment_timeout": "10m",
  "certificate_renew_before": "12h",
  "certificate_renew_check_interval": "1h",
  "certificate_renew_timeout": "20s",
  "session_renew_before": "2m",
  "session_renew_retry_interval": "15s",
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
  "pipe_authorized_user_sid": "S-1-5-21-1000",
  "tray_timeout": "10s",
  "dashboard_refresh_interval": "30s"
}`
}

func TestLoadServiceConfigLoadsServiceConfig(t *testing.T) {
	configDir := writeConfig(t, serviceConfigJSON())

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.PDPGRPCEndpoint != "pdp.example.com:443" || config.PDPTLSServerName != "pdp.example.com" || config.PDPCAFile != filepath.Join(configDir, "ca.pem") || config.EnrollmentTimeout != 10*time.Minute || config.CertificateRenewBefore != 12*time.Hour || config.CertificateRenewCheckInterval != time.Hour || config.CertificateRenewTimeout != 20*time.Second || config.SessionRenewBefore != 2*time.Minute || config.SessionRenewRetryInterval != 15*time.Second || config.DeviceDataSyncInterval != 30*time.Minute || config.DeviceDataSyncChangeScanInterval != 30*time.Second || config.LocalDNSListenAddress != "127.0.0.1:53" || config.LocalDNSServer != "127.0.0.1" || config.SyntheticIPCIDR != "100.64.0.0/10" || !config.HardenBrowserDoH || !config.TrafficInterceptionEnabled || config.TrafficProxyListenAddress != "127.0.0.1:18787" || config.WFPDriverDevicePath != `\\.\TrustAgentWfp` || !config.WFPFailClosed || config.PipeAuthorizedUserSID != "S-1-5-21-1000" {
		t.Fatalf("service config = %+v", config)
	}
}

func TestLoadServiceConfigKeepsAbsolutePDPCAFile(t *testing.T) {
	absoluteCA := filepath.Join(t.TempDir(), "ca.pem")
	body := strings.Replace(serviceConfigJSON(), `"pdp_ca_file": "ca.pem"`, `"pdp_ca_file": "`+escapeJSONPath(absoluteCA)+`"`, 1)
	writeConfig(t, body)

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.PDPCAFile != absoluteCA {
		t.Fatalf("PDPCAFile = %q, want %q", config.PDPCAFile, absoluteCA)
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

func escapeJSONPath(path string) string {
	return strings.ReplaceAll(path, `\`, `\\`)
}
