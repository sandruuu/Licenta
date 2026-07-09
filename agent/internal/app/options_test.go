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
	if err := os.WriteFile(filepath.Join(configDir, "ca.pem"), []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	useExecutableDir(t, configDir)
	return configDir
}

func useExecutableDir(t *testing.T, configDir string) {
	t.Helper()
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
  "pipe_authorized_user_sid": "S-1-5-21-1000"
}`
}

func TestLoadServiceConfigLoadsServiceConfig(t *testing.T) {
	configDir := writeConfig(t, serviceConfigJSON())

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.PDPGRPCEndpoint != "pdp.example.com:443" || config.PDPTLSServerName != "pdp.example.com" || config.PDPCAFile != filepath.Join(configDir, "ca.pem") || config.EnrollmentTimeout != 10*time.Minute || config.CertificateRenewBefore != 12*time.Hour || config.CertificateRenewCheckInterval != time.Hour || config.CertificateRenewTimeout != 20*time.Second || config.SessionRenewBefore != 2*time.Minute || config.SessionRenewRetryInterval != 15*time.Second || config.DeviceDataSyncInterval != 30*time.Minute || config.DeviceDataSyncChangeScanInterval != 2*time.Second || config.LocalDNSListenAddress != "127.0.0.1:53" || config.LocalDNSServer != "127.0.0.1" || config.SyntheticIPCIDR != "100.64.0.0/10" || config.HardenBrowserDoH || !config.TrafficInterceptionEnabled || config.TrafficProxyListenAddress != "127.0.0.1:18787" || config.WFPDriverDevicePath != `\\.\TrustAgentWfp` || !config.WFPFailClosed || config.PipeAuthorizedUserSID != "S-1-5-21-1000" {
		t.Fatalf("service config = %+v", config)
	}
}

func TestLoadServiceConfigIgnoresInternalTuningFields(t *testing.T) {
	body := strings.TrimSuffix(serviceConfigJSON(), "\n}") + `,
  "device_data_sync_change_scan_interval": "30s",
  "harden_browser_doh": true,
  "traffic_interception_enabled": false,
  "wfp_fail_closed": false
}`
	writeConfig(t, body)

	config, err := LoadServiceConfig()
	if err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
	if config.DeviceDataSyncChangeScanInterval != 2*time.Second || config.HardenBrowserDoH || !config.TrafficInterceptionEnabled || !config.WFPFailClosed {
		t.Fatalf("internal defaults were overridden: %+v", config)
	}
}

func TestLoadServiceConfigKeepsAbsolutePDPCAFile(t *testing.T) {
	absoluteCA := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(absoluteCA, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0600); err != nil {
		t.Fatalf("write absolute CA file: %v", err)
	}
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
	writeConfig(t, serviceConfigJSON())

	config, err := LoadTrayConfig()
	if err != nil {
		t.Fatalf("LoadTrayConfig returned error: %v", err)
	}
	if config.Timeout != 10*time.Second || config.DashboardRefreshInterval != time.Second {
		t.Fatalf("tray config = %+v", config)
	}
}

func TestLoadTrayConfigLoadsSharedConfig(t *testing.T) {
	writeConfig(t, `{}`)

	config, err := LoadTrayConfig()
	if err != nil {
		t.Fatalf("LoadTrayConfig returned error: %v", err)
	}
	if config.Timeout != 10*time.Second || config.DashboardRefreshInterval != time.Second {
		t.Fatalf("tray config = %+v", config)
	}
}

func TestLoadServiceConfigAllowsMissingConfig(t *testing.T) {
	useExecutableDir(t, t.TempDir())

	if _, err := LoadServiceConfig(); err != nil {
		t.Fatalf("LoadServiceConfig returned error: %v", err)
	}
}

func TestLoadServiceConfigValidatesServiceConfig(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "missing required endpoint",
			body:    strings.Replace(serviceConfigJSON(), `"pdp_grpc_endpoint": "pdp.example.com:443"`, `"pdp_grpc_endpoint": ""`, 1),
			wantErr: "pdp_grpc_endpoint is required",
		},
		{
			name:    "missing CA file",
			body:    strings.Replace(serviceConfigJSON(), `"pdp_ca_file": "ca.pem"`, `"pdp_ca_file": "missing.pem"`, 1),
			wantErr: "read agent config pdp_ca_file",
		},
		{
			name:    "missing TLS server name",
			body:    strings.Replace(serviceConfigJSON(), `"pdp_tls_server_name": "pdp.example.com"`, `"pdp_tls_server_name": ""`, 1),
			wantErr: "pdp_tls_server_name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeConfig(t, tt.body)

			if _, err := LoadServiceConfig(); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadServiceConfig error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func escapeJSONPath(path string) string {
	return strings.ReplaceAll(path, `\`, `\\`)
}
