package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const configFilename = "config.json"

var executablePath = os.Executable

type configFile struct {
	TrayTimeout                            string `json:"tray_timeout,omitempty"`
	DashboardRefreshInterval               string `json:"dashboard_refresh_interval,omitempty"`
	PDPGRPCEndpoint                        string `json:"pdp_grpc_endpoint,omitempty"`
	PDPTLSServerName                       string `json:"pdp_tls_server_name,omitempty"`
	PDPCAFile                              string `json:"pdp_ca_file,omitempty"`
	EnrollmentTimeout                      string `json:"enrollment_timeout,omitempty"`
	EnrollmentPollInterval                 string `json:"enrollment_poll_interval,omitempty"`
	DeviceDataSyncInterval                 string `json:"device_data_sync_interval,omitempty"`
	DeviceDataSyncChangeScanInterval       string `json:"device_data_sync_change_scan_interval,omitempty"`
	LegacyDeviceDataSyncInterval           string `json:"device_telemetry_interval,omitempty"`
	LegacyDeviceDataSyncChangeScanInterval string `json:"device_telemetry_change_scan_interval,omitempty"`
	EnrollmentStatePath                    string `json:"enrollment_state_path,omitempty"`
	LocalDNSListenAddress                  string `json:"local_dns_listen_address,omitempty"`
	LocalDNSServer                         string `json:"local_dns_server,omitempty"`
	SyntheticIPCIDR                        string `json:"synthetic_ip_cidr,omitempty"`
	HardenBrowserDoH                       bool   `json:"harden_browser_doh,omitempty"`
}

func loadServiceConfig(serviceConfig ServiceConfig) (ServiceConfig, error) {
	fileConfig, found, err := loadConfig()
	if err != nil || !found {
		return serviceConfig, err
	}
	return applyServiceConfig(serviceConfig, fileConfig)
}

func loadTrayConfig(trayConfig TrayConfig) (TrayConfig, error) {
	fileConfig, found, err := loadConfig()
	if err != nil || !found {
		return trayConfig, err
	}
	return applyTrayConfig(trayConfig, fileConfig)
}

func applyServiceConfig(options ServiceConfig, config configFile) (ServiceConfig, error) {
	var err error
	options.PDPGRPCEndpoint = strings.TrimSpace(config.PDPGRPCEndpoint)
	options.PDPTLSServerName = strings.TrimSpace(config.PDPTLSServerName)
	options.PDPCAFile = strings.TrimSpace(config.PDPCAFile)
	options.EnrollmentStatePath = strings.TrimSpace(config.EnrollmentStatePath)
	options.LocalDNSListenAddress = strings.TrimSpace(config.LocalDNSListenAddress)
	options.LocalDNSServer = strings.TrimSpace(config.LocalDNSServer)
	options.SyntheticIPCIDR = strings.TrimSpace(config.SyntheticIPCIDR)
	options.HardenBrowserDoH = config.HardenBrowserDoH
	if options.EnrollmentTimeout, err = optionalConfigDuration("enrollment_timeout", config.EnrollmentTimeout); err != nil {
		return options, err
	}
	if options.EnrollmentPollInterval, err = optionalConfigDuration("enrollment_poll_interval", config.EnrollmentPollInterval); err != nil {
		return options, err
	}
	deviceDataSyncInterval := firstNonEmptyConfig(config.DeviceDataSyncInterval, config.LegacyDeviceDataSyncInterval)
	if options.DeviceDataSyncInterval, err = optionalConfigDuration("device_data_sync_interval", deviceDataSyncInterval); err != nil {
		return options, err
	}
	deviceDataSyncChangeScanInterval := firstNonEmptyConfig(config.DeviceDataSyncChangeScanInterval, config.LegacyDeviceDataSyncChangeScanInterval)
	if options.DeviceDataSyncChangeScanInterval, err = optionalConfigDuration("device_data_sync_change_scan_interval", deviceDataSyncChangeScanInterval); err != nil {
		return options, err
	}
	return options, nil
}

func firstNonEmptyConfig(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func applyTrayConfig(options TrayConfig, config configFile) (TrayConfig, error) {
	var err error
	if options.Timeout, err = requiredConfigDuration("tray_timeout", config.TrayTimeout); err != nil {
		return options, err
	}
	if options.DashboardRefreshInterval, err = requiredConfigDuration("dashboard_refresh_interval", config.DashboardRefreshInterval); err != nil {
		return options, err
	}
	return options, nil
}

func requiredConfigDuration(name, value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("agent config %s is required", name)
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("agent config %s must be a duration: %w", name, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("agent config %s must be greater than zero", name)
	}
	return duration, nil
}

func optionalConfigDuration(name, value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("agent config %s must be a duration: %w", name, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("agent config %s must be greater than zero", name)
	}
	return duration, nil
}

func loadConfig() (configFile, bool, error) {
	path, err := configPath()
	if err != nil {
		return configFile{}, false, err
	}
	config, err := readFileConfig(path)
	if err == nil {
		return config, true, nil
	}
	if os.IsNotExist(err) {
		return configFile{}, false, nil
	}
	return configFile{}, false, err
}

func readFileConfig(path string) (configFile, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "." || cleanPath == "" {
		return configFile{}, os.ErrNotExist
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return configFile{}, err
	}
	var config configFile
	if err := json.Unmarshal(data, &config); err != nil {
		return configFile{}, fmt.Errorf("decode agent config %s: %w", cleanPath, err)
	}
	return config, nil
}

func configPath() (string, error) {
	executable, err := executablePath()
	if err != nil {
		return "", fmt.Errorf("resolve agent executable path: %w", err)
	}
	executable = strings.TrimSpace(executable)
	if executable == "" {
		return "", fmt.Errorf("agent executable path is empty")
	}
	return filepath.Join(filepath.Dir(executable), configFilename), nil
}
