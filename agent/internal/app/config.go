package app

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const configFilename = "config.json"

var executablePath = os.Executable

type configFile struct {
	PAURL                        string   `json:"pa_url"`
	AuthorizedUserSID            string   `json:"authorized_user_sid,omitempty"`
	IssuerURL                    string   `json:"issuer_url,omitempty"`
	CloudCertSHA256              string   `json:"cloud_cert_sha256,omitempty"`
	CAFile                       string   `json:"ca_file,omitempty"`
	ClientID                     string   `json:"client_id,omitempty"`
	Scopes                       string   `json:"scopes,omitempty"`
	ACRValues                    string   `json:"acr_values,omitempty"`
	DNSServer                    string   `json:"dns_server,omitempty"`
	PostureInterval              string   `json:"posture_interval,omitempty"`
	CriticalInterval             string   `json:"critical_interval,omitempty"`
	HeartbeatInterval            string   `json:"heartbeat_interval,omitempty"`
	PostureReportTimeout         string   `json:"posture_report_timeout,omitempty"`
	CatalogInterval              string   `json:"catalog_interval,omitempty"`
	CatalogCacheTTL              string   `json:"catalog_cache_ttl,omitempty"`
	CatalogRetryBackoff          []string `json:"catalog_retry_backoff,omitempty"`
	AccessTokenExpirySkew        string   `json:"access_token_expiry_skew,omitempty"`
	CertificateRenewalInterval   string   `json:"certificate_renewal_interval,omitempty"`
	CertificateRenewBefore       string   `json:"certificate_renew_before,omitempty"`
	CertificateRenewalTimeout    string   `json:"certificate_renewal_timeout,omitempty"`
	PARequestTimeout             string   `json:"pa_request_timeout,omitempty"`
	EnrollmentRateLimitMax       int      `json:"enrollment_rate_limit_max,omitempty"`
	EnrollmentRateLimitWindow    string   `json:"enrollment_rate_limit_window,omitempty"`
	TrayTimeout                  string   `json:"tray_timeout,omitempty"`
	TrayEnrollmentTimeout        string   `json:"tray_enrollment_timeout,omitempty"`
	TokenRefreshInterval         string   `json:"token_refresh_interval,omitempty"`
	TokenRefreshMargin           string   `json:"token_refresh_margin,omitempty"`
	DashboardRefreshInterval     string   `json:"dashboard_refresh_interval,omitempty"`
	InstallTimeout               string   `json:"install_timeout,omitempty"`
	ServiceRecoveryRestartDelays []string `json:"service_recovery_restart_delays,omitempty"`
	TUNEnabled                   bool     `json:"tun,omitempty"`
	TUNName                      string   `json:"tun_name,omitempty"`
	TUNIP                        string   `json:"tun_ip,omitempty"`
	TUNNetmask                   string   `json:"tun_netmask,omitempty"`
	TUNRouteCIDR                 string   `json:"tun_route_cidr,omitempty"`
	ProcessIdentity              bool     `json:"process_identity,omitempty"`
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

func loadInstallConfig(installConfig InstallConfig) (InstallConfig, error) {
	fileConfig, found, err := loadConfig()
	if err != nil || !found {
		return installConfig, err
	}
	return applyInstallConfig(installConfig, fileConfig)
}

func applyServiceConfig(options ServiceConfig, config configFile) (ServiceConfig, error) {
	paURL, err := normalizeConfigURL("pa_url", config.PAURL)
	if err != nil {
		return options, err
	}
	options.PAURL = paURL
	options.CloudCertSHA256 = strings.TrimSpace(config.CloudCertSHA256)
	options.CAFile = strings.TrimSpace(config.CAFile)
	options.AuthorizedUserSID = strings.TrimSpace(config.AuthorizedUserSID)
	dnsServer, err := requiredConfigString("dns_server", config.DNSServer)
	if err != nil {
		return options, err
	}
	options.DNSServer = dnsServer
	if options.PostureInterval, err = requiredConfigDuration("posture_interval", config.PostureInterval); err != nil {
		return options, err
	}
	if options.CriticalInterval, err = requiredConfigDuration("critical_interval", config.CriticalInterval); err != nil {
		return options, err
	}
	if options.HeartbeatInterval, err = requiredConfigDuration("heartbeat_interval", config.HeartbeatInterval); err != nil {
		return options, err
	}
	if options.PostureReportTimeout, err = requiredConfigDuration("posture_report_timeout", config.PostureReportTimeout); err != nil {
		return options, err
	}
	if options.CatalogInterval, err = requiredConfigDuration("catalog_interval", config.CatalogInterval); err != nil {
		return options, err
	}
	if options.CatalogCacheTTL, err = requiredConfigDuration("catalog_cache_ttl", config.CatalogCacheTTL); err != nil {
		return options, err
	}
	if options.CatalogRetryBackoff, err = requiredConfigDurationList("catalog_retry_backoff", config.CatalogRetryBackoff); err != nil {
		return options, err
	}
	if options.AccessTokenExpirySkew, err = requiredConfigDuration("access_token_expiry_skew", config.AccessTokenExpirySkew); err != nil {
		return options, err
	}
	if options.CertificateRenewalInterval, err = requiredConfigDuration("certificate_renewal_interval", config.CertificateRenewalInterval); err != nil {
		return options, err
	}
	if options.CertificateRenewBefore, err = requiredConfigDuration("certificate_renew_before", config.CertificateRenewBefore); err != nil {
		return options, err
	}
	if options.CertificateRenewalTimeout, err = requiredConfigDuration("certificate_renewal_timeout", config.CertificateRenewalTimeout); err != nil {
		return options, err
	}
	if options.PARequestTimeout, err = requiredConfigDuration("pa_request_timeout", config.PARequestTimeout); err != nil {
		return options, err
	}
	if options.EnrollmentRateLimitMax, err = requiredConfigInt("enrollment_rate_limit_max", config.EnrollmentRateLimitMax); err != nil {
		return options, err
	}
	if options.EnrollmentRateLimitWindow, err = requiredConfigDuration("enrollment_rate_limit_window", config.EnrollmentRateLimitWindow); err != nil {
		return options, err
	}
	options.TUNEnabled = config.TUNEnabled
	if config.TUNEnabled {
		if options.TUNName, err = requiredConfigString("tun_name", config.TUNName); err != nil {
			return options, err
		}
		if options.TUNIP, err = requiredConfigString("tun_ip", config.TUNIP); err != nil {
			return options, err
		}
		if options.TUNNetmask, err = requiredConfigString("tun_netmask", config.TUNNetmask); err != nil {
			return options, err
		}
		if options.TUNRouteCIDR, err = requiredConfigString("tun_route_cidr", config.TUNRouteCIDR); err != nil {
			return options, err
		}
	} else {
		options.TUNName = strings.TrimSpace(config.TUNName)
		options.TUNIP = strings.TrimSpace(config.TUNIP)
		options.TUNNetmask = strings.TrimSpace(config.TUNNetmask)
		options.TUNRouteCIDR = strings.TrimSpace(config.TUNRouteCIDR)
	}
	options.ProcessIdentity = config.ProcessIdentity
	return options, nil
}

func applyTrayConfig(options TrayConfig, config configFile) (TrayConfig, error) {
	paURL, err := normalizeConfigURL("pa_url", config.PAURL)
	if err != nil {
		return options, err
	}
	issuerURL, err := issuerURLFromConfig(config, paURL)
	if err != nil {
		return options, err
	}

	options.PAURL = paURL
	options.IssuerURL = issuerURL
	if options.Timeout, err = requiredConfigDuration("tray_timeout", config.TrayTimeout); err != nil {
		return options, err
	}
	if options.EnrollmentTimeout, err = requiredConfigDuration("tray_enrollment_timeout", config.TrayEnrollmentTimeout); err != nil {
		return options, err
	}
	if options.TokenRefreshInterval, err = requiredConfigDuration("token_refresh_interval", config.TokenRefreshInterval); err != nil {
		return options, err
	}
	if options.TokenRefreshMargin, err = requiredConfigDuration("token_refresh_margin", config.TokenRefreshMargin); err != nil {
		return options, err
	}
	if options.DashboardRefreshInterval, err = requiredConfigDuration("dashboard_refresh_interval", config.DashboardRefreshInterval); err != nil {
		return options, err
	}
	options.ClientID = strings.TrimSpace(config.ClientID)
	options.Scopes = strings.TrimSpace(config.Scopes)
	options.ACRValues = strings.TrimSpace(config.ACRValues)
	options.LocalSID = strings.TrimSpace(config.AuthorizedUserSID)
	options.CAFile = strings.TrimSpace(config.CAFile)
	return options, nil
}

func applyInstallConfig(options InstallConfig, config configFile) (InstallConfig, error) {
	timeout, err := requiredConfigDuration("install_timeout", config.InstallTimeout)
	if err != nil {
		return options, err
	}
	options.Timeout = timeout
	restartDelays, err := requiredConfigDurationList("service_recovery_restart_delays", config.ServiceRecoveryRestartDelays)
	if err != nil {
		return options, err
	}
	options.ServiceRecoveryRestartDelays = restartDelays
	return options, nil
}

func issuerURLFromConfig(config configFile, paURL string) (string, error) {
	if strings.TrimSpace(config.IssuerURL) != "" {
		return normalizeConfigURL("issuer_url", config.IssuerURL)
	}
	return paURL, nil
}

func requiredConfigString(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("agent config %s is required", name)
	}
	return value, nil
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

func requiredConfigDurationList(name string, values []string) ([]time.Duration, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("agent config %s is required", name)
	}
	durations := make([]time.Duration, 0, len(values))
	for index, value := range values {
		duration, err := requiredConfigDuration(fmt.Sprintf("%s[%d]", name, index), value)
		if err != nil {
			return nil, err
		}
		durations = append(durations, duration)
	}
	return durations, nil
}

func requiredConfigInt(name string, value int) (int, error) {
	if value <= 0 {
		return 0, fmt.Errorf("agent config %s must be greater than zero", name)
	}
	return value, nil
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

func normalizeConfigURL(name, value string) (string, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("agent config %s must be an absolute URL", name)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("agent config %s must use http or https", name)
	}
	return value, nil
}
