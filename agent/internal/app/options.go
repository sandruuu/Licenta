package app

import "time"

const (
	defaultTrayTimeout              = 10 * time.Second
	defaultDashboardRefreshInterval = time.Second
)

type ServiceConfig struct {
	PDPGRPCEndpoint                  string
	PDPTLSServerName                 string
	PDPCAFile                        string
	EnrollmentTimeout                time.Duration
	CertificateRenewBefore           time.Duration
	CertificateRenewCheckInterval    time.Duration
	CertificateRenewTimeout          time.Duration
	SessionRenewBefore               time.Duration
	SessionRenewRetryInterval        time.Duration
	DeviceDataSyncInterval           time.Duration
	DeviceDataSyncChangeScanInterval time.Duration
	EnrollmentStatePath              string
	LocalDNSListenAddress            string
	LocalDNSServer                   string
	SyntheticIPCIDR                  string
	HardenBrowserDoH                 bool
	TrafficInterceptionEnabled       bool
	TrafficProxyListenAddress        string
	WFPDriverDevicePath              string
	WFPFailClosed                    bool
	PipeAuthorizedUserSID            string
}

type TrayConfig struct {
	Timeout                  time.Duration
	DashboardRefreshInterval time.Duration
}

func LoadServiceConfig() (ServiceConfig, error) {
	return loadServiceConfig(defaultServiceConfig())
}

func LoadTrayConfig() (TrayConfig, error) {
	return loadTrayConfig(defaultTrayConfig())
}

func defaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		EnrollmentTimeout:                10 * time.Minute,
		CertificateRenewBefore:           12 * time.Hour,
		CertificateRenewCheckInterval:    time.Hour,
		CertificateRenewTimeout:          20 * time.Second,
		SessionRenewBefore:               2 * time.Minute,
		SessionRenewRetryInterval:        15 * time.Second,
		DeviceDataSyncInterval:           30 * time.Minute,
		DeviceDataSyncChangeScanInterval: 2 * time.Second,
		LocalDNSListenAddress:            "127.0.0.1:53",
		LocalDNSServer:                   "127.0.0.1",
		SyntheticIPCIDR:                  "100.64.0.0/10",
		HardenBrowserDoH:                 false,
		TrafficInterceptionEnabled:       true,
		TrafficProxyListenAddress:        "127.0.0.1:18787",
		WFPDriverDevicePath:              `\\.\TrustAgentWfp`,
		WFPFailClosed:                    true,
	}
}

func defaultTrayConfig() TrayConfig {
	return TrayConfig{
		Timeout:                  defaultTrayTimeout,
		DashboardRefreshInterval: defaultDashboardRefreshInterval,
	}
}
