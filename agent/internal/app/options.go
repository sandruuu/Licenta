package app

import "time"

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
	return loadServiceConfig(ServiceConfig{})
}

func LoadTrayConfig() (TrayConfig, error) {
	return loadTrayConfig(TrayConfig{})
}
