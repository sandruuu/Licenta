package app

import "time"

type ServiceConfig struct {
	PDPGRPCEndpoint                  string
	PDPTLSServerName                 string
	PDPCAFile                        string
	EnrollmentTimeout                time.Duration
	EnrollmentPollInterval           time.Duration
	DeviceDataSyncInterval           time.Duration
	DeviceDataSyncChangeScanInterval time.Duration
	EnrollmentStatePath              string
	LocalDNSListenAddress            string
	LocalDNSServer                   string
	SyntheticIPCIDR                  string
	HardenBrowserDoH                 bool
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
