package app

import "time"

type ServiceConfig struct {
	PDPGRPCEndpoint        string
	PDPTLSServerName       string
	PDPCAFile              string
	EnrollmentTimeout      time.Duration
	EnrollmentPollInterval time.Duration
	EnrollmentStatePath    string
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
