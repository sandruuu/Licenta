package app

import "time"

type ServiceConfig struct {
	AuthorizedUserSID          string
	PAURL                      string
	CloudCertSHA256            string
	CAFile                     string
	DNSServer                  string
	PostureInterval            time.Duration
	CriticalInterval           time.Duration
	HeartbeatInterval          time.Duration
	PostureReportTimeout       time.Duration
	CatalogInterval            time.Duration
	CatalogCacheTTL            time.Duration
	CatalogRetryBackoff        []time.Duration
	AccessTokenExpirySkew      time.Duration
	CertificateRenewalInterval time.Duration
	CertificateRenewBefore     time.Duration
	CertificateRenewalTimeout  time.Duration
	PARequestTimeout           time.Duration
	EnrollmentRateLimitMax     int
	EnrollmentRateLimitWindow  time.Duration
	TUNEnabled                 bool
	TUNName                    string
	TUNIP                      string
	TUNNetmask                 string
	TUNRouteCIDR               string
	ProcessIdentity            bool
}

type TrayConfig struct {
	Timeout                  time.Duration
	EnrollmentTimeout        time.Duration
	TokenRefreshInterval     time.Duration
	TokenRefreshMargin       time.Duration
	DashboardRefreshInterval time.Duration
	PAURL                    string
	IssuerURL                string
	ClientID                 string
	Scopes                   string
	DeviceID                 string
	EnrollmentNonce          string
	LocalSID                 string
	KeyName                  string
	Hostname                 string
	ACRValues                string
	CAFile                   string
}

type InstallConfig struct {
	Timeout                      time.Duration
	ServiceRecoveryRestartDelays []time.Duration
}

func LoadServiceConfig() (ServiceConfig, error) {
	return loadServiceConfig(ServiceConfig{})
}

func LoadTrayConfig() (TrayConfig, error) {
	return loadTrayConfig(TrayConfig{})
}

func LoadInstallConfig() (InstallConfig, error) {
	return loadInstallConfig(InstallConfig{})
}
