package app

import (
	"context"
	"log/slog"

	"agent/internal/service"
	"agent/internal/service/scm"
	"agent/internal/shared/meta"
	"agent/internal/tray"
)

func Run(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if scm.IsServiceContext() {
		config, err := LoadServiceConfig()
		if err != nil {
			return err
		}
		svc := service.New(serviceConfigFromConfig(config), service.Dependencies{Logger: logger})
		return scm.RunService(meta.ServiceName, svc.Run, logger)
	}
	config, err := LoadTrayConfig()
	if err != nil {
		return err
	}
	return tray.Run(ctx, trayOptionsFromConfig(config), logger)
}

func serviceConfigFromConfig(config ServiceConfig) service.Config {
	return service.Config{
		AuthorizedUserSID:          config.AuthorizedUserSID,
		PAURL:                      config.PAURL,
		CloudCertSHA256:            config.CloudCertSHA256,
		CAFile:                     config.CAFile,
		DNSServer:                  config.DNSServer,
		PostureInterval:            config.PostureInterval,
		CriticalInterval:           config.CriticalInterval,
		HeartbeatInterval:          config.HeartbeatInterval,
		PostureReportTimeout:       config.PostureReportTimeout,
		CatalogInterval:            config.CatalogInterval,
		CatalogCacheTTL:            config.CatalogCacheTTL,
		CatalogRetryBackoff:        config.CatalogRetryBackoff,
		AccessTokenExpirySkew:      config.AccessTokenExpirySkew,
		CertificateRenewalInterval: config.CertificateRenewalInterval,
		CertificateRenewBefore:     config.CertificateRenewBefore,
		CertificateRenewalTimeout:  config.CertificateRenewalTimeout,
		PARequestTimeout:           config.PARequestTimeout,
		EnrollmentRateLimitMax:     config.EnrollmentRateLimitMax,
		EnrollmentRateLimitWindow:  config.EnrollmentRateLimitWindow,
		TUNEnabled:                 config.TUNEnabled,
		TUNName:                    config.TUNName,
		TUNIP:                      config.TUNIP,
		TUNNetmask:                 config.TUNNetmask,
		TUNRouteCIDR:               config.TUNRouteCIDR,
		ProcessIdentity:            config.ProcessIdentity,
	}
}

func trayOptionsFromConfig(config TrayConfig) tray.Options {
	return tray.Options{
		Timeout:                  config.Timeout,
		EnrollmentTimeout:        config.EnrollmentTimeout,
		TokenRefreshInterval:     config.TokenRefreshInterval,
		TokenRefreshMargin:       config.TokenRefreshMargin,
		DashboardRefreshInterval: config.DashboardRefreshInterval,
		PAURL:                    config.PAURL,
		IssuerURL:                config.IssuerURL,
		ClientID:                 config.ClientID,
		Scopes:                   config.Scopes,
		DeviceID:                 config.DeviceID,
		Nonce:                    config.EnrollmentNonce,
		LocalSID:                 config.LocalSID,
		KeyName:                  config.KeyName,
		Hostname:                 config.Hostname,
		CAFile:                   config.CAFile,
		ACRValues:                config.ACRValues,
	}
}
