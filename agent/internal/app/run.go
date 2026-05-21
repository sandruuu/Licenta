package app

import (
	"context"
	"log/slog"

	"agent/internal/service"
	"agent/internal/tray"
)

func Run(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if service.IsServiceContext() {
		config, err := LoadServiceConfig()
		if err != nil {
			return err
		}
		svc := service.New(serviceConfigFromConfig(config), service.Dependencies{Logger: logger})
		return service.RunService(service.ServiceName, svc.Run, logger)
	}
	config, err := LoadTrayConfig()
	if err != nil {
		return err
	}
	return tray.Run(ctx, trayOptionsFromConfig(config), logger)
}

func serviceConfigFromConfig(config ServiceConfig) service.Config {
	return service.Config{
		PDPGRPCEndpoint:        config.PDPGRPCEndpoint,
		PDPTLSServerName:       config.PDPTLSServerName,
		PDPCAFile:              config.PDPCAFile,
		EnrollmentTimeout:      config.EnrollmentTimeout,
		EnrollmentPollInterval: config.EnrollmentPollInterval,
		EnrollmentStatePath:    config.EnrollmentStatePath,
	}
}

func trayOptionsFromConfig(config TrayConfig) tray.Options {
	return tray.Options{
		Timeout:                  config.Timeout,
		DashboardRefreshInterval: config.DashboardRefreshInterval,
	}
}
