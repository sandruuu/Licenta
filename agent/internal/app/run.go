package app

import (
	"context"
	"log/slog"

	"agent/internal/service"
	devicedata "agent/internal/service/device-data"
	"agent/internal/service/host"
	protectedresources "agent/internal/service/protected-resources"
	"agent/internal/tray"
)

func Run(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if host.IsServiceContext() {
		config, err := LoadServiceConfig()
		if err != nil {
			return err
		}
		protectedResources, err := protectedresources.NewManager(protectedResourcesConfigFromConfig(config), protectedresources.Dependencies{Logger: logger})
		if err != nil {
			return err
		}
		svc := service.New(serviceConfigFromConfig(config), service.Dependencies{
			Logger:              logger,
			DeviceDataCollector: devicedata.NewDefaultCollector(logger),
			DeviceDataWatcher:   devicedata.NewDefaultWatcher(logger),
			ProtectedResources:  protectedResources,
		})
		return host.RunService(host.ServiceName, svc.Run, logger)
	}
	config, err := LoadTrayConfig()
	if err != nil {
		return err
	}
	return tray.Run(ctx, trayOptionsFromConfig(config), logger)
}

func protectedResourcesConfigFromConfig(config ServiceConfig) protectedresources.Config {
	return protectedresources.Config{
		DNSListenAddress: config.LocalDNSListenAddress,
		DNSServer:        config.LocalDNSServer,
		SyntheticIPCIDR:  config.SyntheticIPCIDR,
		HardenDoH:        config.HardenBrowserDoH,
	}
}

func serviceConfigFromConfig(config ServiceConfig) service.Config {
	return service.Config{
		PDPGRPCEndpoint:                  config.PDPGRPCEndpoint,
		PDPTLSServerName:                 config.PDPTLSServerName,
		PDPCAFile:                        config.PDPCAFile,
		EnrollmentTimeout:                config.EnrollmentTimeout,
		EnrollmentPollInterval:           config.EnrollmentPollInterval,
		DeviceDataSyncInterval:           config.DeviceDataSyncInterval,
		DeviceDataSyncChangeScanInterval: config.DeviceDataSyncChangeScanInterval,
		EnrollmentStatePath:              config.EnrollmentStatePath,
	}
}

func trayOptionsFromConfig(config TrayConfig) tray.Options {
	return tray.Options{
		Timeout:                  config.Timeout,
		DashboardRefreshInterval: config.DashboardRefreshInterval,
	}
}
