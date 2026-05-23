package app

import (
	"context"
	"log/slog"

	"agent/internal/service"
	devicedata "agent/internal/service/device-data"
	"agent/internal/service/host"
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
		svc := service.New(serviceConfigFromConfig(config), service.Dependencies{
			Logger:              logger,
			DeviceDataCollector: devicedata.NewDefaultCollector(logger),
			DeviceDataWatcher:   devicedata.NewDefaultWatcher(logger),
		})
		return host.RunService(host.ServiceName, svc.Run, logger)
	}
	config, err := LoadTrayConfig()
	if err != nil {
		return err
	}
	return tray.Run(ctx, trayOptionsFromConfig(config), logger)
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
		LocalDNSListenAddress:            config.LocalDNSListenAddress,
		LocalDNSServer:                   config.LocalDNSServer,
		SyntheticIPCIDR:                  config.SyntheticIPCIDR,
		HardenBrowserDoH:                 config.HardenBrowserDoH,
		TrafficInterceptionEnabled:       config.TrafficInterceptionEnabled,
		TrafficProxyListenAddress:        config.TrafficProxyListenAddress,
		WFPDriverDevicePath:              config.WFPDriverDevicePath,
		WFPFailClosed:                    config.WFPFailClosed,
	}
}

func trayOptionsFromConfig(config TrayConfig) tray.Options {
	return tray.Options{
		Timeout:                  config.Timeout,
		DashboardRefreshInterval: config.DashboardRefreshInterval,
	}
}
