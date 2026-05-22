package service

import (
	"context"
	"log/slog"
	"strings"
	"time"

	devicedatasync "agent/internal/service/device-data-sync"
	"agent/internal/service/enrollment"
	"agent/internal/service/usersession"
	"agent/internal/shared/ipc"
)

func New(config Config, dependencies Dependencies) *Service {
	config = normalizeConfig(config)
	dependencies = dependenciesWithDefaults(dependencies)
	return newBaseService(config, dependencies)
}

func normalizeConfig(config Config) Config {
	config.PDPGRPCEndpoint = strings.TrimSpace(config.PDPGRPCEndpoint)
	config.PDPTLSServerName = strings.TrimSpace(config.PDPTLSServerName)
	config.PDPCAFile = strings.TrimSpace(config.PDPCAFile)
	config.EnrollmentStatePath = strings.TrimSpace(config.EnrollmentStatePath)
	config.DeviceKeyName = strings.TrimSpace(config.DeviceKeyName)
	if config.DeviceKeyName == "" {
		config.DeviceKeyName = defaultDeviceKeyName
	}
	if config.EnrollmentTimeout <= 0 {
		config.EnrollmentTimeout = defaultEnrollmentTimeout
	}
	if config.EnrollmentPollInterval <= 0 {
		config.EnrollmentPollInterval = defaultEnrollmentPollInterval
	}
	if config.LoginTimeout <= 0 {
		config.LoginTimeout = defaultLoginTimeout
	}
	if config.LoginPollInterval <= 0 {
		config.LoginPollInterval = defaultLoginPollInterval
	}
	if config.DeviceDataSyncInterval <= 0 {
		config.DeviceDataSyncInterval = defaultDeviceDataSyncInterval
	}
	if config.DeviceDataSyncChangeScanInterval <= 0 {
		config.DeviceDataSyncChangeScanInterval = defaultDeviceDataSyncChangeScanInterval
	}
	return config
}

func dependenciesWithDefaults(dependencies Dependencies) Dependencies {
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.Default()
	}
	listenerFactory := dependencies.ListenerFactory
	if listenerFactory == nil {
		listenerFactory = ipc.Listen
	}
	clock := dependencies.Clock
	if clock == nil {
		clock = time.Now
	}
	dependencies.Logger = logger
	dependencies.ListenerFactory = listenerFactory
	dependencies.Clock = clock
	return dependencies
}

func newBaseService(config Config, dependencies Dependencies) *Service {
	deviceDataStatus := statusDisabled
	if dependencies.DeviceDataCollector != nil {
		deviceDataStatus = deviceDataStatusUnknown
	}
	deviceIdentity := dependencies.DeviceIdentity
	if deviceIdentity == nil {
		deviceIdentity = enrollment.NewDefaultDeviceIdentity()
	}
	var deviceDataSync *devicedatasync.Runner
	enrollmentManager := enrollment.NewManager(enrollmentConfig(config), enrollment.Dependencies{
		Logger:         dependencies.Logger,
		Client:         dependencies.EnrollmentClient,
		DeviceIdentity: deviceIdentity,
		Store:          dependencies.EnrollmentStore,
		Clock:          dependencies.Clock,
		OnEnrolled: func() {
			if deviceDataSync != nil {
				deviceDataSync.Trigger("enrollment")
			}
		},
	})
	var service *Service
	userSessionManager := usersession.NewManager(userSessionConfig(config), usersession.Dependencies{
		Logger:         dependencies.Logger,
		Client:         dependencies.UserSessionClient,
		Enrollment:     enrollmentManager,
		DeviceIdentity: deviceIdentity,
		DeviceDataSnapshot: func() ipc.DeviceDataReport {
			if service == nil {
				return ipc.DeviceDataReport{}
			}
			return service.cachedDeviceDataReport()
		},
		OnCatalog: func(ctx context.Context, _ ipc.PeerIdentity, catalog ipc.CatalogInfo) error {
			if service == nil || service.protectedResources == nil {
				return nil
			}
			return service.protectedResources.ApplyCatalog(ctx, catalog)
		},
		OnLogout: func(ctx context.Context, _ ipc.PeerIdentity) error {
			if service == nil || service.protectedResources == nil {
				return nil
			}
			return service.protectedResources.Clear(ctx)
		},
		Clock: dependencies.Clock,
	})
	var syncCollector devicedatasync.Collector
	if dependencies.DeviceDataCollector != nil {
		syncCollector = deviceDataSyncCollector(&service)
	}
	deviceDataSync = devicedatasync.NewRunner(deviceDataSyncConfig(config), devicedatasync.Dependencies{
		Logger:         dependencies.Logger,
		Collector:      syncCollector,
		Watcher:        dependencies.DeviceDataWatcher,
		Enrollment:     enrollmentManager,
		DeviceIdentity: deviceIdentity,
		ClientFactory:  dependencies.DeviceDataSyncClientFactory,
		Clock:          dependencies.Clock,
	})
	service = &Service{
		logger:              dependencies.Logger,
		state:               StateStopped,
		listenerFactory:     dependencies.ListenerFactory,
		deviceDataCollector: deviceDataCollectorFromDependencies(dependencies),
		enrollment:          enrollmentManager,
		userSessions:        userSessionManager,
		protectedResources:  dependencies.ProtectedResources,
		deviceIdentity:      deviceIdentity,
		deviceDataSync:      deviceDataSync,
		clock:               dependencies.Clock,
		deviceData:          deviceDataState{Status: deviceDataStatus},
		config:              config,
	}
	return service
}

func deviceDataSyncCollector(service **Service) devicedatasync.Collector {
	return devicedatasync.CollectorFunc(func(ctx context.Context, deviceID string) (ipc.DeviceDataReport, error) {
		if service == nil || *service == nil {
			return ipc.DeviceDataReport{}, context.Canceled
		}
		return (*service).collectDeviceData(ctx, deviceID)
	})
}

func deviceDataCollectorFromDependencies(dependencies Dependencies) DeviceDataCollector {
	if dependencies.DeviceDataCollector != nil {
		return dependencies.DeviceDataCollector
	}
	return nil
}

func enrollmentConfig(config Config) enrollment.Config {
	return enrollment.Config{
		PDPGRPCEndpoint:        config.PDPGRPCEndpoint,
		PDPTLSServerName:       config.PDPTLSServerName,
		PDPCAFile:              config.PDPCAFile,
		EnrollmentTimeout:      config.EnrollmentTimeout,
		EnrollmentPollInterval: config.EnrollmentPollInterval,
		EnrollmentStatePath:    config.EnrollmentStatePath,
		DeviceKeyName:          config.DeviceKeyName,
	}
}

func userSessionConfig(config Config) usersession.Config {
	return usersession.Config{
		PDPGRPCEndpoint:   config.PDPGRPCEndpoint,
		PDPTLSServerName:  config.PDPTLSServerName,
		PDPCAFile:         config.PDPCAFile,
		LoginTimeout:      config.LoginTimeout,
		LoginPollInterval: config.LoginPollInterval,
	}
}

func deviceDataSyncConfig(config Config) devicedatasync.Config {
	return devicedatasync.Config{
		Client: devicedatasync.ClientConfig{
			PDPGRPCEndpoint:  config.PDPGRPCEndpoint,
			PDPTLSServerName: config.PDPTLSServerName,
			PDPCAFile:        config.PDPCAFile,
		},
		Interval:           config.DeviceDataSyncInterval,
		ChangeScanInterval: config.DeviceDataSyncChangeScanInterval,
	}
}
