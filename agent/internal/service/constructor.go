package service

import (
	"log/slog"
	"strings"
	"time"

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
	postureStatus := statusDisabled
	if dependencies.PostureCollector != nil {
		postureStatus = postureStatusUnknown
	}
	deviceIdentity := dependencies.DeviceIdentity
	if deviceIdentity == nil {
		deviceIdentity = enrollment.NewDefaultDeviceIdentity()
	}
	enrollmentManager := enrollment.NewManager(enrollmentConfig(config), enrollment.Dependencies{
		Logger:         dependencies.Logger,
		Client:         dependencies.EnrollmentClient,
		DeviceIdentity: deviceIdentity,
		Store:          dependencies.EnrollmentStore,
		Clock:          dependencies.Clock,
	})
	var service *Service
	userSessionManager := usersession.NewManager(userSessionConfig(config), usersession.Dependencies{
		Logger:         dependencies.Logger,
		Client:         dependencies.UserSessionClient,
		Enrollment:     enrollmentManager,
		DeviceIdentity: deviceIdentity,
		PostureSnapshot: func() ipc.DevicePostureReport {
			if service == nil {
				return ipc.DevicePostureReport{}
			}
			return service.cachedPostureReport()
		},
		Clock: dependencies.Clock,
	})
	service = &Service{
		logger:           dependencies.Logger,
		state:            StateStopped,
		listenerFactory:  dependencies.ListenerFactory,
		postureCollector: postureCollectorFromDependencies(dependencies),
		enrollment:       enrollmentManager,
		userSessions:     userSessionManager,
		clock:            dependencies.Clock,
		posture:          devicePostureState{Status: postureStatus},
		config:           config,
	}
	return service
}

func postureCollectorFromDependencies(dependencies Dependencies) DevicePostureCollector {
	if dependencies.PostureCollector != nil {
		return dependencies.PostureCollector
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
