package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	agentevents "agent/internal/service/agent-events"
	devicedatasync "agent/internal/service/device-data-sync"
	"agent/internal/service/enrollment"
	flowauthorization "agent/internal/service/flow-authorization"
	pdpclient "agent/internal/service/pdp-client"
	protectedresources "agent/internal/service/protected-resources"
	trafficinterception "agent/internal/service/traffic-interception"
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
	if config.CertificateRenewBefore <= 0 {
		config.CertificateRenewBefore = defaultCertificateRenewBefore
	}
	if config.CertificateRenewCheckInterval <= 0 {
		config.CertificateRenewCheckInterval = defaultCertificateRenewCheckInterval
	}
	if config.CertificateRenewTimeout <= 0 {
		config.CertificateRenewTimeout = defaultCertificateRenewTimeout
	}
	if config.LoginTimeout <= 0 {
		config.LoginTimeout = defaultLoginTimeout
	}
	if config.LoginPollInterval <= 0 {
		config.LoginPollInterval = defaultLoginPollInterval
	}
	if config.SessionRenewBefore <= 0 {
		config.SessionRenewBefore = defaultSessionRenewBefore
	}
	if config.SessionRenewRetryInterval <= 0 {
		config.SessionRenewRetryInterval = defaultSessionRenewRetryInterval
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
	pdpClient := dependencies.PDPClient
	if pdpClient == nil {
		pdpClient = pdpclient.New(pdpClientConfig(config), deviceIdentity)
	}
	var deviceDataSync *devicedatasync.Runner
	enrollmentManager := enrollment.NewManager(enrollmentConfig(config), enrollment.Dependencies{
		Logger:         dependencies.Logger,
		Client:         dependencies.EnrollmentClient,
		RenewalClient:  dependencies.EnrollmentRenewalClient,
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
		Logger:        dependencies.Logger,
		Client:        dependencies.UserSessionClient,
		ClientFactory: userSessionClientFactory(pdpClient),
		Enrollment:    enrollmentManager,
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
	resourceConnector := newResourceStreamConnector(resourceStreamConnectorConfig{
		PDPCAFile:     config.PDPCAFile,
		GatewayCAFile: config.PDPCAFile,
	}, dependencies, enrollmentManager, userSessionManager, deviceIdentity, pdpClient)
	resourceConnector.onAuthenticationRequired = func(request trafficinterception.StreamRequest) {
		if service != nil {
			service.recordAuthenticationRequired(request)
		}
	}
	resourceConnector.onStepUpRequired = func(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse) {
		if service != nil {
			service.recordStepUpRequired(request, authorization)
		}
	}
	resourceConnector.onResourceAllowed = func(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse) {
		if service != nil {
			service.recordResourceAllowed(request, authorization)
		}
	}
	resourceConnector.onResourceDenied = func(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse, err error) {
		if service != nil {
			service.recordResourceDenied(request, authorization, err)
		}
	}
	protectedResources := dependencies.ProtectedResources
	if protectedResources == nil {
		if manager, err := protectedresources.NewManager(protectedResourcesConfig(config), protectedresources.Dependencies{
			Logger:           dependencies.Logger,
			TrafficConnector: resourceConnector,
		}); err != nil {
			dependencies.Logger.Warn("protected resources manager could not be initialized", "error", err)
		} else {
			protectedResources = manager
		}
	}
	var syncCollector devicedatasync.Collector
	if dependencies.DeviceDataCollector != nil {
		syncCollector = deviceDataSyncCollector(&service)
	}
	deviceDataSync = devicedatasync.NewRunner(deviceDataSyncConfig(config), devicedatasync.Dependencies{
		Logger:        dependencies.Logger,
		Collector:     syncCollector,
		Watcher:       dependencies.DeviceDataWatcher,
		Enrollment:    enrollmentManager,
		ClientFactory: deviceDataSyncClientFactory(dependencies.DeviceDataSyncClientFactory, pdpClient),
		Clock:         dependencies.Clock,
	})
	service = &Service{
		logger:              dependencies.Logger,
		state:               StateStopped,
		listenerFactory:     dependencies.ListenerFactory,
		deviceDataCollector: deviceDataCollectorFromDependencies(dependencies),
		enrollment:          enrollmentManager,
		userSessions:        userSessionManager,
		protectedResources:  protectedResources,
		deviceIdentity:      deviceIdentity,
		deviceDataSync:      deviceDataSync,
		agentEventsFactory:  agentEventsClientFactory(dependencies.AgentEventsClientFactory, pdpClient),
		pdpClient:           pdpClient,
		clock:               dependencies.Clock,
		deviceData:          deviceDataState{Status: deviceDataStatus},
		config:              config,
	}
	return service
}

func agentEventsClientFactory(custom AgentEventsClientFactory, pdpClient *pdpclient.Client) AgentEventsClientFactory {
	if custom != nil {
		return custom
	}
	if pdpClient == nil {
		return func(context.Context, enrollment.EnrollmentRecord) (AgentEventsClient, error) {
			return nil, fmt.Errorf("shared PDP gRPC client is required for agent events")
		}
	}
	return func(ctx context.Context, record enrollment.EnrollmentRecord) (AgentEventsClient, error) {
		connection, err := pdpClient.Connection(ctx, record)
		if err != nil {
			return nil, err
		}
		return agentevents.NewGRPCClientFromConnection(connection)
	}
}

func pdpClientConfig(config Config) pdpclient.Config {
	return pdpclient.Config{
		PDPGRPCEndpoint:  config.PDPGRPCEndpoint,
		PDPTLSServerName: config.PDPTLSServerName,
		PDPCAFile:        config.PDPCAFile,
	}
}

func userSessionClientFactory(pdpClient *pdpclient.Client) usersession.ClientFactory {
	if pdpClient == nil {
		return func(context.Context, usersession.Config, enrollment.EnrollmentRecord) (usersession.Client, error) {
			return nil, fmt.Errorf("shared PDP gRPC client is required for user session")
		}
	}
	return func(ctx context.Context, _ usersession.Config, record enrollment.EnrollmentRecord) (usersession.Client, error) {
		connection, err := pdpClient.Connection(ctx, record)
		if err != nil {
			return nil, err
		}
		return usersession.NewGRPCClientFromConnection(connection)
	}
}

func deviceDataSyncClientFactory(custom DeviceDataSyncClientFactory, pdpClient *pdpclient.Client) DeviceDataSyncClientFactory {
	if custom != nil {
		return custom
	}
	if pdpClient == nil {
		return func(context.Context, enrollment.EnrollmentRecord) (DeviceDataSyncClient, error) {
			return nil, fmt.Errorf("shared PDP gRPC client is required for device data sync")
		}
	}
	return func(ctx context.Context, record enrollment.EnrollmentRecord) (DeviceDataSyncClient, error) {
		connection, err := pdpClient.Connection(ctx, record)
		if err != nil {
			return nil, err
		}
		return devicedatasync.NewGRPCClientFromConnection(connection)
	}
}

func flowAuthorizationClientFromPDP(ctx context.Context, pdpClient *pdpclient.Client, record enrollment.EnrollmentRecord) (flowauthorization.Client, error) {
	if pdpClient == nil {
		return nil, nil
	}
	connection, err := pdpClient.Connection(ctx, record)
	if err != nil {
		return nil, err
	}
	return flowauthorization.NewGRPCClientFromConnection(connection)
}

func protectedResourcesConfig(config Config) protectedresources.Config {
	return protectedresources.Config{
		DNSListenAddress:           config.LocalDNSListenAddress,
		DNSServer:                  config.LocalDNSServer,
		SyntheticIPCIDR:            config.SyntheticIPCIDR,
		HardenDoH:                  config.HardenBrowserDoH,
		TrafficInterceptionEnabled: config.TrafficInterceptionEnabled,
		TrafficProxyListenAddress:  config.TrafficProxyListenAddress,
		WFPDriverDevicePath:        config.WFPDriverDevicePath,
		WFPFailClosed:              config.WFPFailClosed,
	}
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
		PDPGRPCEndpoint:               config.PDPGRPCEndpoint,
		PDPTLSServerName:              config.PDPTLSServerName,
		PDPCAFile:                     config.PDPCAFile,
		EnrollmentTimeout:             config.EnrollmentTimeout,
		EnrollmentPollInterval:        config.EnrollmentPollInterval,
		CertificateRenewBefore:        config.CertificateRenewBefore,
		CertificateRenewCheckInterval: config.CertificateRenewCheckInterval,
		CertificateRenewTimeout:       config.CertificateRenewTimeout,
		EnrollmentStatePath:           config.EnrollmentStatePath,
		DeviceKeyName:                 config.DeviceKeyName,
	}
}

func userSessionConfig(config Config) usersession.Config {
	return usersession.Config{
		LoginTimeout:              config.LoginTimeout,
		LoginPollInterval:         config.LoginPollInterval,
		SessionRenewBefore:        config.SessionRenewBefore,
		SessionRenewRetryInterval: config.SessionRenewRetryInterval,
		TrustedStepUpHosts:        trustedStepUpHosts(config),
	}
}

func trustedStepUpHosts(config Config) []string {
	var hosts []string
	if host := strings.TrimSpace(config.PDPTLSServerName); host != "" {
		hosts = append(hosts, host)
	}
	endpoint := strings.TrimSpace(config.PDPGRPCEndpoint)
	if endpoint != "" {
		if host, _, err := net.SplitHostPort(endpoint); err == nil && host != "" {
			hosts = append(hosts, host, endpoint)
		} else {
			hosts = append(hosts, endpoint)
		}
	}
	return hosts
}

func deviceDataSyncConfig(config Config) devicedatasync.Config {
	return devicedatasync.Config{
		Interval:           config.DeviceDataSyncInterval,
		ChangeScanInterval: config.DeviceDataSyncChangeScanInterval,
	}
}
