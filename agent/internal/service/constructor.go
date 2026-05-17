package service

import (
	"log/slog"
	"strings"
	"time"

	"agent/internal/service/deviceidentity"
	"agent/internal/service/deviceposture"
	"agent/internal/service/enrollmentflow"
	servicestate "agent/internal/service/state"
	"agent/internal/shared/ipc"
)

func New(config Config, dependencies Dependencies) *Service {
	config = normalizeConfig(config)
	dependencies = dependenciesWithDefaults(dependencies)
	service := newBaseService(config, dependencies)

	service.configurePAClient(config, dependencies)
	service.configureDNS(config, dependencies)
	service.configureGatewayRelay(config, dependencies)
	service.configureNetworkManager(config, dependencies)
	service.restoreStartupState()

	return service
}

func normalizeConfig(config Config) Config {
	config.AuthorizedUserSID = strings.TrimSpace(config.AuthorizedUserSID)
	config.DNSServer = strings.TrimSpace(config.DNSServer)
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
	return &Service{
		logger:                     dependencies.Logger,
		state:                      StateStopped,
		authorizedUserSID:          config.AuthorizedUserSID,
		listenerFactory:            dependencies.ListenerFactory,
		enrollmentValidator:        dependencies.EnrollmentValidator,
		identityProvider:           identityProviderFromDependencies(config, dependencies),
		postureCollector:           postureCollectorFromDependencies(dependencies),
		postureReporter:            dependencies.PostureReporter,
		postureInterval:            config.PostureInterval,
		criticalInterval:           config.CriticalInterval,
		heartbeatInterval:          config.HeartbeatInterval,
		postureReportTimeout:       config.PostureReportTimeout,
		catalogClient:              dependencies.CatalogClient,
		dnsConfigurator:            dependencies.DNSConfigurator,
		catalogInterval:            config.CatalogInterval,
		catalogCacheTTL:            config.CatalogCacheTTL,
		catalogRetryBackoff:        append([]time.Duration(nil), config.CatalogRetryBackoff...),
		accessTokenExpirySkew:      config.AccessTokenExpirySkew,
		dnsServer:                  config.DNSServer,
		enrollmentRunner:           dependencies.EnrollmentRunner,
		enrollmentRenewer:          dependencies.EnrollmentRenewer,
		stateStore:                 stateStoreFromDependencies(dependencies),
		catalogCacheStore:          catalogCacheStoreFromDependencies(config, dependencies),
		certificateLoader:          certificateLoaderFromDependencies(dependencies),
		certificateRenewalInterval: config.CertificateRenewalInterval,
		certificateRenewBefore:     config.CertificateRenewBefore,
		certificateRenewalTimeout:  config.CertificateRenewalTimeout,
		clock:                      dependencies.Clock,
		rateLimiter:                enrollmentflow.NewRateLimiter(config.EnrollmentRateLimitMax, config.EnrollmentRateLimitWindow),
		enrollment: enrollmentState{
			State:         ipc.EnrollmentStateUnenrolled,
			ActiveUserSID: config.AuthorizedUserSID,
			KeyName:       deviceidentity.KeyNameForDevice(),
			Nonce:         randomNonce(),
		},
		posture: devicePostureState{Status: postureStatusUnknown},
		session: sessionState{State: sessionStatusMissing},
		catalog: deviceCatalogState{Status: catalogStatusWaitingForEnrollment},
	}
}

func identityProviderFromDependencies(config Config, dependencies Dependencies) deviceidentity.Provider {
	if dependencies.IdentityProvider != nil {
		return dependencies.IdentityProvider
	}
	return deviceidentity.NewProvider(deviceidentity.Options{AuthorizedUserSID: config.AuthorizedUserSID, Clock: dependencies.Clock})
}

func postureCollectorFromDependencies(dependencies Dependencies) DevicePostureCollector {
	if dependencies.PostureCollector != nil {
		return dependencies.PostureCollector
	}
	return deviceposture.NewCollector()
}

func stateStoreFromDependencies(dependencies Dependencies) servicestate.EnrollmentStore {
	if dependencies.StateStore != nil {
		return dependencies.StateStore
	}
	return servicestate.NewDefaultEnrollmentStore(dependencies.Clock)
}

func catalogCacheStoreFromDependencies(config Config, dependencies Dependencies) servicestate.CatalogCacheStore {
	if dependencies.CatalogCacheStore != nil || strings.TrimSpace(config.PAURL) == "" {
		return dependencies.CatalogCacheStore
	}
	return servicestate.NewDefaultCatalogCacheStore(dependencies.Clock)
}

func certificateLoaderFromDependencies(dependencies Dependencies) MachineCertificateLoader {
	if dependencies.CertificateLoader != nil {
		return dependencies.CertificateLoader
	}
	return deviceidentity.LoadMachineTLSCertificate
}
