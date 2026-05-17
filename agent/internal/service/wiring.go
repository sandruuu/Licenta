package service

import (
	"context"
	"crypto/tls"
	"strings"

	"agent/internal/service/deviceidentity"
	"agent/internal/service/dnscontrol"
	"agent/internal/service/dnsresolver"
	"agent/internal/service/enrollment"
	agentnetwork "agent/internal/service/network"
	"agent/internal/service/networking"
	"agent/internal/service/pa"
	"agent/internal/service/relay"
	"agent/internal/service/tunnel"
)

func (service *Service) configurePAClient(config Config, dependencies Dependencies) {
	if strings.TrimSpace(config.PAURL) == "" {
		return
	}
	if service.catalogClient != nil &&
		service.postureReporter != nil &&
		service.enrollmentValidator != nil &&
		service.enrollmentRunner != nil &&
		service.enrollmentRenewer != nil &&
		dependencies.ResourceAuthorizer != nil {
		return
	}
	client, err := pa.NewClient(pa.Config{
		PAURL:               config.PAURL,
		CAFile:              config.CAFile,
		ServerCertSHA256:    config.CloudCertSHA256,
		CertificateProvider: service.machineClientCertificate,
		AccessTokenProvider: service.gatewayAccessToken,
		Timeout:             config.PARequestTimeout,
	})
	if err != nil {
		service.logger.Warn("ZTNA Agent PA gRPC client disabled", "error", err)
		return
	}
	service.paClient = client
	if service.catalogClient == nil {
		service.catalogClient = client
	}
	if service.postureReporter == nil {
		service.postureReporter = client
	}
	if service.enrollmentValidator == nil {
		service.enrollmentValidator = client
	}
	if service.enrollmentRunner == nil {
		runner, err := enrollment.NewRunner(enrollment.RunnerConfig{
			Remote:      client,
			KeyProvider: deviceidentity.NewKeyStore(),
			Installer:   enrollment.NewDefaultCertificateInstaller(),
		})
		if err != nil {
			service.logger.Warn("ZTNA Agent gRPC enrollment runner disabled", "error", err)
		} else {
			service.enrollmentRunner = runner
			if service.enrollmentRenewer == nil {
				service.enrollmentRenewer = runner
			}
		}
	}
}

func (service *Service) configureDNS(config Config, dependencies Dependencies) {
	if service.dnsConfigurator == nil {
		service.dnsConfigurator = dnscontrol.NewManager()
	}
	service.syntheticResolver = dependencies.SyntheticResolver
	if service.syntheticResolver == nil {
		resolver, err := dnsresolver.New(dnsresolver.Options{Clock: dependencies.Clock})
		if err == nil {
			service.syntheticResolver = resolver
		} else {
			service.logger.Warn("ZTNA Agent synthetic DNS resolver disabled", "error", err)
		}
	}
	service.dnsResolverServer = dependencies.DNSResolverServer
	if service.dnsResolverServer != nil || service.syntheticResolver == nil || !service.shouldRunSyntheticDNSServer(config, dependencies) {
		return
	}
	server, err := dnsresolver.NewServer(dnsresolver.ServerOptions{ListenAddress: networking.DNSListenAddress(config.DNSServer), Resolver: service.syntheticResolver})
	if err != nil {
		service.logger.Warn("ZTNA Agent local DNS server disabled", "error", err)
		return
	}
	service.dnsResolverServer = server
}

func (service *Service) configureGatewayRelay(config Config, dependencies Dependencies) {
	if !service.shouldRunGatewayRelay(config) {
		return
	}
	resourceAuthorizer := service.resourceAuthorizerFromDependencies(dependencies)
	manager, err := tunnel.NewManager(tunnel.Options{
		Enabled:                   true,
		CAFile:                    config.CAFile,
		ClientCertificateProvider: service.gatewayClientCertificate,
		AccessTokenProvider:       service.gatewayAccessToken,
		Logger:                    dependencies.Logger,
	})
	if err != nil {
		service.logger.Warn("ZTNA Agent Gateway tunnel disabled", "error", err)
		return
	}
	service.gatewayTunnel = manager
	forwarder, err := relay.NewForwarder(relay.Options{
		StreamOpener:        manager,
		Authorizer:          resourceAuthorizer,
		ProcessIdentity:     config.ProcessIdentity,
		AccessEventRecorder: service.recordAccessEvent,
		UserSIDProvider:     service.currentUserSID,
		Clock:               dependencies.Clock,
		Logger:              dependencies.Logger,
	})
	if err != nil {
		service.logger.Warn("ZTNA Agent Gateway relay forwarder disabled", "error", err)
		return
	}
	service.relayForwarder = forwarder
}

func (service *Service) resourceAuthorizerFromDependencies(dependencies Dependencies) relay.ResourceAuthorizer {
	if dependencies.ResourceAuthorizer != nil {
		return dependencies.ResourceAuthorizer
	}
	return service.paClient
}

func (service *Service) configureNetworkManager(config Config, dependencies Dependencies) {
	service.networkManager = dependencies.NetworkManager
	if service.networkManager != nil || !config.TUNEnabled {
		return
	}
	manager, err := agentnetwork.NewManager(agentnetwork.Options{
		Enabled:       true,
		TUNName:       config.TUNName,
		TUNIP:         config.TUNIP,
		TUNNetmask:    config.TUNNetmask,
		TUNDNSServer:  networking.TUNDNSServer(config.DNSServer),
		CGNATCIDR:     config.TUNRouteCIDR,
		Resolver:      service.syntheticResolver,
		PacketHandler: service.relayForwarder,
		Clock:         dependencies.Clock,
	})
	if err != nil {
		service.logger.Warn("ZTNA Agent TUN network manager disabled", "error", err)
		return
	}
	service.networkManager = manager
}

func (service *Service) restoreStartupState() {
	service.refreshIdentitySnapshot(context.Background())
	service.restoreEnrollmentState(context.Background())
	service.restoreCatalogCache(context.Background())
}

func (service *Service) machineClientCertificate(ctx context.Context) (tls.Certificate, error) {
	service.mu.RLock()
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	keyName := strings.TrimSpace(service.enrollment.KeyName)
	keyProvider := strings.TrimSpace(service.enrollment.KeyProvider)
	service.mu.RUnlock()
	return service.certificateLoader(ctx, deviceidentity.MachineCertificateOptions{
		DeviceID:    deviceID,
		KeyName:     keyName,
		KeyProvider: keyProvider,
		Clock:       service.clock,
	})
}

func (service *Service) gatewayClientCertificate(ctx context.Context) (tls.Certificate, error) {
	return service.machineClientCertificate(ctx)
}

func (service *Service) gatewayAccessToken() (string, string) {
	service.mu.RLock()
	defer service.mu.RUnlock()
	deviceID := strings.TrimSpace(service.session.DeviceID)
	if deviceID == "" {
		deviceID = strings.TrimSpace(service.enrollment.DeviceID)
	}
	return service.session.AccessToken, deviceID
}

func (service *Service) currentUserSID() string {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if strings.TrimSpace(service.session.UserSID) != "" {
		return service.session.UserSID
	}
	return service.expectedUserSIDLocked()
}
