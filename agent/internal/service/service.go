package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"ztna.local/agent/internal/authz"
	"ztna.local/agent/internal/catalog"
	"ztna.local/agent/internal/deviceidentity"
	"ztna.local/agent/internal/deviceposture"
	"ztna.local/agent/internal/dnscontrol"
	"ztna.local/agent/internal/dnsresolver"
	"ztna.local/agent/internal/enrollment"
	"ztna.local/agent/internal/ipc"
	"ztna.local/agent/internal/jwtverify"
	agentnetwork "ztna.local/agent/internal/network"
	"ztna.local/agent/internal/process"
	"ztna.local/agent/internal/relay"
	"ztna.local/agent/internal/tunnel"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateDegraded State = "degraded"
	StateStopping State = "stopping"
)

type Options struct {
	AuthorizedUserSID          string
	CloudIssuer                string
	CloudURL                   string
	CloudCertSHA256            string
	JWKSURL                    string
	CAFile                     string
	Logger                     *slog.Logger
	ListenerFactory            func(string) (net.Listener, error)
	TokenValidator             EnrollmentTokenValidator
	IdentityProvider           deviceidentity.Provider
	PostureCollector           DevicePostureCollector
	PostureReporter            DevicePostureReporter
	PostureInterval            time.Duration
	CriticalInterval           time.Duration
	HeartbeatInterval          time.Duration
	CatalogClient              DeviceCatalogClient
	ResourceAuthorizer         relay.ResourceAuthorizer
	DNSConfigurator            DNSConfigurator
	SyntheticResolver          SyntheticResolver
	DNSResolverServer          DNSResolverServer
	NetworkManager             NetworkManager
	CatalogInterval            time.Duration
	DNSServer                  string
	TUNEnabled                 bool
	TUNName                    string
	TUNIP                      string
	TUNNetmask                 string
	TUNRouteCIDR               string
	GatewayTunnel              bool
	GatewayAddress             string
	GatewayServerName          string
	ProcessIdentity            bool
	EnrollmentRunner           EnrollmentRunner
	EnrollmentRenewer          EnrollmentRenewer
	StateStore                 EnrollmentStateStore
	CatalogCacheStore          CatalogCacheStore
	CertificateLoader          MachineCertificateLoader
	CertificateRenewalInterval time.Duration
	CertificateRenewBefore     time.Duration
	Clock                      func() time.Time
}

type EnrollmentTokenValidator interface {
	Validate(context.Context, string) (*jwtverify.Claims, error)
}

type EnrollmentRunner interface {
	Enroll(context.Context, enrollment.RunnerInput) (*enrollment.RunnerResult, error)
}

type EnrollmentRenewer interface {
	Renew(context.Context, enrollment.RenewalInput) (*enrollment.RunnerResult, error)
}

type DevicePostureCollector interface {
	Collect(context.Context, string) (ipc.DevicePostureReport, error)
}

type DevicePostureReporter interface {
	ReportDevicePosture(context.Context, ipc.DevicePostureReport) error
}

type DeviceHeartbeatReporter interface {
	SendHeartbeat(context.Context, string) error
}

type DeviceCatalogClient interface {
	GetCatalog(ctx context.Context, accessToken, currentVersion string) (catalog.Catalog, error)
}

type DNSConfigurator interface {
	Apply(context.Context, dnscontrol.Config) error
}

type SyntheticResolver interface {
	ApplyPolicy(dnsresolver.Policy) error
	Resolve(string) (dnsresolver.Mapping, error)
	Lookup(string) (dnsresolver.Mapping, bool)
	Status() dnsresolver.Status
}

type DNSResolverServer interface {
	Run(context.Context) error
}

type NetworkManager interface {
	Run(context.Context) error
	Status() agentnetwork.Status
}

type MachineCertificateLoader func(context.Context, deviceidentity.MachineCertificateOptions) (tls.Certificate, error)

type Service struct {
	mu                         sync.RWMutex
	logger                     *slog.Logger
	state                      State
	startedAt                  time.Time
	authorizedUserSID          string
	listenerFactory            func(string) (net.Listener, error)
	tokenValidator             EnrollmentTokenValidator
	identityProvider           deviceidentity.Provider
	postureCollector           DevicePostureCollector
	postureReporter            DevicePostureReporter
	postureInterval            time.Duration
	criticalInterval           time.Duration
	heartbeatInterval          time.Duration
	catalogClient              DeviceCatalogClient
	dnsConfigurator            DNSConfigurator
	syntheticResolver          SyntheticResolver
	dnsResolverServer          DNSResolverServer
	networkManager             NetworkManager
	gatewayTunnel              *tunnel.Manager
	relayForwarder             *relay.Forwarder
	catalogInterval            time.Duration
	dnsServer                  string
	enrollmentRunner           EnrollmentRunner
	enrollmentRenewer          EnrollmentRenewer
	stateStore                 EnrollmentStateStore
	catalogCacheStore          CatalogCacheStore
	certificateLoader          MachineCertificateLoader
	certificateRenewalInterval time.Duration
	certificateRenewBefore     time.Duration
	clock                      func() time.Time
	rateLimiter                *submissionRateLimiter
	enrollment                 enrollmentState
	session                    sessionState
	posture                    devicePostureState
	catalog                    deviceCatalogState
	accessEventHistory         []ipc.AccessEvent
}

type enrollmentState struct {
	State               ipc.EnrollmentState
	DeviceID            string
	DeviceIDSource      string
	ActiveUserSID       string
	KeyName             string
	KeyExists           bool
	KeyProvider         string
	Nonce               string
	CertificateSHA256   string
	CertificateNotAfter time.Time
	LastError           string
	IdentityError       string
	IdentityCheckedAt   time.Time
	LastAcceptedAt      time.Time
}

type sessionState struct {
	State         string
	AccessToken   string
	ExpiresAt     time.Time
	UserSID       string
	UserEmail     string
	DeviceID      string
	LastUpdatedAt time.Time
	LastError     string
}

type devicePostureState struct {
	Report          ipc.DevicePostureReport
	Status          string
	LastError       string
	LastReportError string
	LastCollectedAt time.Time
	LastReportedAt  time.Time
}

type deviceCatalogState struct {
	Status              string
	Version             string
	PolicyEpoch         string
	DNSSuffixes         []string
	Resources           []catalog.Resource
	TTLSeconds          int
	ExpiresAt           time.Time
	NextSyncAt          time.Time
	NextRetryAt         time.Time
	ConsecutiveFailures int
	LastError           string
	LastSyncedAt        time.Time
}

const (
	postureStatusUnknown              = "unknown"
	postureStatusCollected            = "collected"
	postureStatusCollectError         = "collect_error"
	postureStatusWaitingForEnrollment = "waiting_for_enrollment"
	postureStatusReported             = "reported"
	postureStatusReportError          = "report_error"
	sessionStatusMissing              = "missing"
	sessionStatusReady                = "ready"
	sessionStatusExpired              = "expired"
	sessionStatusRejected             = "rejected"
	catalogStatusWaitingForEnrollment = "waiting_for_enrollment"
	catalogStatusTokenRequired        = "token_required"
	catalogStatusReady                = "ready"
	catalogStatusStale                = "stale"
	catalogStatusError                = "error"
	defaultPostureReportInterval      = 5 * time.Minute
	defaultCriticalPostureInterval    = time.Minute
	defaultHeartbeatInterval          = time.Minute
	defaultCatalogSyncInterval        = 5 * time.Minute
	defaultCertificateRenewalInterval = time.Hour
	defaultCertificateRenewBefore     = 12 * time.Hour
	defaultCertificateRenewalTimeout  = 30 * time.Second
	defaultPostureReportTimeout       = 30 * time.Second
	defaultDNSServer                  = "127.0.0.1"
	defaultCatalogCacheTTL            = 5 * time.Minute
)

func New(options Options) *Service {
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	listenerFactory := options.ListenerFactory
	if listenerFactory == nil {
		listenerFactory = ipc.Listen
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	tokenValidator := options.TokenValidator
	if tokenValidator == nil && strings.TrimSpace(options.JWKSURL) != "" {
		validator, err := jwtverify.New(jwtverify.Options{Issuer: options.CloudIssuer, JWKSURL: options.JWKSURL, CAFile: options.CAFile, Clock: clock})
		if err == nil {
			tokenValidator = validator
		} else {
			logger.Warn("ZTNA Agent enrollment JWT validator disabled", "error", err)
		}
	}
	authorizedUserSID := strings.TrimSpace(options.AuthorizedUserSID)
	identityProvider := options.IdentityProvider
	if identityProvider == nil {
		identityProvider = deviceidentity.NewProvider(deviceidentity.Options{AuthorizedUserSID: authorizedUserSID, Clock: clock})
	}
	postureCollector := options.PostureCollector
	if postureCollector == nil {
		postureCollector = deviceposture.NewCollector()
	}
	postureInterval := options.PostureInterval
	if postureInterval <= 0 {
		postureInterval = defaultPostureReportInterval
	}
	criticalInterval := options.CriticalInterval
	if criticalInterval <= 0 {
		criticalInterval = defaultCriticalPostureInterval
	}
	heartbeatInterval := options.HeartbeatInterval
	if heartbeatInterval <= 0 {
		heartbeatInterval = defaultHeartbeatInterval
	}
	catalogInterval := options.CatalogInterval
	if catalogInterval <= 0 {
		catalogInterval = defaultCatalogSyncInterval
	}
	certificateRenewalInterval := options.CertificateRenewalInterval
	if certificateRenewalInterval <= 0 {
		certificateRenewalInterval = defaultCertificateRenewalInterval
	}
	certificateRenewBefore := options.CertificateRenewBefore
	if certificateRenewBefore <= 0 {
		certificateRenewBefore = defaultCertificateRenewBefore
	}
	dnsServer := strings.TrimSpace(options.DNSServer)
	if dnsServer == "" {
		dnsServer = defaultDNSServer
	}
	stateStore := options.StateStore
	if stateStore == nil {
		stateStore = newDefaultEnrollmentStateStore(clock)
	}
	catalogCacheStore := options.CatalogCacheStore
	if catalogCacheStore == nil && strings.TrimSpace(options.CloudURL) != "" {
		catalogCacheStore = newDefaultCatalogCacheStore(clock)
	}
	certificateLoader := options.CertificateLoader
	if certificateLoader == nil {
		certificateLoader = deviceidentity.LoadMachineTLSCertificate
	}
	enrollmentRunner := options.EnrollmentRunner
	if enrollmentRunner == nil && strings.TrimSpace(options.CloudURL) != "" {
		runner, err := enrollment.NewRunner(enrollment.RunnerConfig{
			CloudURL:        options.CloudURL,
			CAFile:          options.CAFile,
			CloudCertSHA256: options.CloudCertSHA256,
			KeyProvider:     deviceidentity.NewKeyStore(),
			Installer:       enrollment.NewDefaultCertificateInstaller(),
		})
		if err == nil {
			enrollmentRunner = runner
		} else {
			logger.Warn("ZTNA Agent EST enrollment runner disabled", "error", err)
		}
	}
	enrollmentRenewer := options.EnrollmentRenewer
	if enrollmentRenewer == nil {
		if renewer, ok := enrollmentRunner.(EnrollmentRenewer); ok {
			enrollmentRenewer = renewer
		}
	}
	service := &Service{
		logger:                     logger,
		state:                      StateStopped,
		authorizedUserSID:          authorizedUserSID,
		listenerFactory:            listenerFactory,
		tokenValidator:             tokenValidator,
		identityProvider:           identityProvider,
		postureCollector:           postureCollector,
		postureReporter:            options.PostureReporter,
		postureInterval:            postureInterval,
		criticalInterval:           criticalInterval,
		heartbeatInterval:          heartbeatInterval,
		catalogClient:              options.CatalogClient,
		dnsConfigurator:            options.DNSConfigurator,
		catalogInterval:            catalogInterval,
		dnsServer:                  dnsServer,
		enrollmentRunner:           enrollmentRunner,
		enrollmentRenewer:          enrollmentRenewer,
		stateStore:                 stateStore,
		catalogCacheStore:          catalogCacheStore,
		certificateLoader:          certificateLoader,
		certificateRenewalInterval: certificateRenewalInterval,
		certificateRenewBefore:     certificateRenewBefore,
		clock:                      clock,
		rateLimiter:                newSubmissionRateLimiter(3, time.Minute),
		enrollment: enrollmentState{
			State:         ipc.EnrollmentStateUnenrolled,
			ActiveUserSID: authorizedUserSID,
			KeyName:       deviceidentity.KeyNameForSID(authorizedUserSID),
			Nonce:         randomNonce(),
		},
		posture: devicePostureState{Status: postureStatusUnknown},
		session: sessionState{State: sessionStatusMissing},
		catalog: deviceCatalogState{Status: catalogStatusWaitingForEnrollment},
	}
	if service.catalogClient == nil && strings.TrimSpace(options.CloudURL) != "" {
		catalogClient, err := catalog.NewClient(catalog.Config{
			CloudURL:                  options.CloudURL,
			CAFile:                    options.CAFile,
			ClientCertificateProvider: service.catalogClientCertificate,
		})
		if err == nil {
			service.catalogClient = catalogClient
		} else {
			logger.Warn("ZTNA Agent catalog client disabled", "error", err)
		}
	}
	if service.dnsConfigurator == nil {
		service.dnsConfigurator = dnscontrol.NewManager()
	}
	service.syntheticResolver = options.SyntheticResolver
	if service.syntheticResolver == nil {
		resolver, err := dnsresolver.New(dnsresolver.Options{Clock: clock})
		if err == nil {
			service.syntheticResolver = resolver
		} else {
			logger.Warn("ZTNA Agent synthetic DNS resolver disabled", "error", err)
		}
	}
	service.dnsResolverServer = options.DNSResolverServer
	if service.dnsResolverServer == nil && service.syntheticResolver != nil && service.shouldRunSyntheticDNSServer(options) {
		server, err := dnsresolver.NewServer(dnsresolver.ServerOptions{ListenAddress: dnsListenAddress(dnsServer), Resolver: service.syntheticResolver})
		if err == nil {
			service.dnsResolverServer = server
		} else {
			logger.Warn("ZTNA Agent local DNS server disabled", "error", err)
		}
	}
	resourceAuthorizer := options.ResourceAuthorizer
	if resourceAuthorizer == nil && service.shouldRunGatewayTunnel(options) && strings.TrimSpace(options.CloudURL) != "" {
		authorizer, err := authz.NewClient(authz.Config{
			CloudURL:                  options.CloudURL,
			CAFile:                    options.CAFile,
			ClientCertificateProvider: service.authorizationClientCertificate,
			AccessTokenProvider:       service.gatewayAccessToken,
		})
		if err == nil {
			resourceAuthorizer = authorizer
		} else {
			logger.Warn("ZTNA Agent Cloud authorization client disabled", "error", err)
		}
	}
	if service.shouldRunGatewayTunnel(options) {
		manager, err := tunnel.NewManager(tunnel.Options{
			Enabled:                   true,
			GatewayAddress:            options.GatewayAddress,
			ServerName:                options.GatewayServerName,
			CAFile:                    options.CAFile,
			ClientCertificateProvider: service.gatewayClientCertificate,
			AccessTokenProvider:       service.gatewayAccessToken,
			Logger:                    logger,
		})
		if err == nil {
			service.gatewayTunnel = manager
			forwarder, forwarderErr := relay.NewForwarder(relay.Options{
				StreamOpener:        manager,
				Authorizer:          resourceAuthorizer,
				ProcessIdentity:     options.ProcessIdentity,
				AccessEventRecorder: service.recordAccessEvent,
				UserSIDProvider:     service.currentUserSID,
				Clock:               clock,
				Logger:              logger,
			})
			if forwarderErr == nil {
				service.relayForwarder = forwarder
			} else {
				logger.Warn("ZTNA Agent Gateway relay forwarder disabled", "error", forwarderErr)
			}
		} else {
			logger.Warn("ZTNA Agent Gateway tunnel disabled", "error", err)
		}
	}
	service.networkManager = options.NetworkManager
	if service.networkManager == nil && options.TUNEnabled {
		manager, err := agentnetwork.NewManager(agentnetwork.Options{
			Enabled:       true,
			TUNName:       options.TUNName,
			TUNIP:         options.TUNIP,
			TUNNetmask:    options.TUNNetmask,
			TUNDNSServer:  tunDNSServer(dnsServer),
			CGNATCIDR:     options.TUNRouteCIDR,
			Resolver:      service.syntheticResolver,
			PacketHandler: service.relayForwarder,
			Clock:         clock,
		})
		if err == nil {
			service.networkManager = manager
		} else {
			logger.Warn("ZTNA Agent TUN network manager disabled", "error", err)
		}
	}
	if service.postureReporter == nil && strings.TrimSpace(options.CloudURL) != "" {
		reporter, err := deviceposture.NewGRPCReporter(deviceposture.GRPCReporterConfig{
			CloudURL:                  options.CloudURL,
			CAFile:                    options.CAFile,
			ClientCertificateProvider: service.postureClientCertificate,
		})
		if err == nil {
			service.postureReporter = reporter
		} else {
			logger.Warn("ZTNA Agent gRPC posture reporter disabled", "error", err)
		}
	}
	service.refreshIdentitySnapshot(context.Background())
	service.restoreEnrollmentState(context.Background())
	service.restoreCatalogCache(context.Background())
	return service
}

func (service *Service) postureClientCertificate(ctx context.Context, report ipc.DevicePostureReport) (tls.Certificate, error) {
	service.mu.RLock()
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	keyName := strings.TrimSpace(service.enrollment.KeyName)
	keyProvider := strings.TrimSpace(service.enrollment.KeyProvider)
	service.mu.RUnlock()
	if strings.TrimSpace(report.DeviceID) != "" {
		deviceID = strings.TrimSpace(report.DeviceID)
	}
	return service.certificateLoader(ctx, deviceidentity.MachineCertificateOptions{
		DeviceID:    deviceID,
		KeyName:     keyName,
		KeyProvider: keyProvider,
		Clock:       service.clock,
	})
}

func (service *Service) catalogClientCertificate(ctx context.Context) (tls.Certificate, error) {
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

func (service *Service) authorizationClientCertificate(ctx context.Context) (tls.Certificate, error) {
	return service.catalogClientCertificate(ctx)
}

func (service *Service) gatewayClientCertificate(ctx context.Context) (tls.Certificate, error) {
	service.mu.RLock()
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	keyName := strings.TrimSpace(service.enrollment.KeyName)
	keyProvider := strings.TrimSpace(service.enrollment.KeyProvider)
	service.mu.RUnlock()
	return service.certificateLoader(ctx, deviceidentity.MachineCertificateOptions{DeviceID: deviceID, KeyName: keyName, KeyProvider: keyProvider, Clock: service.clock})
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
	return service.authorizedUserSID
}

func (service *Service) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	service.transition(StateStarting)
	service.setStartedAt(time.Now().UTC())

	listener, err := service.listenerFactory(service.AuthorizedUserSID())
	if err != nil {
		service.transition(StateDegraded)
		return fmt.Errorf("start IPC listener: %w", err)
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- ipc.Serve(ctx, listener, service)
	}()
	service.startSyntheticDNSServer(ctx)
	service.startGatewayTunnel(ctx)
	service.startNetworkManager(ctx)
	service.startPostureReporting(ctx)
	service.startCatalogSync(ctx)
	service.startCertificateRenewal(ctx)
	service.logger.Info("ZTNA Agent service running", "pipe", ipc.PipePath(), "protocol", ipc.ProtocolVersion, "authorized_user_sid", service.AuthorizedUserSID())
	service.transition(StateRunning)

	<-ctx.Done()
	service.transition(StateStopping)
	if service.relayForwarder != nil {
		service.relayForwarder.Close()
	}
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			service.transition(StateStopped)
			return err
		}
	case <-time.After(2 * time.Second):
		service.logger.Warn("ZTNA Agent IPC server did not stop before timeout")
	}
	service.transition(StateStopped)
	return nil
}

func (service *Service) shouldRunSyntheticDNSServer(options Options) bool {
	return strings.TrimSpace(options.CloudURL) != "" || options.CatalogClient != nil || options.CatalogCacheStore != nil
}

func (service *Service) shouldRunGatewayTunnel(options Options) bool {
	return options.GatewayTunnel || strings.TrimSpace(options.GatewayAddress) != ""
}

func (service *Service) startSyntheticDNSServer(ctx context.Context) {
	if service.dnsResolverServer == nil {
		return
	}
	go func() {
		if err := service.dnsResolverServer.Run(ctx); err != nil && ctx.Err() == nil {
			service.logger.Error("ZTNA Agent local DNS server stopped", "error", err)
			service.transition(StateDegraded)
		}
	}()
}

func (service *Service) startGatewayTunnel(ctx context.Context) {
	if service.gatewayTunnel == nil {
		return
	}
	go func() {
		if err := service.gatewayTunnel.Run(ctx); err != nil && ctx.Err() == nil {
			service.logger.Error("ZTNA Agent Gateway tunnel stopped", "error", err)
			service.transition(StateDegraded)
		}
	}()
}

func (service *Service) startNetworkManager(ctx context.Context) {
	if service.networkManager == nil {
		return
	}
	go func() {
		if err := service.networkManager.Run(ctx); err != nil && ctx.Err() == nil {
			service.logger.Error("ZTNA Agent TUN network manager stopped", "error", err)
			service.transition(StateDegraded)
		}
	}()
}

func dnsListenAddress(dnsServer string) string {
	value := strings.TrimSpace(dnsServer)
	if value == "" {
		return dnsresolver.DefaultListenAddress
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && strings.TrimSpace(port) != "" {
			return net.JoinHostPort(ip.String(), port)
		}
		return dnsresolver.DefaultListenAddress
	}
	if ip := net.ParseIP(value); ip != nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	return dnsresolver.DefaultListenAddress
}

func tunDNSServer(dnsServer string) string {
	value := strings.TrimSpace(dnsServer)
	if value == "" {
		return defaultDNSServer
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return ip.String()
		}
		return defaultDNSServer
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return defaultDNSServer
}

func (service *Service) HandleIPC(ctx context.Context, request *ipc.Request) (*ipc.Response, error) {
	if request == nil {
		return nil, errors.New("ipc request is nil")
	}
	switch request.Operation {
	case ipc.OperationPing:
		var payload ipc.PingRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.ping(payload))
	case ipc.OperationGetStatus:
		return ipc.NewResponse(request.ID, service.status())
	case ipc.OperationGetDashboard:
		var payload ipc.DashboardRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.dashboard(ctx))
	case ipc.OperationGetCatalogResources:
		var payload ipc.CatalogResourcesRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.catalogResourcesResponse())
	case ipc.OperationGetActiveSessions:
		var payload ipc.ActiveSessionsRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.activeSessionsResponse())
	case ipc.OperationGetAccessEvents:
		var payload ipc.AccessEventsRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.accessEventsResponse())
	case ipc.OperationGetDevicePosture:
		var payload ipc.DevicePostureRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		report, code, err := service.devicePosture(ctx)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, report)
	case ipc.OperationSubmitEnrollmentToken:
		var payload ipc.SubmitEnrollmentTokenRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		response, code, err := service.submitEnrollmentToken(ctx, payload)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, response)
	case ipc.OperationUpdateAccessToken:
		var payload ipc.UpdateAccessTokenRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		response, code, err := service.updateAccessToken(payload)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, response)
	default:
		return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeUnsupported, "unsupported IPC operation"), nil
	}
}

func (service *Service) ping(payload ipc.PingRequest) ipc.PingResponse {
	identity := process.Current()
	message := strings.TrimSpace(payload.Message)
	if message == "" {
		message = "ping"
	}
	return ipc.PingResponse{
		Message:           "pong from service",
		Echo:              message,
		Protocol:          ipc.ProtocolVersion,
		PipeName:          ipc.PipePath(),
		ServiceState:      string(service.State()),
		ServicePID:        identity.PID,
		ServiceUser:       identity.Username,
		ServiceUserSID:    identity.UserSID,
		AuthorizedUserSID: service.AuthorizedUserSID(),
		ReceivedAt:        time.Now().UTC(),
	}
}

func (service *Service) status() ipc.AgentStatus {
	service.refreshIdentitySnapshot(context.Background())
	identity := process.Current()
	service.mu.RLock()
	enrollment := service.enrollment
	session := service.session
	posture := service.posture
	catalogState := service.catalog
	serviceState := service.state
	authorizedUserSID := service.authorizedUserSID
	service.mu.RUnlock()
	syntheticStatus := dnsresolver.Status{State: dnsresolver.StatusWaiting}
	if service.syntheticResolver != nil {
		syntheticStatus = service.syntheticResolver.Status()
	}
	networkStatus := agentnetwork.Status{State: agentnetwork.StatusDisabled}
	if service.networkManager != nil {
		networkStatus = service.networkManager.Status()
	}
	gatewayStatus := tunnel.Status{State: tunnel.StatusDisabled}
	if service.gatewayTunnel != nil {
		gatewayStatus = service.gatewayTunnel.Status()
	}
	return ipc.AgentStatus{
		ServiceState:             string(serviceState),
		ServicePID:               identity.PID,
		ServiceUser:              identity.Username,
		ServiceUserSID:           identity.UserSID,
		AuthorizedUserSID:        authorizedUserSID,
		EnrollmentState:          enrollment.State,
		DeviceID:                 enrollment.DeviceID,
		DeviceIDSource:           enrollment.DeviceIDSource,
		ActiveUserSID:            enrollment.ActiveUserSID,
		KeyName:                  enrollment.KeyName,
		KeyExists:                enrollment.KeyExists,
		KeyProvider:              enrollment.KeyProvider,
		EnrollmentNonce:          enrollment.Nonce,
		CertificateSHA256:        enrollment.CertificateSHA256,
		CertificateExpiresAt:     enrollment.CertificateNotAfter,
		DevicePostureStatus:      posture.Status,
		DevicePostureCheckCount:  len(posture.Report.Checks),
		DevicePostureCollectedAt: posture.LastCollectedAt,
		DevicePostureReportedAt:  posture.LastReportedAt,
		DevicePostureLastError:   posture.LastError,
		DevicePostureReportError: posture.LastReportError,
		SessionState:             session.State,
		AccessTokenExpiresAt:     session.ExpiresAt,
		CatalogStatus:            catalogState.Status,
		CatalogVersion:           catalogState.Version,
		CatalogPolicyEpoch:       catalogState.PolicyEpoch,
		CatalogDNSSuffixCount:    len(catalogState.DNSSuffixes),
		CatalogResourceCount:     len(catalogState.Resources),
		CatalogLastSyncedAt:      catalogState.LastSyncedAt,
		CatalogNextSyncAt:        catalogState.NextSyncAt,
		CatalogNextRetryAt:       catalogState.NextRetryAt,
		CatalogLastError:         catalogState.LastError,
		SyntheticDNSStatus:       syntheticStatus.State,
		SyntheticDNSSuffixCount:  syntheticStatus.DNSSuffixCount,
		SyntheticResourceCount:   syntheticStatus.ResourceCount,
		SyntheticMappingCount:    syntheticStatus.ActiveMappingCount,
		SyntheticCGNATRange:      syntheticStatus.CGNATRange,
		SyntheticDNSUpdatedAt:    syntheticStatus.LastUpdatedAt,
		SyntheticDNSLastError:    syntheticStatus.LastError,
		NetworkStatus:            networkStatus.State,
		TUNName:                  networkStatus.TUNName,
		TUNIP:                    networkStatus.TUNIP,
		TUNNetmask:               networkStatus.TUNNetmask,
		TUNRouteCIDR:             networkStatus.CGNATRange,
		NetworkUpdatedAt:         networkStatus.UpdatedAt,
		NetworkPacketsRead:       networkStatus.PacketsRead,
		NetworkTCPPackets:        networkStatus.TCPPackets,
		NetworkMatchedPackets:    networkStatus.MatchedPackets,
		NetworkUnmatchedPackets:  networkStatus.UnmatchedPackets,
		NetworkDroppedPackets:    networkStatus.DroppedPackets,
		NetworkForwarderReady:    networkStatus.ForwarderConfigured,
		NetworkLastPacketAt:      networkStatus.LastPacketAt,
		NetworkLastPacketError:   networkStatus.LastPacketError,
		NetworkLastError:         networkStatus.LastError,
		GatewayTunnelStatus:      gatewayStatus.State,
		GatewayAddress:           gatewayStatus.GatewayAddress,
		GatewayTunnelConnectedAt: gatewayStatus.ConnectedAt,
		GatewayTunnelUpdatedAt:   gatewayStatus.UpdatedAt,
		GatewayTunnelLastError:   gatewayStatus.LastError,
		GatewayTunnelStreamCount: gatewayStatus.StreamCount,
		LastError:                enrollment.LastError,
		IdentityError:            enrollment.IdentityError,
		IdentityCheckedAt:        enrollment.IdentityCheckedAt,
		ReportedAt:               service.clock().UTC(),
	}
}

func (service *Service) startPostureReporting(ctx context.Context) {
	if service.postureReporter == nil {
		return
	}
	go service.runPostureReporting(ctx)
}

func (service *Service) runPostureReporting(ctx context.Context) {
	reportTicker := time.NewTicker(service.postureInterval)
	defer reportTicker.Stop()
	criticalTicker := time.NewTicker(service.criticalInterval)
	defer criticalTicker.Stop()
	heartbeatTicker := time.NewTicker(service.heartbeatInterval)
	defer heartbeatTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reportTicker.C:
			_, _ = service.reportPostureIfReady(ctx, "periodic")
		case <-criticalTicker.C:
			_, _ = service.reportCriticalPostureIfChanged(ctx)
		case <-heartbeatTicker.C:
			_ = service.sendHeartbeatIfReady(ctx)
		}
	}
}

func (service *Service) startCatalogSync(ctx context.Context) {
	if service.catalogClient == nil || service.dnsConfigurator == nil {
		return
	}
	go service.runCatalogSync(ctx)
}

func (service *Service) runCatalogSync(ctx context.Context) {
	ticker := time.NewTicker(service.catalogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = service.syncDeviceCatalogIfReady(ctx)
		}
	}
}

func (service *Service) startCertificateRenewal(ctx context.Context) {
	if service.enrollmentRenewer == nil {
		return
	}
	go service.runCertificateRenewal(ctx)
}

func (service *Service) runCertificateRenewal(ctx context.Context) {
	_, _ = service.renewCertificateIfNeeded(ctx, "startup")
	ticker := time.NewTicker(service.certificateRenewalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = service.renewCertificateIfNeeded(ctx, "periodic")
		}
	}
}

func (service *Service) renewCertificateIfNeeded(ctx context.Context, reason string) (bool, error) {
	if service.enrollmentRenewer == nil {
		return false, nil
	}
	service.mu.RLock()
	ready := service.enrollment.State == ipc.EnrollmentStateEnrolled && strings.TrimSpace(service.enrollment.DeviceID) != "" && strings.TrimSpace(service.enrollment.KeyName) != ""
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	keyName := strings.TrimSpace(service.enrollment.KeyName)
	keyProvider := strings.TrimSpace(service.enrollment.KeyProvider)
	service.mu.RUnlock()
	if !ready {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCertificateRenewalTimeout)
		defer cancel()
	}
	certificate, err := service.certificateLoader(ctx, deviceidentity.MachineCertificateOptions{
		DeviceID:    deviceID,
		KeyName:     keyName,
		KeyProvider: keyProvider,
		Clock:       service.clock,
	})
	if err != nil {
		service.setEnrollmentLastError("certificate renewal check: " + err.Error())
		return false, err
	}
	certificateNotAfter, err := tlsCertificateNotAfter(certificate)
	if err != nil {
		service.setEnrollmentLastError("certificate renewal check: " + err.Error())
		return false, err
	}
	service.mu.Lock()
	service.enrollment.CertificateNotAfter = certificateNotAfter
	service.mu.Unlock()
	if !certificateNeedsRenewal(certificateNotAfter, service.clock().UTC(), service.certificateRenewBefore) {
		return false, nil
	}
	result, err := service.enrollmentRenewer.Renew(ctx, enrollment.RenewalInput{
		DeviceID:           deviceID,
		KeyName:            keyName,
		KeyProvider:        firstNonEmptyString(keyProvider, deviceidentity.MicrosoftPlatformCryptoProvider),
		CurrentCertificate: certificate,
	})
	if err != nil {
		service.setEnrollmentLastError("renew endpoint certificate: " + err.Error())
		service.logger.Warn("Endpoint certificate renewal failed", "device_id", deviceID, "reason", reason, "error", err)
		return false, err
	}
	if result == nil {
		err := errors.New("certificate renewal returned no result")
		service.setEnrollmentLastError("renew endpoint certificate: " + err.Error())
		return false, err
	}
	if strings.TrimSpace(result.CertificateSHA256) == "" {
		err := errors.New("certificate renewal returned no certificate fingerprint")
		service.setEnrollmentLastError("renew endpoint certificate: " + err.Error())
		return false, err
	}
	service.mu.Lock()
	service.enrollment.CertificateSHA256 = strings.TrimSpace(result.CertificateSHA256)
	service.enrollment.CertificateNotAfter = result.CertificateNotAfter
	service.enrollment.KeyExists = true
	service.enrollment.LastError = ""
	service.mu.Unlock()
	service.persistEnrollmentState(ctx)
	service.logger.Info("Endpoint certificate renewed", "device_id", deviceID, "reason", reason, "certificate_sha256", result.CertificateSHA256, "expires", result.CertificateNotAfter.Format(time.RFC3339))
	return true, nil
}

func certificateNeedsRenewal(notAfter, now time.Time, renewBefore time.Duration) bool {
	if notAfter.IsZero() {
		return false
	}
	if renewBefore <= 0 {
		renewBefore = defaultCertificateRenewBefore
	}
	return !notAfter.After(now.Add(renewBefore))
}

func (service *Service) syncDeviceCatalogIfReady(ctx context.Context) (bool, error) {
	if service.catalogClient == nil || service.dnsConfigurator == nil {
		return false, nil
	}
	now := service.clock().UTC()
	service.mu.RLock()
	enrolled := service.enrollment.State == ipc.EnrollmentStateEnrolled && strings.TrimSpace(service.enrollment.DeviceID) != ""
	accessToken := strings.TrimSpace(service.session.AccessToken)
	tokenExpiresAt := service.session.ExpiresAt
	currentVersion := strings.TrimSpace(service.catalog.Version)
	nextSyncAt := service.catalog.NextSyncAt
	nextRetryAt := service.catalog.NextRetryAt
	service.mu.RUnlock()
	if !enrolled {
		service.markCatalogWaitingForEnrollment()
		return false, nil
	}
	if accessToken == "" {
		service.markCatalogTokenRequired("access token is required")
		return false, nil
	}
	if !tokenExpiresAt.IsZero() && !tokenExpiresAt.After(now.Add(30*time.Second)) {
		service.markSessionExpired("access token is expired or near expiry")
		service.markCatalogTokenRequired("access token is expired or near expiry")
		return false, nil
	}
	if !nextRetryAt.IsZero() && now.Before(nextRetryAt) {
		return false, nil
	}
	if !nextSyncAt.IsZero() && now.Before(nextSyncAt) {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultPostureReportTimeout)
		defer cancel()
	}
	catalogSnapshot, err := service.catalogClient.GetCatalog(ctx, accessToken, currentVersion)
	if err != nil {
		service.cacheCatalogError(err)
		return false, err
	}
	if catalogSnapshot.NotModified {
		service.markCatalogSynced(catalogSnapshot)
		service.persistCatalogCache(ctx)
		return false, nil
	}
	if err := service.dnsConfigurator.Apply(ctx, dnscontrol.Config{DNSSuffixes: catalogSnapshot.DNSSuffixes, DNSServer: service.dnsServer, HardenDoH: true}); err != nil {
		service.cacheCatalogError(err)
		return false, err
	}
	if err := service.applySyntheticCatalog(catalogSnapshot); err != nil {
		service.cacheCatalogError(err)
		return false, err
	}
	service.cacheCatalog(catalogSnapshot)
	service.persistCatalogCache(ctx)
	service.logger.Info("Device catalog applied", "suffix_count", len(catalogSnapshot.DNSSuffixes), "version", catalogSnapshot.Version)
	return true, nil
}

func (service *Service) cacheCatalog(catalogSnapshot catalog.Catalog) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.catalog.Version = strings.TrimSpace(catalogSnapshot.Version)
	service.catalog.PolicyEpoch = strings.TrimSpace(catalogSnapshot.PolicyEpoch)
	service.catalog.DNSSuffixes = append([]string(nil), catalogSnapshot.DNSSuffixes...)
	service.catalog.Resources = append([]catalog.Resource(nil), catalogSnapshot.Resources...)
	service.catalog.TTLSeconds = catalogSnapshot.TTLSeconds
	service.catalog.ExpiresAt = service.catalogExpiresAt(catalogSnapshot.TTLSeconds)
	service.catalog.NextSyncAt = service.catalogNextSyncAt(catalogSnapshot.TTLSeconds)
	service.catalog.NextRetryAt = time.Time{}
	service.catalog.ConsecutiveFailures = 0
	service.catalog.Status = catalogStatusReady
	service.catalog.LastError = ""
	service.catalog.LastSyncedAt = service.clock().UTC()
}

func (service *Service) applySyntheticCatalog(catalogSnapshot catalog.Catalog) error {
	if service.syntheticResolver == nil {
		return nil
	}
	resources := make([]dnsresolver.Resource, 0, len(catalogSnapshot.Resources))
	for _, resource := range catalogSnapshot.Resources {
		resources = append(resources, dnsresolver.Resource{
			FQDN:       resource.FQDN,
			ResourceID: resource.ResourceID,
			Protocol:   resource.Protocol,
			Port:       resource.Port,
		})
	}
	return service.syntheticResolver.ApplyPolicy(dnsresolver.Policy{
		Version:     strings.TrimSpace(catalogSnapshot.Version),
		PolicyEpoch: strings.TrimSpace(catalogSnapshot.PolicyEpoch),
		DNSSuffixes: append([]string(nil), catalogSnapshot.DNSSuffixes...),
		Resources:   resources,
		TTLSeconds:  catalogSnapshot.TTLSeconds,
	})
}

func (service *Service) markCatalogSynced(catalogSnapshot catalog.Catalog) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if catalogSnapshot.TTLSeconds > 0 {
		service.catalog.TTLSeconds = catalogSnapshot.TTLSeconds
	}
	service.catalog.ExpiresAt = service.catalogExpiresAt(service.catalog.TTLSeconds)
	service.catalog.NextSyncAt = service.catalogNextSyncAt(service.catalog.TTLSeconds)
	service.catalog.NextRetryAt = time.Time{}
	service.catalog.ConsecutiveFailures = 0
	service.catalog.Status = catalogStatusReady
	service.catalog.LastError = ""
	service.catalog.LastSyncedAt = service.clock().UTC()
}

func (service *Service) cacheCatalogError(err error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err != nil {
		service.catalog.LastError = err.Error()
	}
	if isCatalogTokenError(err) {
		service.catalog.Status = catalogStatusTokenRequired
		service.catalog.NextRetryAt = time.Time{}
		return
	}
	service.catalog.Status = catalogStatusError
	service.catalog.ConsecutiveFailures++
	service.catalog.NextRetryAt = service.clock().UTC().Add(catalogBackoff(service.catalog.ConsecutiveFailures))
}

func (service *Service) markCatalogWaitingForEnrollment() {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.catalog.Status = catalogStatusWaitingForEnrollment
	service.catalog.NextRetryAt = time.Time{}
}

func (service *Service) markCatalogTokenRequired(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.catalog.Status = catalogStatusTokenRequired
	service.catalog.LastError = strings.TrimSpace(message)
	service.catalog.NextRetryAt = time.Time{}
}

func (service *Service) catalogExpiresAt(ttlSeconds int) time.Time {
	if ttlSeconds <= 0 {
		return service.clock().UTC().Add(defaultCatalogCacheTTL)
	}
	return service.clock().UTC().Add(time.Duration(ttlSeconds) * time.Second)
}

func (service *Service) catalogNextSyncAt(ttlSeconds int) time.Time {
	if ttlSeconds <= 0 {
		return service.clock().UTC().Add(service.catalogInterval)
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl > service.catalogInterval {
		ttl = service.catalogInterval
	}
	if ttl <= 0 {
		ttl = defaultCatalogCacheTTL
	}
	return service.clock().UTC().Add(ttl)
}

func catalogBackoff(failures int) time.Duration {
	switch {
	case failures <= 1:
		return 5 * time.Minute
	case failures == 2:
		return 10 * time.Minute
	case failures == 3:
		return 15 * time.Minute
	default:
		return 30 * time.Minute
	}
}

func isCatalogTokenError(err error) bool {
	if err == nil {
		return false
	}
	code := status.Code(err)
	if code == codes.Unauthenticated || code == codes.PermissionDenied {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unauthenticated") || strings.Contains(message, "permissiondenied") || strings.Contains(message, "permission denied")
}

func (service *Service) persistedCatalogSnapshot() (persistedCatalogCache, bool) {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.enrollment.State != ipc.EnrollmentStateEnrolled || strings.TrimSpace(service.enrollment.DeviceID) == "" {
		return persistedCatalogCache{}, false
	}
	if strings.TrimSpace(service.catalog.Version) == "" || len(service.catalog.DNSSuffixes) == 0 {
		return persistedCatalogCache{}, false
	}
	fetchedAt := service.catalog.LastSyncedAt
	if fetchedAt.IsZero() {
		fetchedAt = service.clock().UTC()
	}
	cache := persistedCatalogCache{
		Version:        catalogCacheFileVersion,
		DeviceID:       strings.TrimSpace(service.enrollment.DeviceID),
		CatalogVersion: strings.TrimSpace(service.catalog.Version),
		PolicyEpoch:    strings.TrimSpace(service.catalog.PolicyEpoch),
		DNSSuffixes:    append([]string(nil), service.catalog.DNSSuffixes...),
		Resources:      append([]catalog.Resource(nil), service.catalog.Resources...),
		TTLSeconds:     service.catalog.TTLSeconds,
		FetchedAt:      fetchedAt,
		ExpiresAt:      service.catalog.ExpiresAt,
	}
	return cache, cache.validate() == nil
}

func (service *Service) persistCatalogCache(ctx context.Context) {
	if service.catalogCacheStore == nil {
		return
	}
	cache, ok := service.persistedCatalogSnapshot()
	if !ok {
		return
	}
	if err := service.catalogCacheStore.Save(ctx, cache); err != nil {
		service.cacheCatalogError(fmt.Errorf("persist catalog cache: %w", err))
		service.logger.Warn("Failed to persist ZTNA Agent catalog cache", "error", err)
	}
}

func (service *Service) restoreCatalogCache(ctx context.Context) {
	if service.catalogCacheStore == nil || service.dnsConfigurator == nil {
		return
	}
	service.mu.RLock()
	enrolled := service.enrollment.State == ipc.EnrollmentStateEnrolled
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	service.mu.RUnlock()
	if !enrolled || deviceID == "" {
		return
	}
	cache, err := service.catalogCacheStore.Load(ctx)
	if errors.Is(err, ErrCatalogCacheNotFound) {
		return
	}
	if err != nil {
		service.cacheCatalogError(fmt.Errorf("load catalog cache: %w", err))
		service.logger.Warn("Failed to load ZTNA Agent catalog cache", "error", err)
		return
	}
	if strings.TrimSpace(cache.DeviceID) != deviceID {
		service.logger.Warn("Ignoring ZTNA Agent catalog cache for different device", "cache_device_id", cache.DeviceID, "device_id", deviceID)
		return
	}
	if err := service.dnsConfigurator.Apply(ctx, dnscontrol.Config{DNSSuffixes: cache.DNSSuffixes, DNSServer: service.dnsServer, HardenDoH: true}); err != nil {
		service.cacheCatalogError(fmt.Errorf("apply cached catalog DNS: %w", err))
		service.logger.Warn("Failed to apply cached ZTNA Agent catalog", "error", err)
		return
	}
	if err := service.applySyntheticCatalog(catalog.Catalog{Version: cache.CatalogVersion, PolicyEpoch: cache.PolicyEpoch, DNSSuffixes: cache.DNSSuffixes, Resources: cache.Resources, TTLSeconds: cache.TTLSeconds}); err != nil {
		service.cacheCatalogError(fmt.Errorf("apply cached synthetic DNS catalog: %w", err))
		service.logger.Warn("Failed to apply cached ZTNA Agent synthetic DNS catalog", "error", err)
		return
	}
	now := service.clock().UTC()
	statusValue := catalogStatusReady
	if !cache.ExpiresAt.IsZero() && !cache.ExpiresAt.After(now) {
		statusValue = catalogStatusStale
	}
	service.mu.Lock()
	service.catalog.Status = statusValue
	service.catalog.Version = strings.TrimSpace(cache.CatalogVersion)
	service.catalog.PolicyEpoch = strings.TrimSpace(cache.PolicyEpoch)
	service.catalog.DNSSuffixes = append([]string(nil), cache.DNSSuffixes...)
	service.catalog.Resources = append([]catalog.Resource(nil), cache.Resources...)
	service.catalog.TTLSeconds = cache.TTLSeconds
	service.catalog.ExpiresAt = cache.ExpiresAt
	service.catalog.NextSyncAt = time.Time{}
	service.catalog.NextRetryAt = time.Time{}
	service.catalog.ConsecutiveFailures = 0
	service.catalog.LastError = ""
	service.catalog.LastSyncedAt = cache.FetchedAt
	service.mu.Unlock()
	service.logger.Info("ZTNA Agent catalog cache restored", "device_id", deviceID, "suffix_count", len(cache.DNSSuffixes), "version", cache.CatalogVersion, "status", statusValue)
}

func (service *Service) setAccessToken(accessToken string, expiresAt time.Time, userSID, deviceID string, updatedAt time.Time) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.session.State = sessionStatusReady
	service.session.AccessToken = strings.TrimSpace(accessToken)
	service.session.ExpiresAt = expiresAt
	service.session.UserSID = strings.TrimSpace(userSID)
	service.session.DeviceID = strings.TrimSpace(deviceID)
	service.session.LastUpdatedAt = updatedAt.UTC()
	service.session.LastError = ""
	if service.catalog.Status == catalogStatusTokenRequired {
		service.catalog.LastError = ""
		service.catalog.NextRetryAt = time.Time{}
	}
}

func (service *Service) markSessionExpired(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.session.State = sessionStatusExpired
	service.session.LastError = strings.TrimSpace(message)
	service.appendAccessEventLocked(ipc.AccessEvent{Decision: "deny", Reason: service.session.LastError, Source: "local_session"})
}

func (service *Service) markSessionRejected(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.session.State = sessionStatusRejected
	service.session.LastError = strings.TrimSpace(message)
	service.appendAccessEventLocked(ipc.AccessEvent{Decision: "deny", Reason: service.session.LastError, Source: "local_session"})
}

func (service *Service) sendHeartbeatIfReady(ctx context.Context) error {
	reporter, ok := service.postureReporter.(DeviceHeartbeatReporter)
	if !ok || reporter == nil {
		return nil
	}
	if !service.postureReportingReady() {
		service.setPostureStatus(postureStatusWaitingForEnrollment, "")
		return nil
	}
	service.mu.RLock()
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	service.mu.RUnlock()
	if deviceID == "" {
		return nil
	}
	if err := reporter.SendHeartbeat(ctx, deviceID); err != nil {
		service.mu.Lock()
		service.posture.LastReportError = err.Error()
		service.mu.Unlock()
		return err
	}
	return nil
}

func (service *Service) reportPostureIfReady(ctx context.Context, reason string) (bool, error) {
	if service.postureReporter == nil {
		return false, nil
	}
	if !service.postureReportingReady() {
		service.setPostureStatus(postureStatusWaitingForEnrollment, "")
		return false, nil
	}
	report, err := service.collectDevicePosture(ctx)
	if err != nil {
		return false, err
	}
	return service.sendPostureReport(ctx, report, reason)
}

func (service *Service) reportCriticalPostureIfChanged(ctx context.Context) (bool, error) {
	if service.postureReporter == nil {
		return false, nil
	}
	if !service.postureReportingReady() {
		service.setPostureStatus(postureStatusWaitingForEnrollment, "")
		return false, nil
	}
	previous := service.cachedPostureReport()
	report, err := service.collectDevicePosture(ctx)
	if err != nil {
		return false, err
	}
	if !hasNewCriticalPosture(previous, report) {
		return false, nil
	}
	return service.sendPostureReport(ctx, report, "critical_change")
}

func (service *Service) collectDevicePosture(ctx context.Context) (ipc.DevicePostureReport, error) {
	service.mu.RLock()
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	service.mu.RUnlock()
	report, err := service.postureCollector.Collect(ctx, deviceID)
	service.cachePostureReport(report, err)
	if err != nil {
		return ipc.DevicePostureReport{}, err
	}
	return report, nil
}

func (service *Service) cachePostureReport(report ipc.DevicePostureReport, err error) {
	now := service.clock().UTC()
	service.mu.Lock()
	defer service.mu.Unlock()
	if err != nil {
		service.posture.Status = postureStatusCollectError
		service.posture.LastError = err.Error()
		return
	}
	service.posture.Report = report
	service.posture.Status = postureStatusCollected
	service.posture.LastError = ""
	if !report.CollectedAt.IsZero() {
		service.posture.LastCollectedAt = report.CollectedAt.UTC()
	} else {
		service.posture.LastCollectedAt = now
	}
}

func (service *Service) sendPostureReport(ctx context.Context, report ipc.DevicePostureReport, reason string) (bool, error) {
	if service.postureReporter == nil {
		return false, nil
	}
	if strings.TrimSpace(report.DeviceID) == "" {
		return false, errors.New("device_id is required for posture reporting")
	}
	if err := service.postureReporter.ReportDevicePosture(ctx, report); err != nil {
		service.mu.Lock()
		service.posture.Status = postureStatusReportError
		service.posture.LastReportError = err.Error()
		service.mu.Unlock()
		return false, err
	}
	service.mu.Lock()
	service.posture.Status = postureStatusReported
	service.posture.LastReportError = ""
	service.posture.LastReportedAt = service.clock().UTC()
	service.mu.Unlock()
	service.logger.Info("Device posture reported", "device_id", report.DeviceID, "checks", len(report.Checks), "reason", reason)
	return true, nil
}

func (service *Service) cachedPostureReport() ipc.DevicePostureReport {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return clonePostureReport(service.posture.Report)
}

func (service *Service) postureReportingReady() bool {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.enrollment.State == ipc.EnrollmentStateEnrolled && strings.TrimSpace(service.enrollment.DeviceID) != ""
}

func (service *Service) setPostureStatus(status, lastError string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.posture.Status = status
	service.posture.LastError = strings.TrimSpace(lastError)
}

func clonePostureReport(report ipc.DevicePostureReport) ipc.DevicePostureReport {
	clone := report
	if report.Checks != nil {
		clone.Checks = make([]ipc.DevicePostureCheck, len(report.Checks))
		for index, check := range report.Checks {
			clone.Checks[index] = check
			if check.Details != nil {
				clone.Checks[index].Details = make(map[string]string, len(check.Details))
				for key, value := range check.Details {
					clone.Checks[index].Details[key] = value
				}
			}
		}
	}
	return clone
}

func hasNewCriticalPosture(previous, current ipc.DevicePostureReport) bool {
	previousStatuses := make(map[string]string, len(previous.Checks))
	for _, check := range previous.Checks {
		previousStatuses[strings.ToLower(strings.TrimSpace(check.Name))] = strings.ToLower(strings.TrimSpace(check.Status))
	}
	for _, check := range current.Checks {
		name := strings.ToLower(strings.TrimSpace(check.Name))
		if name != "firewall" && name != "antivirus" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(check.Status))
		if status == ipc.DevicePostureStatusCritical && previousStatuses[name] != ipc.DevicePostureStatusCritical {
			return true
		}
	}
	return false
}

func (service *Service) devicePosture(ctx context.Context) (ipc.DevicePostureReport, string, error) {
	if service.postureCollector == nil {
		return ipc.DevicePostureReport{}, ipc.ErrorCodeServiceUnavailable, errors.New("device posture collector is not configured")
	}
	report, err := service.collectDevicePosture(ctx)
	if err != nil {
		return ipc.DevicePostureReport{}, ipc.ErrorCodeInternal, err
	}
	return report, "", nil
}

func (service *Service) updateAccessToken(payload ipc.UpdateAccessTokenRequest) (ipc.UpdateAccessTokenResponse, string, error) {
	now := service.clock().UTC()
	if err := validateAccessTokenUpdate(payload, now); err != nil {
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	userSID := strings.TrimSpace(payload.UserSID)
	deviceID := strings.TrimSpace(payload.DeviceID)
	service.mu.RLock()
	expectedSID := strings.TrimSpace(service.authorizedUserSID)
	expectedDeviceID := strings.TrimSpace(service.enrollment.DeviceID)
	enrolled := service.enrollment.State == ipc.EnrollmentStateEnrolled || service.enrollment.State == ipc.EnrollmentStatePending
	service.mu.RUnlock()
	if expectedSID != "" && userSID != expectedSID {
		err := errors.New("user_sid does not match authorized user")
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	if expectedDeviceID != "" && deviceID != expectedDeviceID {
		err := errors.New("device_id does not match service state")
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	if !enrolled {
		err := errors.New("service is not enrolled")
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeServiceUnavailable, err
	}
	service.setAccessToken(strings.TrimSpace(payload.AccessToken), payload.ExpiresAt.UTC(), userSID, deviceID, now)
	service.triggerCatalogSyncAfterEnrollment()
	return ipc.UpdateAccessTokenResponse{Accepted: true, DeviceID: deviceID, UserSID: userSID, ExpiresAt: payload.ExpiresAt.UTC(), ReceivedAt: now}, "", nil
}

func (service *Service) submitEnrollmentToken(ctx context.Context, payload ipc.SubmitEnrollmentTokenRequest) (ipc.SubmitEnrollmentTokenResponse, string, error) {
	service.refreshIdentitySnapshot(ctx)
	now := service.clock().UTC()
	userSID := strings.TrimSpace(payload.UserSID)
	if userSID == "" {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("user_sid is required")
	}
	if !service.rateLimiter.allow(userSID, now) {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeRateLimited, errors.New("too many enrollment token submissions")
	}
	if service.tokenValidator == nil {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeServiceUnavailable, errors.New("enrollment JWT validator is not configured")
	}
	if err := validateSubmissionShape(payload, now); err != nil {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	service.mu.RLock()
	expectedSID := strings.TrimSpace(service.authorizedUserSID)
	expectedKeyName := service.enrollment.KeyName
	expectedNonce := service.enrollment.Nonce
	expectedDeviceID := service.enrollment.DeviceID
	service.mu.RUnlock()
	if expectedSID != "" && userSID != expectedSID {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("user_sid does not match authorized user")
	}
	if expectedKeyName != "" && strings.TrimSpace(payload.KeyName) != expectedKeyName {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("key_name does not match service state")
	}
	if expectedNonce != "" && strings.TrimSpace(payload.Nonce) != expectedNonce {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("nonce does not match service state")
	}
	if expectedDeviceID != "" && strings.TrimSpace(payload.DeviceID) != expectedDeviceID {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("device_id does not match service state")
	}
	claims, err := service.tokenValidator.Validate(ctx, payload.Token)
	if err != nil {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, fmt.Errorf("validate enrollment token: %w", err)
	}
	if claims.DeviceID != strings.TrimSpace(payload.DeviceID) {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("device_id does not match enrollment token")
	}
	if claims.Nonce != strings.TrimSpace(payload.Nonce) {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("nonce does not match enrollment token")
	}
	if claims.UserSID != "" && claims.UserSID != userSID {
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("user_sid does not match enrollment token")
	}
	service.mu.Lock()
	service.enrollment.State = ipc.EnrollmentStatePending
	service.enrollment.DeviceID = strings.TrimSpace(payload.DeviceID)
	service.enrollment.ActiveUserSID = userSID
	service.enrollment.KeyName = strings.TrimSpace(payload.KeyName)
	service.enrollment.LastError = ""
	service.enrollment.LastAcceptedAt = now
	service.mu.Unlock()
	if strings.TrimSpace(payload.AccessToken) != "" {
		service.setAccessToken(strings.TrimSpace(payload.AccessToken), payload.AccessTokenExpiresAt.UTC(), userSID, strings.TrimSpace(payload.DeviceID), now)
	}
	service.setSessionUserEmail(strings.TrimSpace(payload.UserEmail))
	service.logger.Info("Enrollment token accepted", "device_id", strings.TrimSpace(payload.DeviceID), "user_sid", userSID, "key_name", strings.TrimSpace(payload.KeyName))
	if service.enrollmentRunner == nil {
		return ipc.SubmitEnrollmentTokenResponse{
			Accepted:        true,
			Message:         "enrollment token accepted for TPM enrollment",
			DeviceID:        strings.TrimSpace(payload.DeviceID),
			ActiveUserSID:   userSID,
			KeyName:         strings.TrimSpace(payload.KeyName),
			ReceivedAt:      now,
			EnrollmentState: ipc.EnrollmentStatePending,
		}, "", nil
	}
	result, err := service.enrollmentRunner.Enroll(ctx, enrollment.RunnerInput{
		Token:       payload.Token,
		Nonce:       strings.TrimSpace(payload.Nonce),
		DeviceID:    strings.TrimSpace(payload.DeviceID),
		KeyName:     strings.TrimSpace(payload.KeyName),
		KeyProvider: expectedEnrollmentKeyProvider(service),
		UserEmail:   strings.TrimSpace(payload.UserEmail),
	})
	if err != nil {
		service.markEnrollmentFailed(err)
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInternal, fmt.Errorf("perform TPM/EST enrollment: %w", err)
	}
	if result == nil {
		err := errors.New("enrollment runner returned no result")
		service.markEnrollmentFailed(err)
		return ipc.SubmitEnrollmentTokenResponse{}, ipc.ErrorCodeInternal, err
	}
	service.mu.Lock()
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.CertificateSHA256 = result.CertificateSHA256
	service.enrollment.CertificateNotAfter = result.CertificateNotAfter
	service.enrollment.KeyExists = true
	service.enrollment.LastError = ""
	service.mu.Unlock()
	service.refreshIdentitySnapshot(ctx)
	service.persistEnrollmentState(ctx)
	service.triggerPostureReportAfterEnrollment()
	service.triggerCatalogSyncAfterEnrollment()
	service.logger.Info("Endpoint certificate enrolled", "device_id", strings.TrimSpace(payload.DeviceID), "user_sid", userSID, "certificate_sha256", result.CertificateSHA256)
	return ipc.SubmitEnrollmentTokenResponse{
		Accepted:        true,
		Message:         "endpoint certificate enrolled",
		DeviceID:        strings.TrimSpace(payload.DeviceID),
		ActiveUserSID:   userSID,
		KeyName:         strings.TrimSpace(payload.KeyName),
		ReceivedAt:      now,
		EnrollmentState: ipc.EnrollmentStateEnrolled,
	}, "", nil
}

func (service *Service) triggerPostureReportAfterEnrollment() {
	if service.postureReporter == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultPostureReportTimeout)
		defer cancel()
		_, _ = service.reportPostureIfReady(ctx, "enrollment")
	}()
}

func (service *Service) triggerCatalogSyncAfterEnrollment() {
	if service.catalogClient == nil || service.dnsConfigurator == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultPostureReportTimeout)
		defer cancel()
		_, _ = service.syncDeviceCatalogIfReady(ctx)
	}()
}

func expectedEnrollmentKeyProvider(service *Service) string {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return strings.TrimSpace(service.enrollment.KeyProvider)
}

func (service *Service) persistEnrollmentState(ctx context.Context) {
	if service.stateStore == nil {
		return
	}
	state, ok := service.persistedEnrollmentSnapshot()
	if !ok {
		return
	}
	if err := service.stateStore.Save(ctx, state); err != nil {
		service.setEnrollmentLastError("persist enrollment state: " + err.Error())
		service.logger.Warn("Failed to persist ZTNA Agent enrollment state", "error", err)
	}
}

func (service *Service) persistedEnrollmentSnapshot() (persistedEnrollmentState, bool) {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.enrollment.State != ipc.EnrollmentStateEnrolled {
		return persistedEnrollmentState{}, false
	}
	state := persistedEnrollmentState{
		Version:             enrollmentStateFileVersion,
		EnrollmentState:     ipc.EnrollmentStateEnrolled,
		DeviceID:            strings.TrimSpace(service.enrollment.DeviceID),
		DeviceIDSource:      strings.TrimSpace(service.enrollment.DeviceIDSource),
		ActiveUserSID:       strings.TrimSpace(service.enrollment.ActiveUserSID),
		KeyName:             strings.TrimSpace(service.enrollment.KeyName),
		KeyProvider:         strings.TrimSpace(service.enrollment.KeyProvider),
		CertificateSHA256:   strings.TrimSpace(service.enrollment.CertificateSHA256),
		CertificateNotAfter: service.enrollment.CertificateNotAfter,
		LastAcceptedAt:      service.enrollment.LastAcceptedAt,
	}
	return state, state.validate() == nil
}

func (service *Service) restoreEnrollmentState(ctx context.Context) {
	if service.stateStore == nil {
		return
	}
	state, err := service.stateStore.Load(ctx)
	if errors.Is(err, ErrEnrollmentStateNotFound) {
		return
	}
	if err != nil {
		service.setEnrollmentLastError("load enrollment state: " + err.Error())
		service.logger.Warn("Failed to load ZTNA Agent enrollment state", "error", err)
		return
	}
	if err := service.restorePersistedEnrollmentState(ctx, state); err != nil {
		service.setEnrollmentLastError("restore enrollment state: " + err.Error())
		service.logger.Warn("Failed to restore ZTNA Agent enrollment state", "error", err)
	}
}

func (service *Service) restorePersistedEnrollmentState(ctx context.Context, state persistedEnrollmentState) error {
	if err := state.validate(); err != nil {
		return err
	}
	service.mu.RLock()
	expectedSID := strings.TrimSpace(service.authorizedUserSID)
	currentDeviceID := strings.TrimSpace(service.enrollment.DeviceID)
	currentKeyName := strings.TrimSpace(service.enrollment.KeyName)
	currentKeyProvider := strings.TrimSpace(service.enrollment.KeyProvider)
	service.mu.RUnlock()

	if expectedSID != "" && strings.TrimSpace(state.ActiveUserSID) != expectedSID {
		return fmt.Errorf("persisted active_user_sid does not match authorized user")
	}
	if currentDeviceID != "" && strings.TrimSpace(state.DeviceID) != currentDeviceID {
		return fmt.Errorf("persisted device_id does not match current device identity")
	}
	if currentKeyName != "" && strings.TrimSpace(state.KeyName) != currentKeyName {
		return fmt.Errorf("persisted key_name does not match current device identity")
	}
	keyProvider := firstNonEmptyString(state.KeyProvider, currentKeyProvider, deviceidentity.MicrosoftPlatformCryptoProvider)
	certificate, err := service.certificateLoader(ctx, deviceidentity.MachineCertificateOptions{
		DeviceID:    strings.TrimSpace(state.DeviceID),
		KeyName:     strings.TrimSpace(state.KeyName),
		KeyProvider: keyProvider,
		Clock:       service.clock,
	})
	if err != nil {
		return fmt.Errorf("load Machine Store endpoint certificate: %w", err)
	}
	certificateSHA256, err := tlsCertificateSHA256(certificate)
	if err != nil {
		return err
	}
	certificateNotAfter, err := tlsCertificateNotAfter(certificate)
	if err != nil {
		return err
	}
	if strings.TrimSpace(state.CertificateSHA256) != "" && !strings.EqualFold(strings.TrimSpace(state.CertificateSHA256), certificateSHA256) {
		return fmt.Errorf("persisted certificate_sha256 does not match Machine Store certificate")
	}

	service.mu.Lock()
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = strings.TrimSpace(state.DeviceID)
	service.enrollment.DeviceIDSource = strings.TrimSpace(state.DeviceIDSource)
	service.enrollment.ActiveUserSID = strings.TrimSpace(state.ActiveUserSID)
	service.enrollment.KeyName = strings.TrimSpace(state.KeyName)
	service.enrollment.KeyProvider = keyProvider
	service.enrollment.KeyExists = true
	service.enrollment.CertificateSHA256 = certificateSHA256
	service.enrollment.CertificateNotAfter = certificateNotAfter
	service.enrollment.LastAcceptedAt = state.LastAcceptedAt
	service.enrollment.LastError = ""
	service.mu.Unlock()

	if strings.TrimSpace(state.CertificateSHA256) == "" || !state.CertificateNotAfter.Equal(certificateNotAfter) {
		service.persistEnrollmentState(ctx)
	}
	service.logger.Info("ZTNA Agent enrollment state restored", "device_id", strings.TrimSpace(state.DeviceID), "key_name", strings.TrimSpace(state.KeyName), "certificate_sha256", certificateSHA256)
	return nil
}

func tlsCertificateSHA256(certificate tls.Certificate) (string, error) {
	if certificate.Leaf != nil && len(certificate.Leaf.Raw) > 0 {
		digest := sha256.Sum256(certificate.Leaf.Raw)
		return hex.EncodeToString(digest[:]), nil
	}
	if len(certificate.Certificate) == 0 || len(certificate.Certificate[0]) == 0 {
		return "", errors.New("Machine Store endpoint certificate has no leaf material")
	}
	digest := sha256.Sum256(certificate.Certificate[0])
	return hex.EncodeToString(digest[:]), nil
}

func tlsCertificateNotAfter(certificate tls.Certificate) (time.Time, error) {
	if certificate.Leaf != nil && !certificate.Leaf.NotAfter.IsZero() {
		return certificate.Leaf.NotAfter.UTC(), nil
	}
	if len(certificate.Certificate) == 0 || len(certificate.Certificate[0]) == 0 {
		return time.Time{}, errors.New("Machine Store endpoint certificate has no leaf material")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("parse Machine Store endpoint certificate: %w", err)
	}
	return leaf.NotAfter.UTC(), nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (service *Service) setEnrollmentLastError(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.enrollment.LastError = strings.TrimSpace(message)
}

func (service *Service) markEnrollmentFailed(err error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.enrollment.State = ipc.EnrollmentStateFailed
	service.enrollment.LastError = err.Error()
}

func validateSubmissionShape(payload ipc.SubmitEnrollmentTokenRequest, now time.Time) error {
	if strings.TrimSpace(payload.Token) == "" {
		return errors.New("token is required")
	}
	if len(payload.Token) > jwtverify.MaxTokenBytes {
		return fmt.Errorf("token exceeds %d bytes", jwtverify.MaxTokenBytes)
	}
	if strings.Count(payload.Token, ".") != 2 {
		return errors.New("token must be JWT-shaped")
	}
	if strings.TrimSpace(payload.AccessToken) != "" {
		if len(payload.AccessToken) > jwtverify.MaxTokenBytes {
			return fmt.Errorf("access token exceeds %d bytes", jwtverify.MaxTokenBytes)
		}
		if strings.Count(payload.AccessToken, ".") != 2 {
			return errors.New("access token must be JWT-shaped")
		}
		if payload.AccessTokenExpiresAt.IsZero() || !payload.AccessTokenExpiresAt.After(now) {
			return errors.New("access_token_expires_at must be in the future")
		}
	}
	if strings.TrimSpace(payload.Nonce) == "" {
		return errors.New("nonce is required")
	}
	if strings.TrimSpace(payload.DeviceID) == "" {
		return errors.New("device_id is required")
	}
	if strings.TrimSpace(payload.UserSID) == "" {
		return errors.New("user_sid is required")
	}
	if strings.TrimSpace(payload.KeyName) == "" {
		return errors.New("key_name is required")
	}
	if strings.TrimSpace(payload.UserEmail) != "" {
		email := strings.TrimSpace(payload.UserEmail)
		addr, err := mail.ParseAddress(email)
		if err != nil || addr == nil || addr.Name != "" || addr.Address != email {
			return errors.New("user_email must be a plain RFC 822 mailbox")
		}
	}
	if !payload.ExpiresAt.IsZero() && !payload.ExpiresAt.After(now) {
		return errors.New("expires_at must be in the future")
	}
	if payload.ExpiresInSeconds < 0 {
		return errors.New("expires_in must not be negative")
	}
	return nil
}

func validateAccessTokenUpdate(payload ipc.UpdateAccessTokenRequest, now time.Time) error {
	if strings.TrimSpace(payload.AccessToken) == "" {
		return errors.New("access_token is required")
	}
	if len(payload.AccessToken) > jwtverify.MaxTokenBytes {
		return fmt.Errorf("access token exceeds %d bytes", jwtverify.MaxTokenBytes)
	}
	if strings.Count(payload.AccessToken, ".") != 2 {
		return errors.New("access token must be JWT-shaped")
	}
	if strings.TrimSpace(payload.DeviceID) == "" {
		return errors.New("device_id is required")
	}
	if strings.TrimSpace(payload.UserSID) == "" {
		return errors.New("user_sid is required")
	}
	if payload.ExpiresAt.IsZero() || !payload.ExpiresAt.After(now) {
		return errors.New("expires_at must be in the future")
	}
	return nil
}

func randomNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("nonce-%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func (service *Service) refreshIdentitySnapshot(ctx context.Context) {
	if service.identityProvider == nil {
		return
	}
	snapshot, err := service.identityProvider.Snapshot(ctx)
	if err != nil && snapshot.LastError == "" {
		snapshot.LastError = err.Error()
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if strings.TrimSpace(snapshot.ActiveUserSID) != "" {
		service.enrollment.ActiveUserSID = strings.TrimSpace(snapshot.ActiveUserSID)
	}
	if strings.TrimSpace(snapshot.KeyName) != "" {
		service.enrollment.KeyName = strings.TrimSpace(snapshot.KeyName)
	} else if service.enrollment.ActiveUserSID != "" {
		service.enrollment.KeyName = deviceidentity.KeyNameForSID(service.enrollment.ActiveUserSID)
	}
	if strings.TrimSpace(snapshot.DeviceID) != "" {
		service.enrollment.DeviceID = strings.TrimSpace(snapshot.DeviceID)
		service.enrollment.DeviceIDSource = strings.TrimSpace(snapshot.DeviceIDSource)
	}
	service.enrollment.KeyExists = snapshot.KeyExists
	service.enrollment.KeyProvider = strings.TrimSpace(snapshot.KeyProvider)
	service.enrollment.IdentityError = strings.TrimSpace(snapshot.LastError)
	if !snapshot.CollectedAt.IsZero() {
		service.enrollment.IdentityCheckedAt = snapshot.CollectedAt.UTC()
	}
}

func (service *Service) State() State {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.state
}

func (service *Service) AuthorizedUserSID() string {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.authorizedUserSID
}

func (service *Service) setStartedAt(startedAt time.Time) {
	service.mu.Lock()
	service.startedAt = startedAt
	service.mu.Unlock()
}

func (service *Service) transition(next State) {
	service.mu.Lock()
	service.state = next
	service.mu.Unlock()
	service.logger.Info("ZTNA Agent service state changed", "state", next)
}

type submissionRateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newSubmissionRateLimiter(max int, window time.Duration) *submissionRateLimiter {
	return &submissionRateLimiter{max: max, window: window, hits: make(map[string][]time.Time)}
}

func (limiter *submissionRateLimiter) allow(key string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	cutoff := now.Add(-limiter.window)
	recent := limiter.hits[key][:0]
	for _, hit := range limiter.hits[key] {
		if hit.After(cutoff) {
			recent = append(recent, hit)
		}
	}
	if len(recent) >= limiter.max {
		limiter.hits[key] = recent
		return false
	}
	recent = append(recent, now)
	limiter.hits[key] = recent
	return true
}
