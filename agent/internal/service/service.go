package service

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"time"

	"agent/internal/service/catalog"
	"agent/internal/service/deviceidentity"
	"agent/internal/service/dnscontrol"
	"agent/internal/service/dnsresolver"
	"agent/internal/service/enrollment"
	"agent/internal/service/enrollmentflow"
	agentnetwork "agent/internal/service/network"
	"agent/internal/service/pa"
	"agent/internal/service/relay"
	servicestate "agent/internal/service/state"
	"agent/internal/service/tunnel"
	"agent/internal/shared/ipc"
)

type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateDegraded State = "degraded"
	StateStopping State = "stopping"
)

type Config struct {
	AuthorizedUserSID          string
	PAURL                      string
	CloudCertSHA256            string
	CAFile                     string
	PostureInterval            time.Duration
	CriticalInterval           time.Duration
	HeartbeatInterval          time.Duration
	PostureReportTimeout       time.Duration
	CatalogInterval            time.Duration
	CatalogCacheTTL            time.Duration
	CatalogRetryBackoff        []time.Duration
	AccessTokenExpirySkew      time.Duration
	DNSServer                  string
	TUNEnabled                 bool
	TUNName                    string
	TUNIP                      string
	TUNNetmask                 string
	TUNRouteCIDR               string
	ProcessIdentity            bool
	CertificateRenewalInterval time.Duration
	CertificateRenewBefore     time.Duration
	CertificateRenewalTimeout  time.Duration
	PARequestTimeout           time.Duration
	EnrollmentRateLimitMax     int
	EnrollmentRateLimitWindow  time.Duration
}

type Dependencies struct {
	Logger              *slog.Logger
	ListenerFactory     func(string) (net.Listener, error)
	EnrollmentValidator EnrollmentValidator
	IdentityProvider    deviceidentity.Provider
	PostureCollector    DevicePostureCollector
	PostureReporter     DevicePostureReporter
	CatalogClient       DeviceCatalogClient
	ResourceAuthorizer  relay.ResourceAuthorizer
	DNSConfigurator     DNSConfigurator
	SyntheticResolver   SyntheticResolver
	DNSResolverServer   DNSResolverServer
	NetworkManager      NetworkManager
	EnrollmentRunner    EnrollmentRunner
	EnrollmentRenewer   EnrollmentRenewer
	StateStore          servicestate.EnrollmentStore
	CatalogCacheStore   servicestate.CatalogCacheStore
	CertificateLoader   MachineCertificateLoader
	Clock               func() time.Time
}

type EnrollmentValidator interface {
	ValidateEnrollmentAccessToken(context.Context, enrollment.ValidationInput) (*enrollment.ValidationResult, error)
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
	enrollmentValidator        EnrollmentValidator
	identityProvider           deviceidentity.Provider
	postureCollector           DevicePostureCollector
	postureReporter            DevicePostureReporter
	postureInterval            time.Duration
	criticalInterval           time.Duration
	heartbeatInterval          time.Duration
	postureReportTimeout       time.Duration
	catalogClient              DeviceCatalogClient
	dnsConfigurator            DNSConfigurator
	syntheticResolver          SyntheticResolver
	dnsResolverServer          DNSResolverServer
	networkManager             NetworkManager
	gatewayTunnel              *tunnel.Manager
	relayForwarder             *relay.Forwarder
	paClient                   *pa.Client
	catalogInterval            time.Duration
	catalogCacheTTL            time.Duration
	catalogRetryBackoff        []time.Duration
	accessTokenExpirySkew      time.Duration
	dnsServer                  string
	enrollmentRunner           EnrollmentRunner
	enrollmentRenewer          EnrollmentRenewer
	stateStore                 servicestate.EnrollmentStore
	catalogCacheStore          servicestate.CatalogCacheStore
	certificateLoader          MachineCertificateLoader
	certificateRenewalInterval time.Duration
	certificateRenewBefore     time.Duration
	certificateRenewalTimeout  time.Duration
	clock                      func() time.Time
	rateLimiter                *enrollmentflow.RateLimiter
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
	maxAccessTokenBytes               = 64 * 1024
)
