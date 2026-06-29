package service

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	agentevents "agent/internal/service/agent-events"
	devicedata "agent/internal/service/device-data"
	devicedatasync "agent/internal/service/device-data-sync"
	"agent/internal/service/enrollment"
	flowauthorization "agent/internal/service/flow-authorization"
	gatewaytunnel "agent/internal/service/gateway-tunnel"
	pdpclient "agent/internal/service/pdp-client"
	"agent/internal/service/usersession"
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
	PDPGRPCEndpoint                  string
	PDPTLSServerName                 string
	PDPCAFile                        string
	EnrollmentTimeout                time.Duration
	EnrollmentPollInterval           time.Duration
	CertificateRenewBefore           time.Duration
	CertificateRenewCheckInterval    time.Duration
	CertificateRenewTimeout          time.Duration
	LoginTimeout                     time.Duration
	LoginPollInterval                time.Duration
	SessionRenewBefore               time.Duration
	SessionRenewRetryInterval        time.Duration
	DeviceDataSyncInterval           time.Duration
	DeviceDataSyncChangeScanInterval time.Duration
	EnrollmentStatePath              string
	DeviceKeyName                    string
	LocalDNSListenAddress            string
	LocalDNSServer                   string
	SyntheticIPCIDR                  string
	HardenBrowserDoH                 bool
	TrafficInterceptionEnabled       bool
	TrafficProxyListenAddress        string
	WFPDriverDevicePath              string
	WFPFailClosed                    bool
	PipeAuthorizedUserSID            string
}

type Dependencies struct {
	Logger                      *slog.Logger
	ListenerFactory             func() (net.Listener, error)
	DeviceDataCollector         DeviceDataCollector
	DeviceDataWatcher           DeviceDataWatcher
	EnrollmentClient            enrollment.Client
	EnrollmentRenewalClient     enrollment.RenewalClient
	DeviceDataSyncClientFactory DeviceDataSyncClientFactory
	AgentEventsClientFactory    AgentEventsClientFactory
	ProtectedResources          ProtectedResourcesManager
	DeviceIdentity              enrollment.DeviceIdentity
	EnrollmentStore             enrollment.Store
	UserSessionClient           usersession.Client
	FlowAuthorizer              flowauthorization.Client
	GatewayTunnel               gatewayTunnel
	PDPClient                   *pdpclient.Client
	Clock                       func() time.Time
}

type DeviceDataCollector = devicedata.Collector
type DeviceDataWatcher = devicedata.Watcher
type DeviceDataSyncClient = devicedatasync.Client
type DeviceDataSyncClientFactory = devicedatasync.ClientFactory
type AgentEventsClient = agentevents.Client
type AgentEventsClientFactory func(context.Context, enrollment.EnrollmentRecord) (AgentEventsClient, error)
type gatewayTunnel interface {
	OpenResourceStream(context.Context, gatewaytunnel.ResourceStreamRequest) (net.Conn, error)
	Status() gatewaytunnel.Status
}
type ProtectedResourcesManager interface {
	Run(context.Context) error
	ApplyCatalog(context.Context, ipc.CatalogInfo) error
	Clear(context.Context) error
}

type Service struct {
	mu                  sync.RWMutex
	deviceDataCollectMu sync.Mutex
	logger              *slog.Logger
	state               State
	startedAt           time.Time
	listenerFactory     func() (net.Listener, error)
	deviceDataCollector DeviceDataCollector
	enrollment          *enrollment.Manager
	userSessions        *usersession.Manager
	protectedResources  ProtectedResourcesManager
	deviceIdentity      enrollment.DeviceIdentity
	deviceDataSync      *devicedatasync.Runner
	agentEventsFactory  AgentEventsClientFactory
	pdpClient           *pdpclient.Client
	clock               func() time.Time
	deviceData          deviceDataState
	accessPrompt        accessPromptState
	localAccess         localAccessState
	config              Config
}

type deviceDataState struct {
	Report          ipc.DeviceDataReport
	Status          string
	LastError       string
	LastCollectedAt time.Time
}

type accessPromptState struct {
	Message    string
	ResourceID string
	FQDN       string
	ReportedAt time.Time
}

type localAccessState struct {
	Suspended bool
	Reason    string
	UpdatedAt time.Time
}

const (
	deviceDataStatusUnknown      = "unknown"
	deviceDataStatusCollecting   = "collecting"
	deviceDataStatusCollected    = "collected"
	deviceDataStatusCollectError = "collect_error"
	statusDisabled               = "disabled"
)

const (
	defaultDeviceKeyName                    = enrollment.DefaultDeviceKeyName
	defaultEnrollmentTimeout                = enrollment.DefaultTimeout
	defaultEnrollmentPollInterval           = enrollment.DefaultPollInterval
	defaultCertificateRenewBefore           = enrollment.DefaultCertificateRenewBefore
	defaultCertificateRenewCheckInterval    = enrollment.DefaultCertificateRenewCheckInterval
	defaultCertificateRenewTimeout          = enrollment.DefaultCertificateRenewTimeout
	defaultLoginTimeout                     = usersession.DefaultTimeout
	defaultLoginPollInterval                = usersession.DefaultPollInterval
	defaultSessionRenewBefore               = usersession.DefaultSessionRenewBefore
	defaultSessionRenewRetryInterval        = usersession.DefaultSessionRenewRetry
	defaultDeviceDataSyncInterval           = devicedatasync.DefaultInterval
	defaultDeviceDataSyncChangeScanInterval = devicedatasync.DefaultChangeScanInterval
)
