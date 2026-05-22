package service

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	devicedata "agent/internal/service/device-data"
	devicedatasync "agent/internal/service/device-data-sync"
	"agent/internal/service/enrollment"
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
	LoginTimeout                     time.Duration
	LoginPollInterval                time.Duration
	DeviceDataSyncInterval           time.Duration
	DeviceDataSyncChangeScanInterval time.Duration
	EnrollmentStatePath              string
	DeviceKeyName                    string
}

type Dependencies struct {
	Logger                      *slog.Logger
	ListenerFactory             func() (net.Listener, error)
	DeviceDataCollector         DeviceDataCollector
	DeviceDataWatcher           DeviceDataWatcher
	EnrollmentClient            enrollment.Client
	DeviceDataSyncClientFactory DeviceDataSyncClientFactory
	ProtectedResources          ProtectedResourcesManager
	DeviceIdentity              enrollment.DeviceIdentity
	EnrollmentStore             enrollment.Store
	UserSessionClient           usersession.Client
	Clock                       func() time.Time
}

type DeviceDataCollector = devicedata.Collector
type DeviceDataWatcher = devicedata.Watcher
type DeviceDataSyncClient = devicedatasync.Client
type DeviceDataSyncClientConfig = devicedatasync.ClientConfig
type DeviceDataSyncClientFactory = devicedatasync.ClientFactory
type ProtectedResourcesManager interface {
	Run(context.Context) error
	ApplyCatalog(context.Context, ipc.CatalogInfo) error
	Clear(context.Context) error
}

type Service struct {
	mu                  sync.RWMutex
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
	clock               func() time.Time
	deviceData          deviceDataState
	config              Config
}

type deviceDataState struct {
	Report          ipc.DeviceDataReport
	Status          string
	LastError       string
	LastCollectedAt time.Time
}

const (
	deviceDataStatusUnknown      = "unknown"
	deviceDataStatusCollected    = "collected"
	deviceDataStatusCollectError = "collect_error"
	statusDisabled               = "disabled"
)

const (
	defaultDeviceKeyName                    = enrollment.DefaultDeviceKeyName
	defaultEnrollmentTimeout                = enrollment.DefaultTimeout
	defaultEnrollmentPollInterval           = enrollment.DefaultPollInterval
	defaultLoginTimeout                     = usersession.DefaultTimeout
	defaultLoginPollInterval                = usersession.DefaultPollInterval
	defaultDeviceDataSyncInterval           = devicedatasync.DefaultInterval
	defaultDeviceDataSyncChangeScanInterval = devicedatasync.DefaultChangeScanInterval
)
