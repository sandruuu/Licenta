package service

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

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
	PDPGRPCEndpoint        string
	PDPTLSServerName       string
	PDPCAFile              string
	EnrollmentTimeout      time.Duration
	EnrollmentPollInterval time.Duration
	LoginTimeout           time.Duration
	LoginPollInterval      time.Duration
	EnrollmentStatePath    string
	DeviceKeyName          string
}

type Dependencies struct {
	Logger            *slog.Logger
	ListenerFactory   func() (net.Listener, error)
	PostureCollector  DevicePostureCollector
	EnrollmentClient  enrollment.Client
	DeviceIdentity    enrollment.DeviceIdentity
	EnrollmentStore   enrollment.Store
	UserSessionClient usersession.Client
	Clock             func() time.Time
}

type DevicePostureCollector interface {
	Collect(context.Context, string) (ipc.DevicePostureReport, error)
}

type Service struct {
	mu               sync.RWMutex
	logger           *slog.Logger
	state            State
	startedAt        time.Time
	listenerFactory  func() (net.Listener, error)
	postureCollector DevicePostureCollector
	enrollment       *enrollment.Manager
	userSessions     *usersession.Manager
	clock            func() time.Time
	posture          devicePostureState
	config           Config
}

type devicePostureState struct {
	Report          ipc.DevicePostureReport
	Status          string
	LastError       string
	LastCollectedAt time.Time
}

const (
	postureStatusUnknown      = "unknown"
	postureStatusCollected    = "collected"
	postureStatusCollectError = "collect_error"
	statusDisabled            = "disabled"
)

const (
	defaultDeviceKeyName          = enrollment.DefaultDeviceKeyName
	defaultEnrollmentTimeout      = enrollment.DefaultTimeout
	defaultEnrollmentPollInterval = enrollment.DefaultPollInterval
	defaultLoginTimeout           = usersession.DefaultTimeout
	defaultLoginPollInterval      = usersession.DefaultPollInterval
)
