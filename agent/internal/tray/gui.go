package tray

import (
	"context"
	"embed"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"agent/internal/platform/process"
	servicestate "agent/internal/service/state"
	"agent/internal/shared/ipc"
)

//go:embed all:frontend/dist
var guiAssets embed.FS

type GUIApp struct {
	ctx              context.Context
	client           *ipc.Client
	timeout          time.Duration
	identity         process.Identity
	logger           *slog.Logger
	options          Options
	enrollmentActive atomic.Bool
}

func NewGUIApp(trayOptions Options, logger *slog.Logger) *GUIApp {
	if logger == nil {
		logger = slog.Default()
	}
	timeout := trayOptions.Timeout
	return &GUIApp{
		client:   newDefaultClient(),
		timeout:  timeout,
		identity: process.Current(),
		logger:   logger,
		options:  trayOptions,
	}
}

type EnrollmentStartResponse struct {
	Started         bool                `json:"started"`
	Message         string              `json:"message"`
	EnrollmentState ipc.EnrollmentState `json:"enrollment_state,omitempty"`
	DeviceID        string              `json:"device_id,omitempty"`
	ReportedAt      time.Time           `json:"reported_at"`
}

func GUIAssets() embed.FS {
	return guiAssets
}

func runGUI(ctx context.Context, trayOptions Options, logger *slog.Logger) error {
	if ctx == nil {
		ctx = context.Background()
	}
	app := NewGUIApp(trayOptions, logger)
	return wails.Run(wailsAppOptions(app, defaultGUIWindowConfig))
}

func (app *GUIApp) startup(ctx context.Context) {
	app.ctx = ctx
	wailsRuntime.WindowCenter(ctx)
	wailsRuntime.WindowShow(ctx)
	app.logger.Info("ZTNA Agent Wails tray GUI started", "tray_pid", app.identity.PID, "tray_user", app.identity.Username)
	go app.emitDashboardUpdates(ctx)
}

func (app *GUIApp) shutdown(context.Context) {
	app.logger.Info("ZTNA Agent Wails tray GUI stopped", "tray_pid", app.identity.PID)
}

func (app *GUIApp) GetDashboard() ipc.AgentDashboard {
	var dashboard ipc.AgentDashboard
	callCtx, cancel := context.WithTimeout(app.context(), app.timeout)
	defer cancel()
	if err := app.client.Call(callCtx, ipc.OperationGetDashboard, ipc.DashboardRequest{}, &dashboard); err != nil {
		app.logger.Warn("Failed to fetch Agent dashboard over IPC", "error", err)
		return app.unavailableDashboard(err)
	}
	return dashboard
}

func (app *GUIApp) GetCatalogResources() ipc.CatalogResourcesResponse {
	var response ipc.CatalogResourcesResponse
	callCtx, cancel := context.WithTimeout(app.context(), app.timeout)
	defer cancel()
	if err := app.client.Call(callCtx, ipc.OperationGetCatalogResources, ipc.CatalogResourcesRequest{}, &response); err != nil {
		app.logger.Warn("Failed to fetch catalog resources over IPC", "error", err)
		return ipc.CatalogResourcesResponse{Resources: []ipc.CatalogResource{}, ReportedAt: time.Now().UTC()}
	}
	return response
}

func (app *GUIApp) GetActiveSessions() ipc.ActiveSessionsResponse {
	var response ipc.ActiveSessionsResponse
	callCtx, cancel := context.WithTimeout(app.context(), app.timeout)
	defer cancel()
	if err := app.client.Call(callCtx, ipc.OperationGetActiveSessions, ipc.ActiveSessionsRequest{}, &response); err != nil {
		app.logger.Warn("Failed to fetch active sessions over IPC", "error", err)
		return ipc.ActiveSessionsResponse{Sessions: []ipc.ActiveSession{}, ReportedAt: time.Now().UTC()}
	}
	return response
}

func (app *GUIApp) GetAccessEvents() ipc.AccessEventsResponse {
	var response ipc.AccessEventsResponse
	callCtx, cancel := context.WithTimeout(app.context(), app.timeout)
	defer cancel()
	if err := app.client.Call(callCtx, ipc.OperationGetAccessEvents, ipc.AccessEventsRequest{}, &response); err != nil {
		app.logger.Warn("Failed to fetch access events over IPC", "error", err)
		return ipc.AccessEventsResponse{Events: []ipc.AccessEvent{app.pipeUnavailableEvent(err)}, ReportedAt: time.Now().UTC()}
	}
	return response
}

func (app *GUIApp) StartEnrollment() (EnrollmentStartResponse, error) {
	if !app.enrollmentActive.CompareAndSwap(false, true) {
		return EnrollmentStartResponse{
			Started:    false,
			Message:    "Device enrollment is already running",
			ReportedAt: time.Now().UTC(),
		}, nil
	}
	defer app.enrollmentActive.Store(false)

	enrollmentTimeout := app.timeout
	if app.options.EnrollmentTimeout > 0 {
		enrollmentTimeout = app.options.EnrollmentTimeout
	}
	enrollmentCtx, cancel := context.WithTimeout(app.context(), enrollmentTimeout)
	defer cancel()

	loginOptions := app.options
	loginOptions.Timeout = enrollmentTimeout
	login, err := runLogin(enrollmentCtx, app.client, loginOptions, app.identity, app.logger)
	if err != nil {
		return EnrollmentStartResponse{}, err
	}
	go runAccessTokenRefreshLoop(app.context(), app.client, login, app.timeout, app.options.TokenRefreshInterval, app.options.TokenRefreshMargin, app.logger)
	if app.ctx != nil {
		wailsRuntime.EventsEmit(app.ctx, "dashboard:updated")
	}
	return EnrollmentStartResponse{
		Started:    true,
		Message:    "Device enrollment flow completed",
		DeviceID:   login.deviceID,
		ReportedAt: time.Now().UTC(),
	}, nil
}

func (app *GUIApp) HideWindow() {
	if app.ctx != nil {
		wailsRuntime.WindowHide(app.ctx)
	}
}

func (app *GUIApp) ShowWindow() {
	if app.ctx != nil {
		wailsRuntime.WindowShow(app.ctx)
	}
}

func (app *GUIApp) emitDashboardUpdates(ctx context.Context) {
	if app.options.DashboardRefreshInterval <= 0 {
		return
	}
	ticker := time.NewTicker(app.options.DashboardRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wailsRuntime.EventsEmit(ctx, "dashboard:updated")
		}
	}
}

func (app *GUIApp) context() context.Context {
	if app.ctx != nil {
		return app.ctx
	}
	return context.Background()
}

func (app *GUIApp) unavailableDashboard(err error) ipc.AgentDashboard {
	now := time.Now().UTC()
	reason := strings.TrimSpace(err.Error())
	enrollmentState := unavailableEnrollmentState()
	connectionState := "disconnected"
	connectionMessage := "Agent service IPC is unavailable"
	if enrollmentState == ipc.EnrollmentStateUnenrolled {
		connectionState = "unenrolled"
		connectionMessage = "Device is not enrolled; Agent service IPC is unavailable"
	}
	return ipc.AgentDashboard{
		Connection: ipc.DashboardConnection{
			State:        connectionState,
			Message:      connectionMessage,
			ServiceState: "unavailable",
		},
		Status: ipc.AgentStatus{
			ServiceState:    "unavailable",
			ServicePID:      0,
			ServiceUser:     "LocalSystem",
			EnrollmentState: enrollmentState,
			ReportedAt:      now,
			LastError:       reason,
		},
		Enrollment:  ipc.EnrollmentInfo{State: enrollmentState, LastError: reason},
		Certificate: ipc.CertificateInfo{LastError: reason},
		User: ipc.AuthenticatedUser{
			UserSID:      app.identity.UserSID,
			SessionState: "unavailable",
		},
		Posture: ipc.DevicePostureReport{
			Hostname:    app.identity.Username,
			OS:          "Unknown",
			CollectedAt: now,
			Checks: []ipc.DevicePostureCheck{{
				Name:        "Connectivity",
				Status:      ipc.DevicePostureStatusUnavailable,
				Description: "Agent service pipe is not reachable",
				Details:     map[string]string{"Reason": reason},
			}},
		},
		Resources:      []ipc.CatalogResource{},
		ActiveSessions: []ipc.ActiveSession{},
		AccessEvents:   []ipc.AccessEvent{app.pipeUnavailableEvent(err)},
		ReportedAt:     now,
	}
}

func unavailableEnrollmentState() ipc.EnrollmentState {
	state, err := servicestate.NewDefaultEnrollmentStore(time.Now).Load(context.Background())
	if err == nil {
		return state.EnrollmentState
	}
	if errors.Is(err, servicestate.ErrEnrollmentNotFound) {
		return ipc.EnrollmentStateUnenrolled
	}
	return ipc.EnrollmentStateUnknown
}

func (app *GUIApp) pipeUnavailableEvent(err error) ipc.AccessEvent {
	now := time.Now().UTC()
	reason := strings.TrimSpace(err.Error())
	if reason == "" {
		reason = "Agent service IPC is unavailable"
	}
	return ipc.AccessEvent{
		ID:         "tray-pipe-unavailable",
		Decision:   "deny",
		Reason:     reason,
		Source:     "tray_ipc",
		OccurredAt: now,
	}
}
