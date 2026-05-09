package tray

import (
	"context"
	"embed"
	"log/slog"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"ztna.local/agent/internal/ipc"
	"ztna.local/agent/internal/process"
)

//go:embed all:frontend/dist
var guiAssets embed.FS

type GUIApp struct {
	ctx      context.Context
	client   *ipc.Client
	timeout  time.Duration
	identity process.Identity
	logger   *slog.Logger
}

func NewGUIApp(trayOptions Options, logger *slog.Logger) *GUIApp {
	if logger == nil {
		logger = slog.Default()
	}
	timeout := trayOptions.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &GUIApp{
		client:   newDefaultClient(),
		timeout:  timeout,
		identity: process.Current(),
		logger:   logger,
	}
}

func GUIAssets() embed.FS {
	return guiAssets
}

func runGUI(ctx context.Context, trayOptions Options, logger *slog.Logger) error {
	if ctx == nil {
		ctx = context.Background()
	}
	app := NewGUIApp(trayOptions, logger)
	return wails.Run(&options.App{
		Title:     "ZTNA Agent",
		Width:     1080,
		Height:    760,
		MinWidth:  920,
		MinHeight: 620,
		AssetServer: &assetserver.Options{
			Assets: guiAssets,
		},
		BackgroundColour: &options.RGBA{R: 245, G: 247, B: 250, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
	})
}

func (app *GUIApp) Startup(ctx context.Context) {
	app.startup(ctx)
}

func (app *GUIApp) Shutdown(ctx context.Context) {
	app.shutdown(ctx)
}

func (app *GUIApp) startup(ctx context.Context) {
	app.ctx = ctx
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
	ticker := time.NewTicker(30 * time.Second)
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
	return ipc.AgentDashboard{
		Connection: ipc.DashboardConnection{
			State:        "disconnected",
			Message:      "Agent service IPC is unavailable",
			ServiceState: "unavailable",
		},
		Status: ipc.AgentStatus{
			ServiceState:    "unavailable",
			ServicePID:      0,
			ServiceUser:     "LocalSystem",
			EnrollmentState: ipc.EnrollmentStateUnknown,
			ReportedAt:      now,
			LastError:       reason,
		},
		Enrollment:  ipc.EnrollmentInfo{State: ipc.EnrollmentStateUnknown, LastError: reason},
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
