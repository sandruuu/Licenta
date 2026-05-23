package tray

import (
	"context"
	"embed"
	"log/slog"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"agent/internal/shared/ipc"
)

//go:embed all:frontend/dist
var guiAssets embed.FS

type GUIApp struct {
	ctx      context.Context
	client   *ipc.Client
	timeout  time.Duration
	identity processIdentity
	logger   *slog.Logger
	options  Options
}

func NewGUIApp(trayOptions Options, logger *slog.Logger) *GUIApp {
	if logger == nil {
		logger = slog.Default()
	}
	timeout := trayOptions.Timeout
	return &GUIApp{
		client:   newDefaultClient(),
		timeout:  timeout,
		identity: currentProcessIdentity(),
		logger:   logger,
		options:  trayOptions,
	}
}

type processIdentity struct {
	PID      int
	Username string
	UserSID  string
}

func currentProcessIdentity() processIdentity {
	identity := processIdentity{PID: os.Getpid()}
	currentUser, err := user.Current()
	if err != nil || currentUser == nil {
		return identity
	}
	identity.Username = strings.TrimSpace(currentUser.Username)
	identity.UserSID = strings.TrimSpace(currentUser.Uid)
	return identity
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
	app.logger.Info("TrustAgent Wails tray GUI started", "tray_pid", app.identity.PID, "tray_user", app.identity.Username)
	go app.emitDashboardUpdates(ctx)
}

func (app *GUIApp) shutdown(context.Context) {
	app.logger.Info("TrustAgent Wails tray GUI stopped", "tray_pid", app.identity.PID)
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

func (app *GUIApp) StartEnrollmentInteractive() (ipc.StartEnrollmentInteractiveResponse, error) {
	var response ipc.StartEnrollmentInteractiveResponse
	callCtx, cancel := context.WithTimeout(app.context(), app.timeout)
	defer cancel()
	if err := app.client.Call(callCtx, ipc.OperationStartEnrollmentInteractive, ipc.StartEnrollmentInteractiveRequest{}, &response); err != nil {
		app.logger.Warn("Failed to start interactive enrollment over IPC", "error", err)
		return ipc.StartEnrollmentInteractiveResponse{}, err
	}
	if app.ctx != nil {
		wailsRuntime.EventsEmit(app.ctx, "dashboard:updated")
	}
	return response, nil
}

func (app *GUIApp) StartUserLoginInteractive() (ipc.StartUserLoginInteractiveResponse, error) {
	var response ipc.StartUserLoginInteractiveResponse
	callCtx, cancel := context.WithTimeout(app.context(), app.timeout)
	defer cancel()
	if err := app.client.Call(callCtx, ipc.OperationStartUserLoginInteractive, ipc.StartUserLoginInteractiveRequest{}, &response); err != nil {
		app.logger.Warn("Failed to start interactive user login over IPC", "error", err)
		return ipc.StartUserLoginInteractiveResponse{}, err
	}
	if app.ctx != nil {
		wailsRuntime.EventsEmit(app.ctx, "dashboard:updated")
	}
	return response, nil
}

func (app *GUIApp) LogoutUserSession() (ipc.LogoutUserSessionResponse, error) {
	var response ipc.LogoutUserSessionResponse
	callCtx, cancel := context.WithTimeout(app.context(), app.timeout)
	defer cancel()
	if err := app.client.Call(callCtx, ipc.OperationLogoutUserSession, ipc.LogoutUserSessionRequest{}, &response); err != nil {
		app.logger.Warn("Failed to logout user session over IPC", "error", err)
		return ipc.LogoutUserSessionResponse{}, err
	}
	if app.ctx != nil {
		wailsRuntime.EventsEmit(app.ctx, "dashboard:updated")
	}
	return response, nil
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
		},
		Enrollment: ipc.EnrollmentInfo{State: enrollmentState},
		DeviceData: ipc.DeviceDataReport{
			Hostname:    app.identity.Username,
			OS:          "Unknown",
			CollectedAt: now,
			Checks: []ipc.DeviceDataCheck{{
				Name:        "Device Data",
				Status:      ipc.DeviceDataStatusUnavailable,
				Description: "Agent service pipe is not reachable",
				Details:     map[string]string{"Reason": reason},
			}},
		},
		ReportedAt: now,
	}
}

func unavailableEnrollmentState() ipc.EnrollmentState {
	return ipc.EnrollmentStateUnenrolled
}
