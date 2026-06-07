package tray

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent/internal/shared/ipc"
)

func TestNewGUIAppRequiresExplicitTimeout(t *testing.T) {
	app := NewGUIApp(Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if app.timeout != 0 {
		t.Fatalf("timeout = %s, want 0s", app.timeout)
	}
}

func TestNewGUIAppPreservesTimeout(t *testing.T) {
	app := NewGUIApp(Options{Timeout: time.Second}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if app.timeout != time.Second {
		t.Fatalf("timeout = %s, want 1s", app.timeout)
	}
}

func TestUnavailableDashboardPreservesLastKnownDashboard(t *testing.T) {
	app := NewGUIApp(Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	app.rememberDashboard(ipc.AgentDashboard{
		Connection: ipc.DashboardConnection{
			State:        "connected",
			Message:      "Device enrolled",
			ServiceState: "running",
		},
		Status: ipc.AgentStatus{
			ServiceState:    "running",
			EnrollmentState: ipc.EnrollmentStateEnrolled,
		},
		Enrollment: ipc.EnrollmentInfo{
			State:    ipc.EnrollmentStateEnrolled,
			DeviceID: "device-1",
		},
		UserSession: ipc.UserSessionInfo{
			State:     ipc.UserSessionStateAuthenticated,
			SessionID: "session-1",
		},
	})

	dashboard := app.unavailableDashboard(errors.New("pipe temporarily unavailable"))
	if dashboard.Status.EnrollmentState != ipc.EnrollmentStateEnrolled || dashboard.Enrollment.State != ipc.EnrollmentStateEnrolled {
		t.Fatalf("enrollment state was not preserved: %+v", dashboard)
	}
	if dashboard.UserSession.State != ipc.UserSessionStateAuthenticated || dashboard.UserSession.SessionID != "session-1" {
		t.Fatalf("user session was not preserved: %+v", dashboard.UserSession)
	}
	if dashboard.Connection.State != "connected" || dashboard.Connection.ServiceState != "unavailable" || dashboard.Status.ServiceState != "unavailable" {
		t.Fatalf("connection/status = %+v / %+v", dashboard.Connection, dashboard.Status)
	}
}

func TestWailsAppOptionsUsesWindowConfig(t *testing.T) {
	app := NewGUIApp(Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	wailsOptions := wailsAppOptions(app, defaultGUIWindowConfig)
	if wailsOptions.Title != defaultGUIWindowConfig.Title || wailsOptions.Width != defaultGUIWindowConfig.Width || wailsOptions.Height != defaultGUIWindowConfig.Height || !wailsOptions.DisableResize {
		t.Fatalf("wails options = %+v", wailsOptions)
	}
	if len(wailsOptions.Bind) != 1 || wailsOptions.Bind[0] != app {
		t.Fatalf("wails bind = %+v", wailsOptions.Bind)
	}
	if wailsOptions.AssetServer == nil || wailsOptions.BackgroundColour == nil {
		t.Fatalf("wails options missing asset server/background: %+v", wailsOptions)
	}
}

func TestAgentUIDoesNotUseWindowsNotifications(t *testing.T) {
	forbidden := []string{
		"InitializeNotifications",
		"SendNotification",
		"SendNotificationWithActions",
		"RequestNotificationAuthorization",
		"CheckNotificationAuthorization",
	}
	paths := []string{"gui.go"}
	err := filepath.WalkDir(filepath.Join("frontend", "src"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk frontend source: %v", err)
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		source := string(content)
		for _, token := range forbidden {
			if strings.Contains(source, token) {
				t.Fatalf("%s uses Windows notification API %q; Agent events must stay inside the Agent UI", path, token)
			}
		}
	}
}
