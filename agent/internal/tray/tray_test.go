package tray

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
