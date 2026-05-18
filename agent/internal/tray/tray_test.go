package tray

import (
	"io"
	"log/slog"
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
