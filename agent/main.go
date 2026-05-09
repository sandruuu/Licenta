package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	agentapp "ztna.local/agent/internal/app"
	"ztna.local/agent/internal/tray"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	if shouldRunAgentCLI(os.Args[1:]) {
		if err := agentapp.Run(context.Background(), os.Args[1:], logger); err != nil {
			if errors.Is(err, agentapp.ErrUsage) {
				agentapp.PrintUsage(os.Stderr)
				os.Exit(2)
			}
			logger.Error("ZTNA Agent exited with error", "error", err)
			os.Exit(1)
		}
		return
	}

	guiApp := tray.NewGUIApp(tray.Options{}, logger)
	if err := wails.Run(&options.App{
		Title:     "ZTNA Agent",
		Width:     1080,
		Height:    760,
		MinWidth:  920,
		MinHeight: 620,
		AssetServer: &assetserver.Options{
			Assets: tray.GUIAssets(),
		},
		BackgroundColour: &options.RGBA{R: 245, G: 247, B: 250, A: 1},
		OnStartup:        guiApp.Startup,
		OnShutdown:       guiApp.Shutdown,
		Bind: []interface{}{
			guiApp,
		},
	}); err != nil {
		logger.Error("ZTNA Agent Wails GUI exited with error", "error", err)
		os.Exit(1)
	}
}

func shouldRunAgentCLI(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] != "tray" {
		return true
	}
	for _, arg := range args[1:] {
		if arg == "--proof" {
			return true
		}
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}
