//go:build windows

package main

import (
	"context"
	"log/slog"
	"os"

	"agent/internal/app"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	if err := app.InstallService(context.Background(), logger); err != nil {
		logger.Error("Agent installer exited with error", "error", err)
		os.Exit(1)
	}
	logger.Info("Agent service is installed and running")
}
