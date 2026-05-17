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
	if err := app.Run(context.Background(), logger); err != nil {
		logger.Error("Agent exited with error", "error", err)
		os.Exit(1)
	}
}
