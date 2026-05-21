package tray

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type Options struct {
	Timeout                  time.Duration
	DashboardRefreshInterval time.Duration
}

func Run(ctx context.Context, options Options, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Timeout <= 0 {
		return fmt.Errorf("tray timeout is required")
	}
	if options.DashboardRefreshInterval <= 0 {
		return fmt.Errorf("tray dashboard refresh interval is required")
	}
	return runGUI(ctx, options, logger)
}
