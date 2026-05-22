//go:build !windows

package host

import (
	"context"
	"log/slog"
)

func RunService(_ string, run func(context.Context) error, _ *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return run(ctx)
}

func IsServiceContext() bool {
	return false
}
