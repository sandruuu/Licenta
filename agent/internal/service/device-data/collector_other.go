//go:build !windows

package devicedata

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"
)

type defaultCollector struct{}

func NewDefaultCollector(_ *slog.Logger) Collector {
	return defaultCollector{}
}

func (collector defaultCollector) Collect(_ context.Context, deviceID string) (Report, error) {
	hostname, _ := os.Hostname()
	return Report{
		DeviceID:    strings.TrimSpace(deviceID),
		Hostname:    strings.TrimSpace(hostname),
		OS:          runtime.GOOS,
		CollectedAt: time.Now().UTC(),
		Checks: []Check{{
			Name:        "Operating System",
			Status:      StatusGood,
			Description: runtime.GOOS,
		}},
	}, nil
}
