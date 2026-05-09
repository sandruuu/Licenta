//go:build !windows

package health

import (
	"context"
	"runtime"

	"ztna.local/endpoint-agent/internal/ipc"
)

func platformCheckDefinitions() []checkDefinition {
	return []checkDefinition{{Name: "Operating System", Build: func(ctx context.Context) (ipc.HealthCheck, string) {
		return ipc.HealthCheck{
			Name:        "Operating System",
			Status:      "warning",
			Description: "Windows posture collectors are unavailable on this platform",
			Details: map[string]string{
				"GOOS":   runtime.GOOS,
				"GOARCH": runtime.GOARCH,
			},
		}, runtime.GOOS
	}}}
}
