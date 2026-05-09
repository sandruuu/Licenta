//go:build !windows

package deviceposture

import (
	"context"
	"runtime"

	"ztna.local/agent/internal/ipc"
)

func platformCheckDefinitions() []checkDefinition {
	return []checkDefinition{
		{Name: "Operating System", Build: unavailablePlatformCheck("Operating System")},
		{Name: "Firewall", Build: unavailablePlatformCheck("Firewall")},
		{Name: "Antivirus", Build: unavailablePlatformCheck("Antivirus")},
		{Name: "Disk Encryption", Build: unavailablePlatformCheck("Disk Encryption")},
		{Name: "Windows Updates", Build: unavailablePlatformCheck("Windows Updates")},
		{Name: "Connectivity", Build: unavailablePlatformCheck("Connectivity")},
		{Name: "Password & Lock", Build: unavailablePlatformCheck("Password & Lock")},
	}
}

func unavailablePlatformCheck(name string) func(context.Context) (ipc.DevicePostureCheck, string) {
	return func(context.Context) (ipc.DevicePostureCheck, string) {
		return ipc.DevicePostureCheck{
			Name:        name,
			Status:      ipc.DevicePostureStatusUnavailable,
			Description: "Windows posture collectors are unavailable on this platform",
			Details: map[string]string{
				"GOOS":   runtime.GOOS,
				"GOARCH": runtime.GOARCH,
			},
		}, runtime.GOOS
	}
}
