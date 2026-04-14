//go:build windows

package collectors

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// commandTimeout is the maximum duration for any collector command
const commandTimeout = 15 * time.Second

// OSInfo holds operating system information
type OSInfo struct {
	Name         string
	Version      string
	Build        string
	Architecture string
	Uptime       string
}

// CollectOSInfo gathers operating system details via PowerShell
func CollectOSInfo() OSInfo {
	info := OSInfo{
		Architecture: runtime.GOARCH,
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// Get OS caption and version
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Caption") {
				info.Name = extractValue(line)
			} else if strings.HasPrefix(line, "Version") {
				info.Version = extractValue(line)
			} else if strings.HasPrefix(line, "BuildNumber") {
				info.Build = extractValue(line)
			}
		}
	}

	// Map GOARCH to a friendlier name
	switch runtime.GOARCH {
	case "amd64":
		info.Architecture = "x64 (64-bit)"
	case "386":
		info.Architecture = "x86 (32-bit)"
	case "arm64":
		info.Architecture = "ARM64"
	default:
		info.Architecture = runtime.GOARCH
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel2()

	// Calculate uptime
	uptimeOut, err := exec.CommandContext(ctx2, "powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_OperatingSystem).LastBootUpTime").Output()
	if err == nil {
		bootStr := strings.TrimSpace(string(uptimeOut))
		// Parse the date — PowerShell outputs something like "Friday, February 24, 2026 10:00:00 AM"
		layouts := []string{
			"Monday, January 2, 2006 3:04:05 PM",
			"1/2/2006 3:04:05 PM",
			"2006-01-02 15:04:05",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, bootStr); err == nil {
				uptime := time.Since(t)
				days := int(uptime.Hours()) / 24
				hours := int(uptime.Hours()) % 24
				mins := int(uptime.Minutes()) % 60
				if days > 0 {
					info.Uptime = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
				} else {
					info.Uptime = fmt.Sprintf("%dh %dm", hours, mins)
				}
				break
			}
		}
		if info.Uptime == "" {
			info.Uptime = "N/A"
		}
	}

	return info
}

func extractValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
