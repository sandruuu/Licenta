//go:build windows

package collectors

import (
	"context"
	"os/exec"
	"strings"
)

// AntivirusInfo holds antivirus product details
type AntivirusInfo struct {
	ProductName string
	Enabled     bool
	UpToDate    bool
	Found       bool
}

// CollectAntivirusInfo queries Windows Security Center for AV products
func CollectAntivirusInfo() AntivirusInfo {
	info := AntivirusInfo{}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | Format-List`).Output()
	if err != nil {
		return info
	}

	output := string(out)
	if strings.TrimSpace(output) == "" {
		return info
	}

	info.Found = true
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "displayName") {
			info.ProductName = extractValue(line)
		} else if strings.HasPrefix(line, "productState") {
			stateStr := extractValue(line)
			// productState is a bitmask:
			// Bits 12-8: product state (real-time protection)
			// 0x1000 = ON, 0x0000 = OFF
			// Bits 4-0: signature status
			// 0x00 = up to date, 0x10 = out of date
			info.Enabled, info.UpToDate = parseProductState(stateStr)
		}
	}

	return info
}

func parseProductState(stateStr string) (enabled bool, upToDate bool) {
	// Parse the decimal product state value
	var state int
	for _, c := range strings.TrimSpace(stateStr) {
		if c >= '0' && c <= '9' {
			state = state*10 + int(c-'0')
		}
	}

	if state == 0 {
		return false, false
	}

	// Check bit 12 (0x1000) for real-time protection
	enabled = (state & 0x1000) != 0
	// Check bit 4 (0x10) for out-of-date signatures
	upToDate = (state & 0x10) == 0

	return enabled, upToDate
}
