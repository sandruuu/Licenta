//go:build windows

package collectors

import (
	"context"
	"os/exec"
	"strings"
)

// DiskEncryptionInfo holds BitLocker status for the system drive
type DiskEncryptionInfo struct {
	ProtectionStatus string // "Protection On", "Protection Off", "Unknown"
	EncryptionMethod string
	VolumeStatus     string
	IsEncrypted      bool
}

// CollectDiskEncryption checks BitLocker status on C: drive
func CollectDiskEncryption() DiskEncryptionInfo {
	info := DiskEncryptionInfo{
		ProtectionStatus: "Unknown",
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// Try PowerShell first
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue | Select-Object ProtectionStatus, VolumeStatus, EncryptionMethod | Format-List`).Output()

	if err == nil && strings.TrimSpace(string(out)) != "" {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ProtectionStatus") {
				val := extractValue(line)
				info.ProtectionStatus = val
				info.IsEncrypted = strings.Contains(strings.ToLower(val), "on") || val == "1"
			} else if strings.HasPrefix(line, "VolumeStatus") {
				info.VolumeStatus = extractValue(line)
			} else if strings.HasPrefix(line, "EncryptionMethod") {
				info.EncryptionMethod = extractValue(line)
			}
		}
		return info
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel2()

	// Fallback: use manage-bde command line
	out2, err2 := exec.CommandContext(ctx2, "manage-bde", "-status", "C:").Output()
	if err2 == nil {
		output := string(out2)
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Protection Status") {
				val := extractAfterColon(line)
				info.ProtectionStatus = val
				info.IsEncrypted = strings.Contains(strings.ToLower(val), "on")
			} else if strings.Contains(line, "Encryption Method") {
				info.EncryptionMethod = extractAfterColon(line)
			} else if strings.Contains(line, "Conversion Status") {
				info.VolumeStatus = extractAfterColon(line)
			}
		}
	}

	return info
}

func extractAfterColon(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
