//go:build windows

package collectors

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// PasswordInfo holds password and screen-lock policy details
type PasswordInfo struct {
	PasswordSet   bool
	ScreenLockSet bool
	LockTimeout   string // e.g. "5 minutes"
}

// validUsername matches safe Windows usernames (alphanumeric, dot, hyphen, underscore)
var validUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// CollectPasswordInfo checks if the current user has a password set and screen lock configured
func CollectPasswordInfo() PasswordInfo {
	info := PasswordInfo{}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// Sanitize USERNAME to prevent command injection
	username := os.Getenv("USERNAME")
	if username == "" || !validUsername.MatchString(username) {
		return info
	}

	// Check if the current user has a password set
	// net user <username> will show "Password required" field
	out, err := exec.CommandContext(ctx, "net", "user", username).Output()
	if err == nil {
		output := string(out)
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Check "Password last set" — if it says "Never", no password
			if strings.Contains(line, "Password last set") {
				val := extractAfterMultiSpace(line)
				if !strings.Contains(strings.ToLower(val), "never") {
					info.PasswordSet = true
				}
			}
		}
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel2()

	// Check screen lock timeout via power settings
	lockOut, err := exec.CommandContext(ctx2, "powershell", "-NoProfile", "-Command",
		`powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 2>$null`).Output()
	if err == nil {
		output := string(lockOut)
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Current AC Power Setting Index") || strings.Contains(line, "Current DC Power Setting Index") {
				val := extractAfterColon(line)
				val = strings.TrimSpace(val)
				if val != "" && val != "0x00000000" {
					info.ScreenLockSet = true
					// Value is in seconds (hex)
					info.LockTimeout = parseHexSeconds(val)
				}
			}
		}
	}

	// Fallback: check registry for screen saver lock
	if !info.ScreenLockSet {
		ctx3, cancel3 := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel3()

		regOut, err := exec.CommandContext(ctx3, "powershell", "-NoProfile", "-Command",
			`Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ScreenSaverIsSecure`).Output()
		if err == nil {
			val := strings.TrimSpace(string(regOut))
			if val == "1" {
				info.ScreenLockSet = true
				ctx4, cancel4 := context.WithTimeout(context.Background(), commandTimeout)
				defer cancel4()

				// Get screen saver timeout
				timeoutOut, err := exec.CommandContext(ctx4, "powershell", "-NoProfile", "-Command",
					`Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ScreenSaveTimeOut`).Output()
				if err == nil {
					timeout := strings.TrimSpace(string(timeoutOut))
					info.LockTimeout = timeout + " seconds"
				}
			}
		}
	}

	return info
}

func extractAfterMultiSpace(line string) string {
	// Fields in "net user" are separated by multiple spaces
	parts := strings.Fields(line)
	if len(parts) >= 4 {
		return strings.Join(parts[3:], " ")
	}
	return ""
}

func parseHexSeconds(hex string) string {
	hex = strings.TrimPrefix(hex, "0x")
	var seconds int
	for _, c := range hex {
		if c >= '0' && c <= '9' {
			seconds = seconds*16 + int(c-'0')
		} else if c >= 'a' && c <= 'f' {
			seconds = seconds*16 + int(c-'a'+10)
		} else if c >= 'A' && c <= 'F' {
			seconds = seconds*16 + int(c-'A'+10)
		}
	}
	if seconds >= 3600 {
		return strings.TrimRight(strings.TrimRight(
			strings.Replace(
				strings.Replace(
					formatDuration(seconds), "h", "h ", 1),
				"m", "m ", 1),
			" "), " ")
	}
	if seconds >= 60 {
		minutes := seconds / 60
		if minutes == 1 {
			return "1 minute"
		}
		return strconv.Itoa(minutes) + " minutes"
	}
	return strconv.Itoa(seconds) + " seconds"
}

func formatDuration(totalSec int) string {
	h := totalSec / 3600
	m := (totalSec % 3600) / 60
	if h > 0 && m > 0 {
		return strconv.Itoa(h) + "h " + strconv.Itoa(m) + "m"
	}
	if h > 0 {
		return strconv.Itoa(h) + "h"
	}
	return strconv.Itoa(m) + "m"
}
