//go:build windows

package tray

import (
	"fmt"
	"os/exec"
	"strings"
)

func openBrowser(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("browser URL is required")
	}
	return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", rawURL).Start()
}
