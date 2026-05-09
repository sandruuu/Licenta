//go:build !windows

package tray

import "fmt"

func openBrowser(string) error {
	return fmt.Errorf("browser login is only supported on Windows for this agent milestone")
}
