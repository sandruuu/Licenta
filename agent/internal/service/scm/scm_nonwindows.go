//go:build !windows

package scm

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type Config struct {
	ServiceName       string
	DisplayName       string
	Description       string
	AuthorizedUserSID string
	CloudIssuer       string
	CloudURL          string
	JWKSURL           string
	CAFile            string
	DNSServer         string
	CatalogInterval   time.Duration
	TUNEnabled        bool
	TUNName           string
	TUNIP             string
	TUNNetmask        string
	TUNRouteCIDR      string
	GatewayTunnel     bool
	GatewayAddress    string
	GatewayServerName string
	ProcessIdentity   bool
}

func RunService(string, func(context.Context) error, *slog.Logger) error {
	return fmt.Errorf("Windows service mode is only supported on Windows")
}

func InstallOrUpdate(Config, *slog.Logger) error {
	return fmt.Errorf("Windows service install is only supported on Windows")
}
func Start(string, *slog.Logger) error {
	return fmt.Errorf("Windows service start is only supported on Windows")
}
func Stop(string, *slog.Logger) error {
	return fmt.Errorf("Windows service stop is only supported on Windows")
}
func Uninstall(string, *slog.Logger) error {
	return fmt.Errorf("Windows service uninstall is only supported on Windows")
}
func PrintStatus(string) error {
	return fmt.Errorf("Windows service status is only supported on Windows")
}
