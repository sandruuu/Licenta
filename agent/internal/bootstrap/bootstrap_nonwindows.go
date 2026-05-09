//go:build !windows

package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type Options struct {
	DemoMessage       string
	Timeout           time.Duration
	CloudIssuer       string
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
	Login             bool
	CloudURL          string
	IssuerURL         string
	ClientID          string
	Scopes            string
	DeviceID          string
	EnrollmentNonce   string
	KeyName           string
	Hostname          string
	ACRValues         string
}

func Run(context.Context, Options, *slog.Logger) error {
	return fmt.Errorf("bootstrap is only supported on Windows")
}
