package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"ztna.local/agent/internal/meta"
)

var ErrUsage = errors.New("invalid command usage")

type Command string

const (
	CommandBootstrap      Command = "bootstrap"
	CommandService        Command = "service"
	CommandRunService     Command = "run-service"
	CommandInstallService Command = "install-service"
	CommandStart          Command = "start"
	CommandStop           Command = "stop"
	CommandStatus         Command = "status"
	CommandUninstall      Command = "uninstall"
	CommandTray           Command = "tray"
	CommandHelp           Command = "help"
)

type Options struct {
	Command           Command
	AuthorizedUserSID string
	CloudIssuer       string
	CloudURL          string
	CloudCertSHA256   string
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
	IssuerURL         string
	ClientID          string
	Scopes            string
	DeviceID          string
	EnrollmentNonce   string
	KeyName           string
	Hostname          string
	ACRValues         string
	DemoMessage       string
	TrayStay          bool
	TrayProof         bool
	Timeout           time.Duration
}

func Parse(args []string) (Options, error) {
	options := Options{
		Command:     CommandBootstrap,
		DemoMessage: meta.DefaultDemoMessage,
		Timeout:     30 * time.Second,
	}
	if len(args) == 0 {
		return options, nil
	}
	command := Command(strings.ToLower(strings.TrimSpace(args[0])))
	switch command {
	case "", CommandBootstrap:
		options.Command = CommandBootstrap
		return parseBootstrap(args[1:], options)
	case CommandService:
		options.Command = CommandService
		return parseAuthorizedSID(args[1:], options, "service")
	case CommandRunService:
		options.Command = CommandRunService
		return parseAuthorizedSID(args[1:], options, "run-service")
	case CommandInstallService:
		options.Command = CommandInstallService
		return parseAuthorizedSID(args[1:], options, "install-service")
	case CommandStart, CommandStop, CommandStatus, CommandUninstall:
		options.Command = command
		if len(args) > 1 {
			return options, fmt.Errorf("%w: command %q does not accept arguments", ErrUsage, command)
		}
		return options, nil
	case CommandTray:
		options.Command = CommandTray
		return parseTray(args[1:], options)
	case CommandHelp, "-h", "--help":
		options.Command = CommandHelp
		return options, nil
	default:
		return options, fmt.Errorf("%w: unknown command %q", ErrUsage, args[0])
	}
}

func parseBootstrap(args []string, options Options) (Options, error) {
	flagSet := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.StringVar(&options.DemoMessage, "demo-message", options.DemoMessage, "message sent from the tray process")
	flagSet.BoolVar(&options.Login, "login", options.Login, "launch tray OIDC enrollment after service readiness")
	flagSet.StringVar(&options.CloudURL, "cloud-url", options.CloudURL, "Cloud base URL used by the tray for enrollment token issuance and by the service for EST simpleenroll")
	flagSet.StringVar(&options.IssuerURL, "issuer-url", options.IssuerURL, "OIDC issuer URL used by the tray")
	flagSet.StringVar(&options.ClientID, "client-id", options.ClientID, "OIDC public client ID used by the tray")
	flagSet.StringVar(&options.Scopes, "scopes", options.Scopes, "OIDC scopes requested by the tray")
	flagSet.StringVar(&options.DeviceID, "device-id", options.DeviceID, "device ID override for development when TPM EK derivation is unavailable")
	flagSet.StringVar(&options.EnrollmentNonce, "enrollment-nonce", options.EnrollmentNonce, "enrollment nonce override")
	flagSet.StringVar(&options.KeyName, "key-name", options.KeyName, "TPM key name override")
	flagSet.StringVar(&options.Hostname, "hostname", options.Hostname, "hostname sent to Cloud OIDC")
	flagSet.StringVar(&options.ACRValues, "acr-values", options.ACRValues, "OIDC acr_values requested by the tray")
	flagSet.StringVar(&options.CloudIssuer, "cloud-issuer", options.CloudIssuer, "expected Cloud JWT issuer for enrollment tokens")
	flagSet.StringVar(&options.JWKSURL, "jwks-url", options.JWKSURL, "Cloud JWKS URL used by the service for enrollment token verification")
	flagSet.StringVar(&options.CloudCertSHA256, "cloud-cert-sha256", options.CloudCertSHA256, "SHA-256 hex fingerprint of the PDP TLS certificate for pinning")
	flagSet.StringVar(&options.CAFile, "ca-file", options.CAFile, "PEM CA bundle used by the service when fetching JWKS")
	flagSet.StringVar(&options.DNSServer, "dns-server", options.DNSServer, "DNS server IP used in NRPT rules")
	flagSet.DurationVar(&options.CatalogInterval, "catalog-interval", options.CatalogInterval, "Cloud catalog refresh interval")
	flagSet.BoolVar(&options.TUNEnabled, "tun", options.TUNEnabled, "enable service-owned TUN adapter and CGNAT route management")
	flagSet.StringVar(&options.TUNName, "tun-name", options.TUNName, "Windows TUN adapter name")
	flagSet.StringVar(&options.TUNIP, "tun-ip", options.TUNIP, "IPv4 address assigned to the TUN adapter")
	flagSet.StringVar(&options.TUNNetmask, "tun-netmask", options.TUNNetmask, "IPv4 netmask assigned to the TUN adapter")
	flagSet.StringVar(&options.TUNRouteCIDR, "tun-route-cidr", options.TUNRouteCIDR, "CIDR routed to the TUN adapter")
	flagSet.BoolVar(&options.GatewayTunnel, "gateway-tunnel", options.GatewayTunnel, "enable service-owned Gateway mTLS/yamux tunnel")
	flagSet.StringVar(&options.GatewayAddress, "gateway-address", options.GatewayAddress, "Gateway host:port used by the service-owned tunnel")
	flagSet.StringVar(&options.GatewayServerName, "gateway-server-name", options.GatewayServerName, "TLS server name override for the Gateway tunnel")
	flagSet.BoolVar(&options.ProcessIdentity, "process-identity", options.ProcessIdentity, "attach Windows process identity context to Gateway connect frames")
	flagSet.DurationVar(&options.Timeout, "timeout", options.Timeout, "time to wait for service readiness")
	if err := flagSet.Parse(args); err != nil {
		return options, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if flagSet.NArg() != 0 {
		return options, fmt.Errorf("%w: bootstrap received unexpected arguments", ErrUsage)
	}
	return options, nil
}

func parseTray(args []string, options Options) (Options, error) {
	flagSet := flag.NewFlagSet("tray", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.StringVar(&options.DemoMessage, "demo-message", options.DemoMessage, "message sent to the service")
	flagSet.BoolVar(&options.TrayStay, "stay", options.TrayStay, "keep the tray process running after the IPC proof")
	flagSet.BoolVar(&options.TrayProof, "proof", options.TrayProof, "run the legacy IPC proof instead of the Wails tray GUI")
	flagSet.BoolVar(&options.Login, "login", options.Login, "run browser OIDC and submit enrollment token to the service")
	flagSet.StringVar(&options.CloudURL, "cloud-url", options.CloudURL, "Cloud base URL used for enrollment token issuance")
	flagSet.StringVar(&options.IssuerURL, "issuer-url", options.IssuerURL, "OIDC issuer URL")
	flagSet.StringVar(&options.ClientID, "client-id", options.ClientID, "OIDC public client ID")
	flagSet.StringVar(&options.Scopes, "scopes", options.Scopes, "OIDC scopes")
	flagSet.StringVar(&options.DeviceID, "device-id", options.DeviceID, "device ID override")
	flagSet.StringVar(&options.EnrollmentNonce, "enrollment-nonce", options.EnrollmentNonce, "enrollment nonce override")
	flagSet.StringVar(&options.KeyName, "key-name", options.KeyName, "TPM key name override")
	flagSet.StringVar(&options.Hostname, "hostname", options.Hostname, "hostname sent to Cloud OIDC")
	flagSet.StringVar(&options.CAFile, "ca-file", options.CAFile, "PEM CA bundle used by tray HTTP clients")
	flagSet.StringVar(&options.ACRValues, "acr-values", options.ACRValues, "OIDC acr_values")
	flagSet.DurationVar(&options.Timeout, "timeout", 10*time.Second, "time to wait for the IPC response")
	if err := flagSet.Parse(args); err != nil {
		return options, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if flagSet.NArg() != 0 {
		return options, fmt.Errorf("%w: tray received unexpected arguments", ErrUsage)
	}
	return options, nil
}

func parseAuthorizedSID(args []string, options Options, name string) (Options, error) {
	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.StringVar(&options.AuthorizedUserSID, "authorized-user-sid", options.AuthorizedUserSID, "interactive user SID allowed to access the pipe")
	flagSet.StringVar(&options.CloudIssuer, "cloud-issuer", options.CloudIssuer, "expected Cloud JWT issuer for enrollment tokens")
	flagSet.StringVar(&options.CloudURL, "cloud-url", options.CloudURL, "Cloud base URL used by the service for EST simpleenroll")
	flagSet.StringVar(&options.CloudCertSHA256, "cloud-cert-sha256", options.CloudCertSHA256, "SHA-256 hex fingerprint of the PDP TLS certificate for pinning")
	flagSet.StringVar(&options.JWKSURL, "jwks-url", options.JWKSURL, "Cloud JWKS URL used by the service for enrollment token verification")
	flagSet.StringVar(&options.CAFile, "ca-file", options.CAFile, "PEM CA bundle used by the service when fetching JWKS")
	flagSet.StringVar(&options.DNSServer, "dns-server", options.DNSServer, "DNS server IP used in NRPT rules")
	flagSet.DurationVar(&options.CatalogInterval, "catalog-interval", options.CatalogInterval, "Cloud catalog refresh interval")
	flagSet.BoolVar(&options.TUNEnabled, "tun", options.TUNEnabled, "enable service-owned TUN adapter and CGNAT route management")
	flagSet.StringVar(&options.TUNName, "tun-name", options.TUNName, "Windows TUN adapter name")
	flagSet.StringVar(&options.TUNIP, "tun-ip", options.TUNIP, "IPv4 address assigned to the TUN adapter")
	flagSet.StringVar(&options.TUNNetmask, "tun-netmask", options.TUNNetmask, "IPv4 netmask assigned to the TUN adapter")
	flagSet.StringVar(&options.TUNRouteCIDR, "tun-route-cidr", options.TUNRouteCIDR, "CIDR routed to the TUN adapter")
	flagSet.BoolVar(&options.GatewayTunnel, "gateway-tunnel", options.GatewayTunnel, "enable service-owned Gateway mTLS/yamux tunnel")
	flagSet.StringVar(&options.GatewayAddress, "gateway-address", options.GatewayAddress, "Gateway host:port used by the service-owned tunnel")
	flagSet.StringVar(&options.GatewayServerName, "gateway-server-name", options.GatewayServerName, "TLS server name override for the Gateway tunnel")
	flagSet.BoolVar(&options.ProcessIdentity, "process-identity", options.ProcessIdentity, "attach Windows process identity context to Gateway connect frames")
	if err := flagSet.Parse(args); err != nil {
		return options, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if flagSet.NArg() != 0 {
		return options, fmt.Errorf("%w: %s received unexpected arguments", ErrUsage, name)
	}
	return options, nil
}

func PrintUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Usage: ztna-agent [bootstrap|service|run-service|install-service|start|stop|status|uninstall|tray]")
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "Commands:")
	fmt.Fprintln(writer, "  bootstrap       Install/start the LocalSystem service and launch the tray proof")
	fmt.Fprintln(writer, "  service         Run as the Windows service entrypoint")
	fmt.Fprintln(writer, "  run-service     Run the service in console mode for development")
	fmt.Fprintln(writer, "  install-service Install or update the Windows service, then start it")
	fmt.Fprintln(writer, "  start           Start the installed Windows service")
	fmt.Fprintln(writer, "  stop            Stop the installed Windows service")
	fmt.Fprintln(writer, "  status          Print installed Windows service state")
	fmt.Fprintln(writer, "  uninstall       Stop and remove the Windows service")
	fmt.Fprintln(writer, "  tray            Run the user-context Wails tray GUI")
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "Enrollment verification flags for bootstrap/service/install-service/run-service:")
	fmt.Fprintln(writer, "  --cloud-issuer        Expected Cloud JWT issuer")
	fmt.Fprintln(writer, "  --cloud-url           Cloud base URL used for service EST simpleenroll")
	fmt.Fprintln(writer, "  --cloud-cert-sha256   SHA-256 hex fingerprint of the PDP TLS certificate for pinning")
	fmt.Fprintln(writer, "  --jwks-url            Cloud JWKS URL used by the service")
	fmt.Fprintln(writer, "  --ca-file             PEM CA bundle for JWKS TLS validation")
	fmt.Fprintln(writer, "  --tun           Enable service-owned TUN adapter and CGNAT route management")
	fmt.Fprintln(writer, "  --gateway-tunnel Enable service-owned Gateway mTLS/yamux tunnel")
	fmt.Fprintln(writer, "  --gateway-address Gateway host:port used by the service tunnel")
}
