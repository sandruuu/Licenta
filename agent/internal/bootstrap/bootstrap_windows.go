//go:build windows

package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"ztna.local/agent/internal/ipc"
	"ztna.local/agent/internal/meta"
	"ztna.local/agent/internal/process"
	"ztna.local/agent/internal/service/scm"
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

func Run(ctx context.Context, options Options, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Second
	}
	identity := process.Current()
	if strings.TrimSpace(identity.UserSID) == "" {
		return fmt.Errorf("current Windows user SID is required")
	}
	message := strings.TrimSpace(options.DemoMessage)
	if message == "" {
		message = meta.DefaultDemoMessage
	}
	if process.IsElevated() {
		if err := installAndStartService(identity.UserSID, options, logger); err != nil {
			return err
		}
	} else {
		if err := runElevatedInstall(ctx, identity.UserSID, options, logger); err != nil {
			return err
		}
	}
	if err := waitForService(ctx, options.Timeout, identity, logger); err != nil {
		return err
	}
	return launchTray(ctx, message, options, logger)
}

func installAndStartService(userSID string, options Options, logger *slog.Logger) error {
	if err := scm.InstallOrUpdate(scm.Config{
		ServiceName:       meta.ServiceName,
		DisplayName:       meta.ServiceDisplayName,
		Description:       meta.ServiceDescription,
		AuthorizedUserSID: userSID,
		CloudIssuer:       options.CloudIssuer,
		CloudURL:          options.CloudURL,
		JWKSURL:           options.JWKSURL,
		CAFile:            options.CAFile,
		DNSServer:         options.DNSServer,
		CatalogInterval:   options.CatalogInterval,
		TUNEnabled:        options.TUNEnabled,
		TUNName:           options.TUNName,
		TUNIP:             options.TUNIP,
		TUNNetmask:        options.TUNNetmask,
		TUNRouteCIDR:      options.TUNRouteCIDR,
		GatewayTunnel:     options.GatewayTunnel,
		GatewayAddress:    options.GatewayAddress,
		GatewayServerName: options.GatewayServerName,
		ProcessIdentity:   options.ProcessIdentity,
	}, logger); err != nil {
		return err
	}
	return scm.Start(meta.ServiceName, logger)
}

func runElevatedInstall(ctx context.Context, userSID string, options Options, logger *slog.Logger) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	args := []string{"install-service", "--authorized-user-sid", userSID}
	if strings.TrimSpace(options.CloudIssuer) != "" {
		args = append(args, "--cloud-issuer", options.CloudIssuer)
	}
	if strings.TrimSpace(options.CloudURL) != "" {
		args = append(args, "--cloud-url", options.CloudURL)
	}
	if strings.TrimSpace(options.JWKSURL) != "" {
		args = append(args, "--jwks-url", options.JWKSURL)
	}
	if strings.TrimSpace(options.CAFile) != "" {
		args = append(args, "--ca-file", options.CAFile)
	}
	if strings.TrimSpace(options.DNSServer) != "" {
		args = append(args, "--dns-server", options.DNSServer)
	}
	if options.CatalogInterval > 0 {
		args = append(args, "--catalog-interval", options.CatalogInterval.String())
	}
	if options.TUNEnabled {
		args = append(args, "--tun")
	}
	if options.GatewayTunnel {
		args = append(args, "--gateway-tunnel")
	}
	if options.ProcessIdentity {
		args = append(args, "--process-identity")
	}
	appendStringArg := func(name, value string) {
		if strings.TrimSpace(value) != "" {
			args = append(args, name, value)
		}
	}
	appendStringArg("--tun-name", options.TUNName)
	appendStringArg("--tun-ip", options.TUNIP)
	appendStringArg("--tun-netmask", options.TUNNetmask)
	appendStringArg("--tun-route-cidr", options.TUNRouteCIDR)
	appendStringArg("--gateway-address", options.GatewayAddress)
	appendStringArg("--gateway-server-name", options.GatewayServerName)
	command := fmt.Sprintf("Start-Process -FilePath %s -ArgumentList %s -Verb RunAs -Wait", quotePowerShell(executable), powerShellArray(args))
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	logger.Info("Requesting elevation to install/start ZTNA Agent service")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run elevated install helper: %w", err)
	}
	return nil
}

func waitForService(ctx context.Context, timeout time.Duration, identity process.Identity, logger *slog.Logger) error {
	deadline := time.Now().Add(timeout)
	for {
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		var response ipc.PingResponse
		err := ipc.NewDefaultClient().Call(callCtx, ipc.OperationPing, ipc.PingRequest{
			Message:     "bootstrap readiness probe",
			TrayPID:     identity.PID,
			TrayUser:    identity.Username,
			TrayUserSID: identity.UserSID,
			SentAt:      time.Now().UTC(),
		}, &response)
		cancel()
		if err == nil {
			logger.Info("ZTNA Agent service IPC is ready", "service_pid", response.ServicePID, "service_user", response.ServiceUser)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wait for service IPC readiness: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func launchTray(ctx context.Context, message string, options Options, logger *slog.Logger) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	args := []string{"tray", "--demo-message", message, "--stay"}
	if options.Login {
		args = append(args, "--login")
	}
	appendStringFlag := func(name, value string) {
		if strings.TrimSpace(value) != "" {
			args = append(args, name, value)
		}
	}
	appendStringFlag("--cloud-url", options.CloudURL)
	appendStringFlag("--issuer-url", options.IssuerURL)
	appendStringFlag("--client-id", options.ClientID)
	appendStringFlag("--scopes", options.Scopes)
	appendStringFlag("--device-id", options.DeviceID)
	appendStringFlag("--enrollment-nonce", options.EnrollmentNonce)
	appendStringFlag("--key-name", options.KeyName)
	appendStringFlag("--hostname", options.Hostname)
	appendStringFlag("--ca-file", options.CAFile)
	appendStringFlag("--acr-values", options.ACRValues)
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch tray process: %w", err)
	}
	logger.Info("ZTNA Agent tray process launched", "pid", cmd.Process.Pid)
	return nil
}

func quotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func powerShellArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, quotePowerShell(value))
	}
	return "@(" + strings.Join(quoted, ",") + ")"
}
