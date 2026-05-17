//go:build windows

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agent/internal/platform/process"
	"agent/internal/service/scm"
	"agent/internal/shared/ipc"
	"agent/internal/shared/meta"
)

const (
	elevatedInstallEnv        = "ZTNA_AGENT_ELEVATED_INSTALL"
	elevatedInstallRequestEnv = "ZTNA_AGENT_INSTALL_REQUEST"
)

type Options struct {
	ServiceExecutable            string
	Timeout                      time.Duration
	ServiceRecoveryRestartDelays []time.Duration
}

type installRequest struct {
	Options Options `json:"options"`
}

func ElevatedInstallRequested() bool {
	return strings.TrimSpace(os.Getenv(elevatedInstallEnv)) == "1"
}

func RunElevatedInstallRequest(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !process.IsElevated() {
		return fmt.Errorf("elevated install request requires administrator privileges")
	}
	requestPath := strings.TrimSpace(os.Getenv(elevatedInstallRequestEnv))
	if requestPath == "" {
		return fmt.Errorf("elevated install request path is not configured")
	}
	request, err := readInstallRequest(requestPath)
	if err != nil {
		return err
	}
	defer os.Remove(requestPath)
	return installAndStartService(request.Options, logger)
}

func InstallService(ctx context.Context, options Options, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Timeout <= 0 {
		return fmt.Errorf("install timeout is required")
	}
	identity := process.Current()
	if process.IsElevated() {
		if err := installAndStartService(options, logger); err != nil {
			return err
		}
	} else {
		if err := runElevatedInstall(ctx, options, logger); err != nil {
			return err
		}
	}
	if err := waitForService(ctx, options.Timeout, identity, logger); err != nil {
		return err
	}
	return nil
}

func installAndStartService(options Options, logger *slog.Logger) error {
	if err := scm.InstallOrUpdate(serviceConfig(options), logger); err != nil {
		return err
	}
	return scm.Start(meta.ServiceName, logger)
}

func runElevatedInstall(ctx context.Context, options Options, logger *slog.Logger) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	requestPath, err := writeInstallRequest(options)
	if err != nil {
		return err
	}
	defer os.Remove(requestPath)
	command := fmt.Sprintf(
		"$env:%s=%s; $env:%s=%s; Start-Process -FilePath %s -Verb RunAs -Wait",
		elevatedInstallEnv,
		quotePowerShell("1"),
		elevatedInstallRequestEnv,
		quotePowerShell(requestPath),
		quotePowerShell(executable),
	)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	logger.Info("Requesting elevation to install/start ZTNA Agent service")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run elevated install helper: %w", err)
	}
	return nil
}

func writeInstallRequest(options Options) (string, error) {
	dir := filepath.Join(os.TempDir(), "ztna-agent")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create install request directory: %w", err)
	}
	file, err := os.CreateTemp(dir, "install-*.json")
	if err != nil {
		return "", fmt.Errorf("create install request: %w", err)
	}
	path := file.Name()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(installRequest{Options: options}); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("encode install request: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close install request: %w", err)
	}
	return path, nil
}

func readInstallRequest(path string) (installRequest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return installRequest{}, fmt.Errorf("read install request: %w", err)
	}
	var request installRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return installRequest{}, fmt.Errorf("decode install request: %w", err)
	}
	return request, nil
}

func serviceConfig(options Options) scm.Config {
	return scm.Config{
		ExecutablePath:        strings.TrimSpace(options.ServiceExecutable),
		ServiceName:           meta.ServiceName,
		DisplayName:           meta.ServiceDisplayName,
		Description:           meta.ServiceDescription,
		RecoveryRestartDelays: append([]time.Duration(nil), options.ServiceRecoveryRestartDelays...),
	}
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

func quotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
