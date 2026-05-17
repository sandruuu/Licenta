package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent/internal/app/bootstrap"
)

func InstallService(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if bootstrap.ElevatedInstallRequested() {
		return bootstrap.RunElevatedInstallRequest(ctx, logger)
	}
	if _, err := LoadServiceConfig(); err != nil {
		return err
	}
	installConfig, err := LoadInstallConfig()
	if err != nil {
		return err
	}
	serviceExecutable, err := resolveServiceExecutable()
	if err != nil {
		return err
	}
	installOptions := bootstrapOptions(serviceExecutable, installConfig.Timeout, installConfig.ServiceRecoveryRestartDelays)
	return bootstrap.InstallService(ctx, installOptions, logger)
}

func bootstrapOptions(serviceExecutable string, timeout time.Duration, recoveryRestartDelays []time.Duration) bootstrap.Options {
	return bootstrap.Options{
		ServiceExecutable:            serviceExecutable,
		Timeout:                      timeout,
		ServiceRecoveryRestartDelays: append([]time.Duration(nil), recoveryRestartDelays...),
	}
}

func resolveServiceExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve installer executable: %w", err)
	}
	return serviceExecutablePath(executable)
}

func serviceExecutablePath(currentExecutable string) (string, error) {
	currentExecutable = strings.TrimSpace(currentExecutable)
	if currentExecutable == "" {
		return "", fmt.Errorf("installer executable path is empty")
	}
	currentExecutable, err := filepath.Abs(currentExecutable)
	if err != nil {
		return "", fmt.Errorf("resolve absolute installer executable path: %w", err)
	}
	if strings.EqualFold(filepath.Base(currentExecutable), "ztna-agent.exe") {
		return currentExecutable, nil
	}
	target := filepath.Join(filepath.Dir(currentExecutable), "ztna-agent.exe")
	if _, err := os.Stat(target); err != nil {
		return "", fmt.Errorf("ztna-agent.exe must be placed next to %s: %w", filepath.Base(currentExecutable), err)
	}
	return target, nil
}
