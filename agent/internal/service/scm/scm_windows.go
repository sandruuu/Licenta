//go:build windows

package scm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	windowsEventServiceStarted uint32 = 1000
	windowsEventServiceStopped uint32 = 1001
	windowsEventServiceFailed  uint32 = 1002
)

type Config struct {
	ExecutablePath        string
	ServiceName           string
	DisplayName           string
	Description           string
	RecoveryRestartDelays []time.Duration
}

func RunService(serviceName string, run func(context.Context) error, logger *slog.Logger) error {
	if IsServiceContext() {
		return svc.Run(serviceName, &windowsService{serviceName: serviceName, run: run})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return run(ctx)
}

func IsServiceContext() bool {
	interactive, err := svc.IsAnInteractiveSession()
	return err == nil && !interactive
}

func InstallOrUpdate(config Config, logger *slog.Logger) error {
	executable := strings.TrimSpace(config.ExecutablePath)
	if executable == "" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return fmt.Errorf("resolve executable: %w", err)
		}
	}
	var err error
	executable, err = filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf("resolve absolute executable path: %w", err)
	}
	if _, err := os.Stat(executable); err != nil {
		return fmt.Errorf("stat service executable: %w", err)
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Service Control Manager: %w", err)
	}
	defer manager.Disconnect()

	mgrConfig := mgr.Config{
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      config.DisplayName,
		Description:      config.Description,
		DelayedAutoStart: true,
	}
	service, err := manager.OpenService(config.ServiceName)
	if err == nil {
		defer service.Close()
		currentConfig, err := service.Config()
		if err != nil {
			return fmt.Errorf("read existing service configuration: %w", err)
		}
		currentConfig.BinaryPathName = binaryPath(executable)
		currentConfig.StartType = mgr.StartAutomatic
		currentConfig.ErrorControl = mgr.ErrorNormal
		currentConfig.DisplayName = config.DisplayName
		currentConfig.Description = config.Description
		currentConfig.DelayedAutoStart = true
		if err := service.UpdateConfig(currentConfig); err != nil {
			return fmt.Errorf("update service configuration: %w", err)
		}
		if err := configureRecovery(service, config.RecoveryRestartDelays); err != nil {
			return err
		}
		if err := installEventSource(config.ServiceName); err != nil {
			return err
		}
		logger.Info("ZTNA Agent Windows service updated", "service", config.ServiceName, "path", executable)
		return nil
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("open service: %w", err)
	}
	service, err = manager.CreateService(config.ServiceName, executable, mgrConfig)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer service.Close()
	if err := configureRecovery(service, config.RecoveryRestartDelays); err != nil {
		return err
	}
	if err := installEventSource(config.ServiceName); err != nil {
		return err
	}
	logger.Info("ZTNA Agent Windows service installed", "service", config.ServiceName, "path", executable)
	return nil
}

func Start(serviceName string, logger *slog.Logger) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return fmt.Errorf("query service status: %w", err)
	}
	if status.State == svc.Running {
		logger.Info("ZTNA Agent Windows service is already running", "service", serviceName)
		return nil
	}
	if status.State == svc.StopPending {
		if err := waitState(service, svc.Stopped, 30*time.Second); err != nil {
			return err
		}
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	if err := waitState(service, svc.Running, 30*time.Second); err != nil {
		return err
	}
	logger.Info("ZTNA Agent Windows service started", "service", serviceName)
	return nil
}

func Stop(serviceName string, logger *slog.Logger) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	if err := stopHandle(service); err != nil {
		return err
	}
	logger.Info("ZTNA Agent Windows service stopped", "service", serviceName)
	return nil
}

func Uninstall(serviceName string, logger *slog.Logger) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			_ = removeEventSource(serviceName)
			logger.Info("ZTNA Agent Windows service is not installed", "service", serviceName)
			return nil
		}
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	if err := stopHandle(service); err != nil && !isServiceNotRunningError(err) {
		return err
	}
	if err := service.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	if err := removeEventSource(serviceName); err != nil {
		return err
	}
	logger.Info("ZTNA Agent Windows service uninstalled", "service", serviceName)
	return nil
}

func PrintStatus(serviceName string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return fmt.Errorf("query service status: %w", err)
	}
	fmt.Printf("%s: %s\n", serviceName, stateName(status.State))
	return nil
}

func binaryPath(executable string) string {
	return syscall.EscapeArg(executable)
}

func configureRecovery(service *mgr.Service, restartDelays []time.Duration) error {
	if len(restartDelays) == 0 {
		return fmt.Errorf("service recovery restart delays are required")
	}
	actions := make([]mgr.RecoveryAction, 0, len(restartDelays))
	for _, delay := range restartDelays {
		if delay <= 0 {
			return fmt.Errorf("service recovery restart delays must be greater than zero")
		}
		actions = append(actions, mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: delay})
	}
	if err := service.SetRecoveryActions(actions, 24*60*60); err != nil {
		return fmt.Errorf("configure service recovery actions: %w", err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("configure service recovery on non-crash failures: %w", err)
	}
	return nil
}

func waitState(service *mgr.Service, desired svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := service.Query()
		if err != nil {
			return fmt.Errorf("query service status: %w", err)
		}
		if status.State == desired {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for service to reach %s", stateName(desired))
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func stopHandle(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return fmt.Errorf("query service status: %w", err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State == svc.StopPending {
		return waitState(service, svc.Stopped, 30*time.Second)
	}
	_, err = service.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	return waitState(service, svc.Stopped, 30*time.Second)
}

func stateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	default:
		return fmt.Sprintf("unknown(%d)", state)
	}
}

func installEventSource(serviceName string) error {
	err := eventlog.InstallAsEventCreate(serviceName, eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil && !strings.Contains(err.Error(), "registry key already exists") {
		return fmt.Errorf("install Windows event source: %w", err)
	}
	return nil
}

func removeEventSource(serviceName string) error {
	if err := eventlog.Remove(serviceName); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("remove Windows event source: %w", err)
	}
	return nil
}

func logEvent(serviceName string, eventType uint16, eventID uint32, message string) {
	log, err := eventlog.Open(serviceName)
	if err != nil {
		return
	}
	defer log.Close()
	switch eventType {
	case eventlog.Error:
		_ = log.Error(eventID, message)
	case eventlog.Warning:
		_ = log.Warning(eventID, message)
	default:
		_ = log.Info(eventID, message)
	}
}

func isServiceNotRunningError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not been started")
}

type windowsService struct {
	serviceName string
	run         func(context.Context) error
}

func (service *windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	changes <- svc.Status{State: svc.StartPending}
	logEvent(service.serviceName, eventlog.Info, windowsEventServiceStarted, "ZTNA Agent service is starting")
	go func() { result <- service.run(ctx) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	logEvent(service.serviceName, eventlog.Info, windowsEventServiceStarted, "ZTNA Agent service is running")

	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-result; err != nil {
					logEvent(service.serviceName, eventlog.Error, windowsEventServiceFailed, "ZTNA Agent service stopped with error: "+err.Error())
					return false, 1
				}
				logEvent(service.serviceName, eventlog.Info, windowsEventServiceStopped, "ZTNA Agent service stopped")
				return false, 0
			default:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case err := <-result:
			if err != nil {
				logEvent(service.serviceName, eventlog.Error, windowsEventServiceFailed, "ZTNA Agent service exited with error: "+err.Error())
				return false, 1
			}
			logEvent(service.serviceName, eventlog.Info, windowsEventServiceStopped, "ZTNA Agent service exited")
			return false, 0
		}
	}
}
