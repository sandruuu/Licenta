//go:build windows

package host

import (
	"context"
	"log/slog"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	windowsEventServiceStarted uint32 = 1000
	windowsEventServiceStopped uint32 = 1001
	windowsEventServiceFailed  uint32 = 1002
)

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

type windowsService struct {
	serviceName string
	run         func(context.Context) error
}

func (service *windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	changes <- svc.Status{State: svc.StartPending}
	logEvent(service.serviceName, eventlog.Info, windowsEventServiceStarted, "TrustAgent service is starting")
	go func() { result <- service.run(ctx) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	logEvent(service.serviceName, eventlog.Info, windowsEventServiceStarted, "TrustAgent service is running")

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
					logEvent(service.serviceName, eventlog.Error, windowsEventServiceFailed, "TrustAgent service stopped with error: "+err.Error())
					return false, 1
				}
				logEvent(service.serviceName, eventlog.Info, windowsEventServiceStopped, "TrustAgent service stopped")
				return false, 0
			default:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case err := <-result:
			if err != nil {
				logEvent(service.serviceName, eventlog.Error, windowsEventServiceFailed, "TrustAgent service exited with error: "+err.Error())
				return false, 1
			}
			logEvent(service.serviceName, eventlog.Info, windowsEventServiceStopped, "TrustAgent service exited")
			return false, 0
		}
	}
}
