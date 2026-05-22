package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"agent/internal/shared/ipc"
)

func (service *Service) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	service.transition(StateStarting)
	service.setStartedAt(time.Now().UTC())
	service.enrollment.Refresh(ctx)

	listener, err := service.listenerFactory()
	if err != nil {
		service.transition(StateDegraded)
		return fmt.Errorf("start IPC listener: %w", err)
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- ipc.Serve(ctx, listener, service)
	}()
	go service.runProtectedResources(ctx)
	go service.runDeviceDataSync(ctx)
	service.logger.Info("TrustAgent service running", "pipe", ipc.PipePath(), "protocol", ipc.ProtocolVersion)
	service.transition(StateRunning)

	<-ctx.Done()
	service.transition(StateStopping)
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			service.transition(StateStopped)
			return err
		}
	case <-time.After(2 * time.Second):
		service.logger.Warn("TrustAgent IPC server did not stop before timeout")
	}
	service.transition(StateStopped)
	return nil
}

func (service *Service) runProtectedResources(ctx context.Context) {
	if service == nil || service.protectedResources == nil {
		return
	}
	if err := service.protectedResources.Run(ctx); err != nil && ctx.Err() == nil {
		service.logger.Warn("protected resources manager stopped", "error", err)
	}
}

func (service *Service) runDeviceDataSync(ctx context.Context) {
	if service == nil || service.deviceDataSync == nil {
		return
	}
	service.deviceDataSync.Run(ctx)
}
