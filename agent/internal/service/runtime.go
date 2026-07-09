package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"agent/internal/ipc"
)

func (service *Service) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	defer service.closePDPClient()
	service.transition(StateStarting)
	service.setStartedAt(time.Now().UTC())

	listener, err := service.listenerFactory()
	if err != nil {
		service.transition(StateDegraded)
		return fmt.Errorf("start IPC listener: %w", err)
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- ipc.Serve(ctx, listener, service)
	}()
	go service.refreshEnrollment(ctx)
	go service.runProtectedResources(ctx)
	go service.runDeviceDataSync(ctx)
	go service.runAgentEvents(ctx)
	go service.runCertificateRenewal(ctx)
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

func (service *Service) refreshEnrollment(ctx context.Context) {
	if service == nil || service.enrollment == nil {
		return
	}
	service.enrollment.Refresh(ctx)
}

func (service *Service) closePDPClient() {
	if service == nil || service.pdpClient == nil {
		return
	}
	if err := service.pdpClient.Close(); err != nil {
		service.logger.Warn("failed to close PDP gRPC client", "error", err)
	}
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

func (service *Service) runCertificateRenewal(ctx context.Context) {
	if service == nil || service.enrollment == nil {
		return
	}
	service.enrollment.RunCertificateRenewal(ctx)
}
