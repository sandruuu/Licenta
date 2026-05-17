package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"agent/internal/shared/ipc"
)

func (service *Service) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	service.transition(StateStarting)
	service.setStartedAt(time.Now().UTC())

	listener, err := service.listenerFactory(service.AuthorizedUserSID())
	if err != nil {
		service.transition(StateDegraded)
		return fmt.Errorf("start IPC listener: %w", err)
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- ipc.Serve(ctx, listener, service)
	}()
	service.startSyntheticDNSServer(ctx)
	service.startNetworkManager(ctx)
	service.startPostureReporting(ctx)
	service.startCatalogSync(ctx)
	service.startCertificateRenewal(ctx)
	service.logger.Info("ZTNA Agent service running", "pipe", ipc.PipePath(), "protocol", ipc.ProtocolVersion, "authorized_user_sid", service.AuthorizedUserSID())
	service.transition(StateRunning)

	<-ctx.Done()
	service.transition(StateStopping)
	if service.relayForwarder != nil {
		service.relayForwarder.Close()
	}
	if service.paClient != nil {
		_ = service.paClient.Close()
	}
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			service.transition(StateStopped)
			return err
		}
	case <-time.After(2 * time.Second):
		service.logger.Warn("ZTNA Agent IPC server did not stop before timeout")
	}
	service.transition(StateStopped)
	return nil
}

func (service *Service) shouldRunSyntheticDNSServer(config Config, dependencies Dependencies) bool {
	return strings.TrimSpace(config.PAURL) != "" || dependencies.CatalogClient != nil || dependencies.CatalogCacheStore != nil
}

func (service *Service) shouldRunGatewayRelay(config Config) bool {
	return config.TUNEnabled && strings.TrimSpace(config.PAURL) != ""
}

func (service *Service) startSyntheticDNSServer(ctx context.Context) {
	if service.dnsResolverServer == nil {
		return
	}
	go func() {
		if err := service.dnsResolverServer.Run(ctx); err != nil && ctx.Err() == nil {
			service.logger.Error("ZTNA Agent local DNS server stopped", "error", err)
			service.transition(StateDegraded)
		}
	}()
}

func (service *Service) startNetworkManager(ctx context.Context) {
	if service.networkManager == nil {
		return
	}
	go func() {
		if err := service.networkManager.Run(ctx); err != nil && ctx.Err() == nil {
			service.logger.Error("ZTNA Agent TUN network manager stopped", "error", err)
			service.transition(StateDegraded)
		}
	}()
}
