package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gateway/internal/config"
	"gateway/internal/controlplane"
	"gateway/internal/dataplane"
	"gateway/internal/enrollment"
)

const shutdownWait = 5 * time.Second

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	enrollmentResult, err := enrollment.Ensure(context.Background(), cfg)
	if err != nil {
		log.Fatalf("[GATEWAY] gateway enrollment failed: %v", err)
	}
	if enrollmentResult.Status == enrollment.EnrollmentStatusCreated {
		log.Printf("[GATEWAY] enrollment completed: ID = %s", cfg.ControlPlane.GatewayID)
	} else if enrollmentResult.Status == enrollment.EnrollmentStatusExisting {
		log.Printf("[GATEWAY] existing enrollment loaded: ID = %s", cfg.ControlPlane.GatewayID)
	} else if enrollmentResult.Status == enrollment.EnrollmentStatusRenewed {
		log.Printf("[GATEWAY] expired enrollment certificate renewed: ID = %s", cfg.ControlPlane.GatewayID)
	}

	controlPlaneClient, err := controlplane.NewClient(cfg)
	if err != nil {
		log.Fatalf("[GATEWAY] failed to initialize control plane client: %v", err)
	}
	defer controlPlaneClient.Close()

	gateway := dataplane.New(cfg, controlPlaneClient, nil)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	controlErr := make(chan error, 1)
	go func() {
		controlErr <- controlPlaneClient.RunControlStream(ctx, cfg.ControlPlane.GatewayID, gateway)
	}()

	go gateway.StartCertRenewalLoop(ctx)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- gateway.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("[GATEWAY] gateway stopped: %v", err)
		}
		log.Fatal("[GATEWAY] gateway listener stopped unexpectedly")
	case err := <-controlErr:
		if ctx.Err() == nil {
			log.Fatalf("[GATEWAY] PA control plane stopped: %v", err)
		}
		shutdownGateway(gateway, serverErr, shutdownWait)
	case <-ctx.Done():
		shutdownGateway(gateway, serverErr, shutdownWait)
	}
}

func shutdownGateway(gateway *dataplane.Gateway, serverErr <-chan error, timeout time.Duration) {
	log.Printf("[GATEWAY] shutdown requested")
	gateway.Shutdown()
	select {
	case err := <-serverErr:
		if err != nil {
			log.Printf("[GATEWAY] listener stopped: %v", err)
		}
	case <-time.After(timeout):
		log.Printf("[GATEWAY] listener shutdown timed out")
	}
}
