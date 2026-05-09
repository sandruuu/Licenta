package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gateway/internal/auth"
	"gateway/internal/config"
	"gateway/internal/controlplane"
	"gateway/internal/dataplane"
	"gateway/internal/enrollment"
	"gateway/internal/relay"
)

func main() {
	configPath := flag.String("config", "gateway-config.json", "path to gateway config JSON")
	healthAddr := flag.String("health-addr", ":8080", "health endpoint listen address")
	flag.Parse()

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	startupCtx, startupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	enrollmentResult, err := enrollment.Ensure(startupCtx, cfg)
	startupCancel()
	if err != nil {
		log.Fatalf("gateway enrollment failed: %v", err)
	}
	if enrollmentResult.Enrolled {
		if err := cfg.SaveToFile(*configPath); err != nil {
			log.Fatalf("save enrolled gateway config: %v", err)
		}
		log.Printf("[GATEWAY] enrollment completed for gateway_id=%s", enrollmentResult.GatewayID)
	}

	cloudClient, err := auth.NewCloudClient(cfg)
	if err != nil {
		log.Fatalf("initialize cloud client: %v", err)
	}
	defer cloudClient.Close()

	gateway := dataplane.New(cfg, cloudClient, relay.New())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if cfg.ControlPlane != nil && cfg.ControlPlane.Enabled {
		controlClient, err := controlplane.NewClient(controlplane.Config{
			PAURL:           firstNonEmpty(cfg.ControlPlane.PAURL, cfg.CloudURL),
			GatewayID:       cfg.ControlPlane.GatewayID,
			GatewayEndpoint: cfg.ControlPlane.GatewayEndpoint,
			ServerName:      cfg.ControlPlane.ServerName,
			CAFile:          firstNonEmpty(cfg.ControlPlane.CAFile, cfg.CloudCA, cfg.TLSCA),
			CertFile:        firstNonEmpty(cfg.ControlPlane.CertFile, cfg.MTLSCert),
			KeyFile:         firstNonEmpty(cfg.ControlPlane.KeyFile, cfg.MTLSKey),
			ReconnectMin:    seconds(cfg.ControlPlane.ReconnectMinSeconds),
			ReconnectMax:    seconds(cfg.ControlPlane.ReconnectMaxSeconds),
		}, gateway)
		if err != nil {
			log.Fatalf("initialize PA control plane: %v", err)
		}
		go controlClient.Run(ctx)
		log.Printf("[GATEWAY] PA control plane enabled for gateway_id=%s", cfg.ControlPlane.GatewayID)
	} else {
		log.Printf("[GATEWAY] PA control plane disabled; Gateway will accept only sessions already provisioned in-process")
	}

	certRenewalStop := make(chan struct{})
	go gateway.StartCertRenewalLoop(certRenewalStop)

	healthServer := startHealthServer(*healthAddr, gateway)
	defer shutdownHealthServer(healthServer)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- gateway.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("gateway stopped: %v", err)
		}
	case <-ctx.Done():
		log.Printf("[GATEWAY] shutdown requested")
		gateway.Shutdown()
		close(certRenewalStop)
		select {
		case err := <-serverErr:
			if err != nil {
				log.Printf("[GATEWAY] listener stopped: %v", err)
			}
		case <-time.After(5 * time.Second):
			log.Printf("[GATEWAY] listener shutdown timed out")
		}
	}
}

func startHealthServer(addr string, gateway *dataplane.Gateway) *http.Server {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":               "ok",
			"role":                 "gateway-pep",
			"provisioned_sessions": gateway.ProvisionedSessionCount(),
		})
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[GATEWAY] health server failed: %v", err)
		}
	}()
	return server
}

func shutdownHealthServer(server *http.Server) {
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func seconds(value int) time.Duration {
	if value <= 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}
