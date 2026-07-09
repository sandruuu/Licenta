package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("[KEYCLOAK-SCIM] Invalid config: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.PDPTLSSkipVerify}, //nolint:gosec // local lab connector supports self-signed PDP TLS.
		},
	}
	kc := &keycloakClient{
		baseURL:   cfg.KeycloakBaseURL,
		realm:     cfg.KeycloakRealm,
		authRealm: cfg.KeycloakAuthRealm,
		clientID:  cfg.KeycloakClientID,
		secret:    cfg.KeycloakClientSecret,
		username:  cfg.KeycloakUsername,
		password:  cfg.KeycloakPassword,
		pageSize:  cfg.PageSize,
		http:      httpClient,
	}
	scim := &scimClient{
		baseURL: cfg.PDPSCIMBaseURL,
		token:   cfg.PDPSCIMToken,
		http:    httpClient,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	run := func() {
		start := time.Now()
		stats, err := syncDirectory(ctx, cfg, kc, scim)
		if err != nil {
			log.Printf("[KEYCLOAK-SCIM] Sync failed: %v", err)
			return
		}
		log.Printf("[KEYCLOAK-SCIM] Sync completed in %s: users=%d groups=%d disabled_missing_users=%d deleted_missing_groups=%d",
			time.Since(start).Round(time.Millisecond), stats.UsersUpserted, stats.GroupsUpserted, stats.UsersDeprovisioned, stats.GroupsDeprovisioned)
	}

	run()
	if cfg.SyncOnce {
		return
	}

	ticker := time.NewTicker(cfg.SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[KEYCLOAK-SCIM] Stopping")
			return
		case <-ticker.C:
			run()
		}
	}
}
