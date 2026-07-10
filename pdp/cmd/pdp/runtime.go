package main

import (
	"context"
	"log"

	"pdp/config"
	"pdp/pa"
	"pdp/pa/transport"
	"pdp/runtime/redisstate"
	"pdp/store"
)

func initializeStore(cfg *config.Config, stopChan <-chan struct{}) *store.Store {
	dataStore := store.NewWithDatabaseURL(cfg.DataDir, cfg.DatabaseURL)
	if err := dataStore.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	dataStore.StartAutoSave(cfg.Runtime.StoreAutoSaveInterval, stopChan)
	log.Println("[STORE] PostgreSQL database ready")
	return dataStore
}

func initializeRuntimeState(ctx context.Context, cfg *config.Config) *redisstate.Client {
	runtimeState, err := redisstate.Open(ctx, cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to initialize Redis runtime state: %v", err)
	}
	log.Println("[REDIS] Runtime state ready")
	return runtimeState
}

func initializePolicyAdministrator(cfg *config.Config, dataStore *store.Store, runtimeState *redisstate.Client, stopChan <-chan struct{}) *pa.PolicyAdministrator {
	policyAdmin := pa.NewPolicyAdministrator(cfg, dataStore, runtimeState)

	policyAdmin.Sessions.StartCleanupLoop(cfg.Runtime.SessionCleanupInterval, stopChan)
	policyAdmin.Enrollment.StartCleanupLoop(cfg.Runtime.EnrollmentCleanupInterval, stopChan)
	return policyAdmin
}

func startPolicyAdministratorTransport(ctx context.Context, cfg *config.Config, policyAdmin *pa.PolicyAdministrator, identity *pdpIdentityState) <-chan error {
	server, err := transport.NewServer(policyAdmin, cfg.ListenAddr, cfg.MTLSCA)
	if err != nil {
		log.Fatalf("Failed to initialize PA transport server: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.StartTLS(ctx, identity.getCertificate)
	}()
	return errCh
}
