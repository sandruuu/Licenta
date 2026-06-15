package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("=== TrustCloud Service (PA + PE) ===")

	cfg := loadConfig("config.json")
	ensureDataDir(cfg)

	shutdownCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	runtimeState := initializeRuntimeState(shutdownCtx, cfg)
	defer runtimeState.Close()

	pdpIdentity := initializePDPIdentity(shutdownCtx, cfg, runtimeState)

	stopChan := make(chan struct{})
	dataStore := initializeStore(cfg, stopChan)
	defer dataStore.Close()
	policyAdmin := initializePolicyAdministrator(cfg, dataStore, runtimeState, stopChan)
	transportErr := startPolicyAdministratorTransport(shutdownCtx, cfg, policyAdmin, pdpIdentity)

	waitForShutdown(shutdownCtx, stopChan, transportErr)
}
