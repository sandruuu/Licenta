package main

import (
	"context"
	"log"
)

func waitForShutdown(ctx context.Context, stopChan chan struct{}, transportErr <-chan error) {
	log.Println("=== TrustCloud running. Press Ctrl+C to stop. ===")
	select {
	case err := <-transportErr:
		close(stopChan)
		if err != nil {
			log.Fatalf("PA transport server error: %v", err)
		}
		return
	case <-ctx.Done():
	}

	log.Println("\n=== Shutting down... ===")
	if err := <-transportErr; err != nil {
		log.Printf("PA transport shutdown error: %v", err)
	}
	close(stopChan)
	log.Println("=== Shutdown complete ===")
}
