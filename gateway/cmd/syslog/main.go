// Syslog Aggregator microservice — centralized structured logging.
// Receives JSON log entries over TCP from all gateway services.
// Writes daily-rotated log files and prints to stdout for SIEM integration.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	gwsyslog "gateway/syslog"
)

func main() {
	addr := flag.String("addr", ":5514", "Listen address for syslog TCP receiver")
	logDir := flag.String("logdir", "logs", "Directory for log files")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate (optional)")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key (optional)")
	authToken := flag.String("auth-token", "", "Shared token for client authentication (optional)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	server := gwsyslog.NewServer(*addr, *logDir, *tlsCert, *tlsKey, *authToken)

	log.Println("──────────────────────────────────────────")
	log.Printf("  Service:   Secure Alert Gateway — Syslog Aggregator")
	log.Printf("  Listen:    %s (TCP)", *addr)
	log.Printf("  Log Dir:   %s", *logDir)
	if *tlsCert != "" {
		log.Printf("  TLS:       enabled")
	}
	if *authToken != "" {
		log.Printf("  Auth:      token required")
	}
	log.Println("──────────────────────────────────────────")

	if err := server.Start(); err != nil {
		log.Fatalf("[SYSLOG] Failed to start: %v", err)
	}

	// Health endpoint on :8081 for Docker healthcheck / monitoring
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "ok",
				"service": "gateway-syslog",
			})
		})
		log.Printf("[SYSLOG] Health endpoint listening on :8081")
		if err := http.ListenAndServe(":8081", healthMux); err != nil {
			log.Printf("[SYSLOG] Health endpoint error: %v", err)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[SYSLOG] Shutting down...")
	server.Stop()
}
