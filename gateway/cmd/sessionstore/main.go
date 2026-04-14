// Session Store microservice — centralized persistent session management.
// Exposes an HTTP/JSON API on :6380 for session CRUD, backed by SQLite.
// Enables horizontal scaling of portal instances.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gateway/sessionstore"
	"gateway/store"
)

func main() {
	addr := flag.String("addr", ":6380", "Listen address for session store API")
	cleanup := flag.Duration("cleanup", 60*time.Second, "Session cleanup interval")
	dataDir := flag.String("data", "/app/data", "Directory for SQLite database")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate (optional)")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key (optional)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Initialize SQLite store
	db := store.New(*dataDir)
	if err := db.InitDB(); err != nil {
		log.Fatalf("[STORE] Failed to initialize database: %v", err)
	}

	sessStore := sessionstore.New(db)

	// Register HTTP routes
	mux := http.NewServeMux()
	sessStore.RegisterRoutes(mux)

	// Start cleanup loop
	sessStore.StartCleanupLoop(*cleanup)

	// Start HTTP server
	server := &http.Server{
		Addr:              *addr,
		Handler:           http.MaxBytesHandler(mux, 1<<20), // 1 MB body limit
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if *tlsCert != "" && *tlsKey != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}

	go func() {
		log.Println("──────────────────────────────────────────")
		log.Printf("  Service:   Secure Alert Gateway — Session Store")
		log.Printf("  Listen:    %s", *addr)
		log.Printf("  Cleanup:   every %s", *cleanup)
		log.Printf("  Data:      %s", *dataDir)
		if *tlsCert != "" {
			log.Printf("  TLS:       enabled")
		}
		log.Println("──────────────────────────────────────────")

		var err error
		if *tlsCert != "" && *tlsKey != "" {
			err = server.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("[STORE] Server error: %v", err)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[STORE] Shutting down...")
	sessStore.Stop()
	db.Close()
	server.Close()
}
