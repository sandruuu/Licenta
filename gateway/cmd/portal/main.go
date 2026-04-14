// Portal Data Plane microservice — the PEP (Policy Enforcement Point).
// Handles TLS/yamux connections from connect-app on :9443,
// validates authentication, enforces access policies via the cloud,
// and relays traffic to internal resources.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	gwadmin "gateway/admin"
	"gateway/internal/auth"
	"gateway/internal/cgnat"
	"gateway/internal/config"
	gwdns "gateway/internal/dns"
	"gateway/internal/relay"
	"gateway/portal"
	"gateway/sessionstore"
	"gateway/store"
	"gateway/syslog"
)

func main() {
	configPath := flag.String("config", "gateway-config.json", "Path to gateway config file")
	storeURL := flag.String("store-url", "http://localhost:6380", "Session store URL")
	syslogAddr := flag.String("syslog-addr", "localhost:5514", "Syslog aggregator address")
	dataDir := flag.String("data", "/app/data", "Directory for SQLite database")
	storeTLSCA := flag.String("store-tls-ca", "", "CA cert for session store TLS (optional)")
	syslogTLSCA := flag.String("syslog-tls-ca", "", "CA cert for syslog TLS (optional)")
	syslogToken := flag.String("syslog-auth-token", "", "Auth token for syslog (optional)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Load config
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Fatalf("[PORTAL] Failed to load config: %v", err)
	}

	// Generate self-signed TLS cert if none configured (first boot)
	if err := gwadmin.GenerateSelfSignedCert(cfg, *configPath); err != nil {
		log.Printf("[PORTAL] WARNING: Failed to generate self-signed cert: %v", err)
	}

	// Initialize components
	cloudClient, err := auth.NewCloudClient(cfg)
	if err != nil {
		log.Fatalf("[PORTAL] Cloud client init failed: %v", err)
	}
	var storeTLS *tls.Config
	if *storeTLSCA != "" {
		pem, err := os.ReadFile(*storeTLSCA)
		if err != nil {
			log.Fatalf("[PORTAL] Failed to read store TLS CA: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		storeTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	}
	var syslogTLS *tls.Config
	if *syslogTLSCA != "" {
		pem, err := os.ReadFile(*syslogTLSCA)
		if err != nil {
			log.Fatalf("[PORTAL] Failed to read syslog TLS CA: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		syslogTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	}
	sessClient := sessionstore.NewClient(*storeURL, storeTLS)
	syslogClient := syslog.NewClient(*syslogAddr, "portal", syslogTLS, *syslogToken)

	// Initialize SQLite store (read-only for portal — shared DB)
	db := store.New(*dataDir)
	if err := db.InitDB(); err != nil {
		log.Fatalf("[PORTAL] Failed to initialize database: %v", err)
	}

	relayMgr := relay.New(db)
	dnsResolver := gwdns.New(cfg, db)

	// Initialize dynamic CGNAT allocator with TTL-based garbage collection
	var cgnatAlloc *cgnat.Allocator
	if cfg.CGNAT != nil && cfg.CGNAT.Enabled {
		var err error
		// Default TTL: 60 seconds — mappings expire if not refreshed.
		// GC runs every 15 seconds to clean up stale entries.
		cgnatTTL := 5 * time.Minute
		cgnatGCInterval := 30 * time.Second
		cgnatAlloc, err = cgnat.NewAllocator(cfg.CGNAT.PoolStart, cfg.CGNAT.PoolEnd, cgnatTTL, cgnatGCInterval)
		if err != nil {
			log.Printf("[PORTAL] CGNAT allocator failed: %v", err)
		} else {
			defer cgnatAlloc.Stop()
		}
	}

	log.Println("──────────────────────────────────────────")
	log.Printf("  Service:   Secure Alert Gateway — Portal (Data Plane / PEP)")
	log.Printf("  Listen:    %s", cfg.ListenAddr)
	if cfg.TLSCert != "" {
		log.Printf("  TLS:       enabled")
	} else {
		log.Printf("  TLS:       disabled (development mode)")
	}
	log.Printf("  Cloud:     %s", cfg.CloudURL)
	log.Printf("  Store:     %s", *storeURL)
	log.Printf("  Syslog:    %s", *syslogAddr)
	log.Printf("  Data:      %s", *dataDir)
	log.Printf("  Resources: %d in database", db.CountResources())
	log.Println("──────────────────────────────────────────")

	// Create portal
	p := portal.New(cfg, cloudClient, sessClient, relayMgr, dnsResolver, cgnatAlloc, syslogClient, db)

	// Start automatic mTLS certificate renewal loop
	certRenewalStop := make(chan struct{})
	go p.StartCertRenewalLoop(certRenewalStop)

	go func() {
		if err := p.ListenAndServe(); err != nil {
			log.Fatalf("[PORTAL] Server error: %v", err)
		}
	}()

	// Health endpoint on :8080 for Docker healthcheck / monitoring
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "ok",
				"service": "gateway-portal",
			})
		})
		log.Printf("[PORTAL] Health endpoint listening on :8080")
		if err := http.ListenAndServe(":8080", healthMux); err != nil {
			log.Printf("[PORTAL] Health endpoint error: %v", err)
		}
	}()

	syslogClient.Info("portal.start", "Portal data plane started", map[string]string{
		"listen_addr": cfg.ListenAddr,
		"resources":   fmt.Sprintf("%d", db.CountResources()),
	})

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	close(certRenewalStop) // stop renewal loop
	log.Println("[PORTAL] Shutting down...")
	syslogClient.Info("portal.stop", "Portal data plane shutting down", nil)
	syslogClient.Close()
	db.Close()
}
