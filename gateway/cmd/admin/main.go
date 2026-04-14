// Secure Alert Gateway — Admin Management Plane microservice.
// Provides HTTP APIs + web UI on :8444 for resource management, enrollment,
// TLS certificate upload, session oversight, and health monitoring.
// Admin account can be auto-created from environment variables when explicitly enabled.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	gwadmin "gateway/admin"
	"gateway/internal/config"
	"gateway/sessionstore"
	"gateway/store"
	"gateway/syslog"
)

func main() {
	configPath := flag.String("config", "gateway-config.json", "Path to gateway config file")
	addr := flag.String("addr", ":8444", "Listen address for admin management API")
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
		log.Printf("[ADMIN] Config not found, using defaults: %v", err)
		cfg = config.DefaultConfig()
	}

	// Validate secrets — reject placeholder/insecure values
	if warnings := cfg.ValidateSecrets(); len(warnings) > 0 {
		for _, w := range warnings {
			log.Printf("[ADMIN] ⚠ SECURITY WARNING: %s", w)
		}
		if !cfg.DevMode {
			log.Fatalf("[ADMIN] Refusing to start with insecure secrets. Fix the warnings above or set dev_mode=true for development.")
		}
		log.Printf("[ADMIN] Continuing in dev_mode despite security warnings.")
	}

	// Initialize SQLite store
	db := store.New(*dataDir)
	if err := db.InitDB(); err != nil {
		log.Fatalf("[ADMIN] Failed to initialize database: %v", err)
	}

	// Migrate resources from JSON config (one-time)
	if len(cfg.Resources) > 0 {
		if n, err := db.MigrateResourcesFromConfig(cfg.Resources); err != nil {
			log.Printf("[ADMIN] Resource migration error: %v", err)
		} else if n > 0 {
			log.Printf("[ADMIN] Migrated %d resources from config to SQLite", n)
		}
	}

	// Initialize clients
	var storeTLS *tls.Config
	if *storeTLSCA != "" {
		pem, err := os.ReadFile(*storeTLSCA)
		if err != nil {
			log.Fatalf("[ADMIN] Failed to read store TLS CA: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		storeTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	}
	var syslogTLS *tls.Config
	if *syslogTLSCA != "" {
		pem, err := os.ReadFile(*syslogTLSCA)
		if err != nil {
			log.Fatalf("[ADMIN] Failed to read syslog TLS CA: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		syslogTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	}
	sessClient := sessionstore.NewClient(*storeURL, storeTLS)
	syslogClient := syslog.NewClient(*syslogAddr, "admin", syslogTLS, *syslogToken)

	// Read optional admin auto-setup settings from environment.
	autoSetup := false
	if v := os.Getenv("ADMIN_AUTO_SETUP"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			log.Printf("[ADMIN] Invalid ADMIN_AUTO_SETUP value %q, defaulting to setup wizard", v)
		} else {
			autoSetup = parsed
		}
	}
	adminEmail := os.Getenv("ADMIN_EMAIL")
	adminPassword := os.Getenv("ADMIN_PASSWORD")

	log.Println("──────────────────────────────────────────")
	log.Printf("  Service:   Secure Alert Gateway — Admin")
	log.Printf("  Listen:    %s", *addr)
	log.Printf("  Config:    %s", *configPath)
	log.Printf("  Store:     %s", *storeURL)
	log.Printf("  Syslog:    %s", *syslogAddr)
	log.Printf("  Data:      %s", *dataDir)
	log.Printf("  Cloud:     %s", cfg.CloudURL)
	log.Printf("  Resources: %d in database", db.CountResources())
	if autoSetup && adminEmail != "" {
		log.Printf("  Admin:     auto-setup from env")
	} else if !autoSetup && (adminEmail != "" || adminPassword != "") {
		log.Printf("  Admin:     env credentials present but ignored (ADMIN_AUTO_SETUP=false)")
	}
	log.Println("──────────────────────────────────────────")

	// Create and start admin server
	adminServer := gwadmin.New(cfg, *configPath, sessClient, syslogClient, db)

	// Auto-create the admin account only when explicitly enabled.
	if autoSetup {
		if adminEmail == "" || adminPassword == "" {
			log.Printf("[ADMIN] ADMIN_AUTO_SETUP is enabled but ADMIN_EMAIL / ADMIN_PASSWORD are missing; falling back to setup wizard")
		} else {
			adminServer.AutoSetup(adminEmail, adminPassword)
		}
	}

	// Setup wizard status + token generation
	if cfg.IsSetupComplete() {
		log.Printf("[ADMIN] Setup complete (admin: %s)", cfg.Setup.AdminEmail)
	} else {
		// Generate a setup token if one doesn't exist yet
		if cfg.Setup == nil || cfg.Setup.SetupToken == "" {
			token := cfg.GenerateSetupToken()
			cfg.SaveToFile(*configPath)
			log.Println("[ADMIN] ┌─────────────────────────────────────────────────────────┐")
			log.Println("[ADMIN] │  FIRST-BOOT SETUP REQUIRED                              │")
			log.Println("[ADMIN] │                                                         │")
			log.Printf("[ADMIN] │  Setup Token: %s                  │", token)
			log.Println("[ADMIN] │                                                         │")
			log.Println("[ADMIN] │  Open the admin UI and enter this token to begin setup.  │")
			log.Println("[ADMIN] └─────────────────────────────────────────────────────────┘")
		} else {
			log.Println("[ADMIN] ┌─────────────────────────────────────────────────────────┐")
			log.Println("[ADMIN] │  SETUP NOT COMPLETE                                     │")
			log.Println("[ADMIN] │                                                         │")
			log.Printf("[ADMIN] │  Setup Token: %s                  │", cfg.Setup.SetupToken)
			log.Println("[ADMIN] │                                                         │")
			log.Println("[ADMIN] │  Open the admin UI and enter this token to begin setup.  │")
			log.Println("[ADMIN] └─────────────────────────────────────────────────────────┘")
		}
	}

	go func() {
		if err := adminServer.ListenAndServe(*addr); err != nil {
			log.Fatalf("[ADMIN] Server error: %v", err)
		}
	}()

	// Background log cleanup to prevent unbounded disk growth
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if n := db.CleanOldLogs(10000); n > 0 {
				log.Printf("[ADMIN] Cleaned %d old log entries (keeping 10000)", n)
			}
		}
	}()

	syslogClient.Info("admin.start", "Secure Alert Gateway admin started", nil)

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[ADMIN] Shutting down...")
	syslogClient.Info("admin.stop", "Secure Alert Gateway admin shutting down", nil)
	syslogClient.Close()
	db.Close()
}
