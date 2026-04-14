package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"cloud/admin"
	"cloud/api"
	"cloud/certs"
	"cloud/config"
	"cloud/idp"
	"cloud/models"
	"cloud/store"
)

func main() {
	// CLI flags
	configPath := flag.String("config", "", "Path to config.json")
	genConfig := flag.Bool("gen-config", false, "Generate default config.json and exit")
	genCerts := flag.String("gen-certs", "", "Generate all component TLS certificates signed by internal CA into the given directory (e.g. --gen-certs=../certs)")
	createAdmin := flag.String("create-admin", "", "Create admin user (format: username:password:email)")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("=== ZTNA Cloud Service (PA + PE + IdP) ===")

	// Load or generate config
	var cfg *config.Config
	if *genConfig {
		cfg = config.DefaultConfig()
		outPath := "cloud-config.json"
		if *configPath != "" {
			outPath = *configPath
		}
		if err := cfg.SaveToFile(outPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
		fmt.Printf("Default config written to %s\n", outPath)
		os.Exit(0)
	}

	// ──────────────────────────────
	// Generate component certificates
	// ──────────────────────────────
	if *genCerts != "" {
		generateComponentCerts(*genCerts)
		os.Exit(0)
	}

	if *configPath != "" {
		var err error
		cfg, err = config.LoadFromFile(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		log.Printf("Config loaded from %s", *configPath)
	} else {
		cfg = config.DefaultConfig()
		log.Println("Using default config (use --config to specify a file)")
	}

	// ──────────────────────────────
	// Validate required secrets
	// ──────────────────────────────
	if cfg.JWTSecret == "" || cfg.JWTSecret == "CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32" {
		log.Fatal("[SECURITY] jwt_secret is not configured. Generate one with: openssl rand -hex 32")
	}
	if len(cfg.JWTSecret) < 32 {
		log.Fatal("[SECURITY] jwt_secret is too short (minimum 32 characters)")
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		log.Fatal("[SECURITY] tls_cert and tls_key are required because gateway-to-cloud communication is strictly mTLS")
	}
	if cfg.MTLSCA == "" {
		log.Fatal("[SECURITY] mtls_ca is required because gateway-to-cloud communication is strictly mTLS")
	}

	// ──────────────────────────────
	// 1. Initialize data store (SQLite)
	// ──────────────────────────────
	dataStore := store.New(cfg.DataDir)
	if err := dataStore.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Import legacy store.json if database is empty
	if err := dataStore.LoadFromDisk(); err != nil {
		log.Printf("[WARN] Failed to load legacy data: %v", err)
	}

	// Start periodic cleanup of pending auth sessions
	stopChan := make(chan struct{})
	dataStore.StartAutoSave(1*time.Minute, stopChan)

	// ──────────────────────────────
	// 1b. Initialize internal CA
	// ──────────────────────────────
	caCertPath := filepath.Join(cfg.DataDir, "ca-cert.pem")
	caKeyPath := filepath.Join(cfg.DataDir, "ca-key.pem")
	caBundle, err := certs.LoadOrInitCA(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}
	log.Printf("[CA] Internal CA ready (cert: %s)", caCertPath)

	// ──────────────────────────────
	// 2. Initialize Policy Administrator (PA)
	//    This also initializes IdP and PE
	// ──────────────────────────────
	pa := admin.NewPolicyAdministrator(cfg, dataStore)
	pa.CA = caBundle

	// ──────────────────────────────
	// 2b. Register OIDC clients (gateways)
	// ──────────────────────────────
	registerOIDCClients(pa, cfg)

	// ──────────────────────────────
	// 2c. Ensure default test user for development
	// ──────────────────────────────
	ensureTestUser(pa)

	// ──────────────────────────────
	// 3. Create admin user if requested
	// ──────────────────────────────
	if *createAdmin != "" {
		createAdminUser(pa, *createAdmin)
	}

	// ──────────────────────────────
	// 4. Start session cleanup loop
	// ──────────────────────────────
	pa.Sessions.StartCleanupLoop(5*time.Minute, stopChan)

	// ──────────────────────────────
	// 5. Start API server
	// ──────────────────────────────
	server, err := api.NewServer(pa, cfg.ListenAddr, cfg.MTLSCA)
	if err != nil {
		log.Fatalf("Failed to initialize API server: %v", err)
	}

	go func() {
		if err := server.StartTLS(cfg.TLSCert, cfg.TLSKey); err != nil {
			log.Println("[WARN] Running without TLS — use tls_cert/tls_key in config for production")
			log.Fatalf("Server error: %v", err)
		}
	}()

	// ──────────────────────────────
	// Print status
	// ──────────────────────────────
	printStatus(cfg, dataStore)

	// ──────────────────────────────
	// Wait for shutdown signal
	// ──────────────────────────────
	log.Println("=== ZTNA Cloud running. Press Ctrl+C to stop. ===")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\n=== Shutting down... ===")
	close(stopChan)

	// Final save
	if err := dataStore.SaveToDisk(); err != nil {
		log.Printf("[WARN] Failed to save data on shutdown: %v", err)
	}

	log.Println("=== Shutdown complete ===")
}

// registerOIDCClients re-registers OIDC clients for all enrolled gateways.
// On startup, the cloud reads gateway records from the database and registers
// their OIDC clients so token exchange works immediately after restart.
func registerOIDCClients(pa *admin.PolicyAdministrator, cfg *config.Config) {
	count := 0

	// Register OIDC clients for all enrolled gateways
	gateways := pa.Store.ListGateways()
	for _, gw := range gateways {
		if gw.Status != "enrolled" || gw.OIDCClientID == "" {
			continue
		}
		redirectURIs := []string{
			"https://localhost:9443/auth/callback",
			"https://127.0.0.1:9443/auth/callback",
		}
		if gw.FQDN != "" {
			redirectURIs = append([]string{
				fmt.Sprintf("https://%s/auth/callback", gw.FQDN),
			}, redirectURIs...)
		}
		pa.IdP.OIDC.RegisterClient(&idp.OIDCClient{
			ClientID:     gw.OIDCClientID,
			ClientSecret: gw.OIDCClientSecret,
			RedirectURIs: redirectURIs,
			Name:         "Gateway: " + gw.Name,
		})
		count++
	}

	log.Printf("[OIDC] Registered %d OIDC client(s) from enrolled gateways", count)
}

// ensureTestUser creates a default admin user if the "admin" user doesn't exist.
// This enables immediate testing of the OIDC flow without manual setup.
// Credentials: admin / admin
func ensureTestUser(pa *admin.PolicyAdministrator) {
	// Check if "admin" user already exists
	users := pa.Store.ListUsers()
	for _, u := range users {
		if u.Username == "admin" {
			log.Printf("[INIT] Test user 'admin' already exists (id=%s), skipping creation", u.ID)
			return
		}
	}

	user, err := pa.IdP.Users.Register(models.RegisterRequest{
		Username: "admin",
		Password: "admin",
		Email:    "admin@ztna.local",
	})
	if err != nil {
		log.Printf("[INIT] Failed to create test user: %v", err)
		return
	}

	if err := pa.IdP.Users.SetUserRole(user.ID, "admin"); err != nil {
		log.Printf("[INIT] Failed to set admin role: %v", err)
		return
	}

	log.Printf("[INIT] Test user created: admin / admin (role=admin, id=%s)", user.ID)
}

func createAdminUser(pa *admin.PolicyAdministrator, spec string) {
	// Parse "username:password:email"
	parts := splitN(spec, ":", 3)
	if len(parts) < 3 {
		log.Fatalf("--create-admin format: username:password:email")
	}

	user, err := pa.IdP.Users.Register(models.RegisterRequest{
		Username: parts[0],
		Password: parts[1],
		Email:    parts[2],
	})
	if err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}

	if err := pa.IdP.Users.SetUserRole(user.ID, "admin"); err != nil {
		log.Fatalf("Failed to set admin role: %v", err)
	}

	log.Printf("Admin user created: %s (%s)", user.Username, user.ID)
}

func splitN(s, sep string, n int) []string {
	result := make([]string, 0, n)
	for i := 0; i < n-1; i++ {
		idx := -1
		for j := 0; j < len(s); j++ {
			if j+len(sep) <= len(s) && s[j:j+len(sep)] == sep {
				idx = j
				break
			}
		}
		if idx < 0 {
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	result = append(result, s)
	return result
}

func printStatus(cfg *config.Config, s *store.Store) {
	users := s.ListUsers()
	rules := s.ListPolicyRules()
	sessions := s.ListSessions()
	resources := s.ListResources()

	log.Println("──────────────────────────────────────────")
	log.Printf("  Service:  ZTNA Cloud (PDP + IdP)")
	log.Printf("  Listen:   %s", cfg.ListenAddr)
	if cfg.TLSCert != "" {
		log.Printf("  TLS:      enabled")
	} else {
		log.Printf("  TLS:      disabled (development mode)")
	}
	log.Printf("  Data dir: %s", cfg.DataDir)
	log.Printf("  Users:    %d registered", len(users))
	log.Printf("  Rules:    %d policy rules", len(rules))
	log.Printf("  Resources:%d configured", len(resources))
	log.Printf("  Sessions: %d active", len(sessions))
	log.Printf("  JWT exp:  %s", cfg.JWTExpiry)
	log.Printf("  Sess exp: %s", cfg.SessionExpiry)
	log.Println("──────────────────────────────────────────")
	log.Println("  IdP Endpoints:")
	log.Println("    POST /api/auth/register       - Register user")
	log.Println("    POST /api/auth/login           - Login (primary auth)")
	log.Println("    POST /api/auth/verify-mfa      - Complete MFA")
	log.Println("    POST /api/auth/enroll-mfa      - Enroll in MFA")
	log.Println("    POST /api/auth/activate-mfa    - Activate MFA")
	log.Println("  Browser Auth:")
	log.Println("    POST /api/auth/start-session   - Start browser auth session")
	log.Println("    GET  /api/auth/session-status   - Poll auth session status")
	log.Println("    GET  /auth/login               - Browser login page")
	log.Println("  OIDC (IdP):")
	log.Println("    GET  /auth/authorize            - OIDC Authorization endpoint")
	log.Println("    POST /auth/token                - OIDC Token exchange")
	log.Println("    POST /api/auth/oidc-complete     - Complete OIDC auth session")
	log.Println("  Gateway (PEP):")
	log.Println("    POST /api/gateway/authorize     - Gateway auth request")
	log.Println("    POST /api/gateway/device-report - Device health report")
	log.Println("    POST /api/gateway/validate-token- Validate JWT")
	log.Println("  PDP Admin:")
	log.Println("    GET  /api/admin/dashboard       - Dashboard stats")
	log.Println("    CRUD /api/admin/resources       - Manage resources")
	log.Println("    CRUD /api/admin/rules           - Manage policies")
	log.Println("    GET  /api/admin/users           - List users")
	log.Println("    GET  /api/admin/sessions        - List sessions")
	log.Println("    GET  /api/admin/audit           - Audit log")
	log.Println("  Dashboard:")
	log.Println("    GET  /dashboard/                - React admin console")
	log.Println("──────────────────────────────────────────")
}

// generateComponentCerts creates the internal CA (if missing) and generates
// the Cloud server TLS certificate. The Gateway manages its own TLS certificate
// (self-signed at first boot, admin upload, or Let's Encrypt).
// Agent certificates (connect-app, device-health-app) are NOT generated here —
// they use TPM-bound keys and obtain certificates through the enrollment API.
func generateComponentCerts(outDir string) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory %s: %v", outDir, err)
	}

	// Load or create the internal CA (stored alongside certs)
	caCertPath := filepath.Join(outDir, "ca.crt")
	caKeyPath := filepath.Join(outDir, "ca.key")
	ca, err := certs.LoadOrInitCA(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}
	fmt.Printf("  CA certificate: %s\n", caCertPath)

	// Also copy CA cert into data dir so Cloud can use it at runtime
	dataDir := "./data"
	if err := os.MkdirAll(dataDir, 0755); err == nil {
		os.WriteFile(filepath.Join(dataDir, "ca-cert.pem"), ca.CertPEM, 0644)
		os.WriteFile(filepath.Join(dataDir, "ca-key.pem"), ca.KeyPEM, 0600)
	}

	localhost := net.ParseIP("127.0.0.1")

	// Only the Cloud server certificate is generated here.
	// Gateway generates its own TLS cert (self-signed, upload, or Let's Encrypt).
	// Agent certs (connect-app, health-app) are obtained via TPM enrollment.
	fmt.Println("\n=== Generating ZTNA Cloud Certificate ===")

	certPEM, keyPEM, err := certs.GenerateComponentCert(
		ca, "ZTNA Cloud",
		[]string{"localhost", "cloud", "cloud.lab.local"},
		[]net.IP{localhost},
		365, true, false,
	)
	if err != nil {
		log.Fatalf("Failed to generate cloud cert: %v", err)
	}

	certPath := filepath.Join(outDir, "cloud.crt")
	keyPath := filepath.Join(outDir, "cloud.key")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		log.Fatalf("Failed to write %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		log.Fatalf("Failed to write %s: %v", keyPath, err)
	}
	fmt.Printf("  cloud        %s / %s  (server)\n", certPath, keyPath)

	// Distribute ca.crt to sibling component directories so they can validate
	// the Cloud's TLS certificate. Each component keeps its own certs/ folder.
	siblingDirs := []string{
		filepath.Join(outDir, "..", "..", "gateway", "certs"),
		filepath.Join(outDir, "..", "..", "connect-app", "certs"),
		filepath.Join(outDir, "..", "..", "device-health-app", "certs"),
	}
	// If outDir is cloud/certs, siblings are at ../gateway/certs etc.
	// Detect layout: if outDir ends with cloud/certs, use relative sibling paths
	absOut, _ := filepath.Abs(outDir)
	if filepath.Base(filepath.Dir(absOut)) == "cloud" {
		siblingDirs = []string{
			filepath.Join(filepath.Dir(filepath.Dir(absOut)), "gateway", "certs"),
			filepath.Join(filepath.Dir(filepath.Dir(absOut)), "connect-app", "certs"),
			filepath.Join(filepath.Dir(filepath.Dir(absOut)), "device-health-app", "certs"),
		}
	}

	fmt.Println("\n  Distributing ca.crt to component directories:")
	for _, dir := range siblingDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("    SKIP %s: %v\n", dir, err)
			continue
		}
		dst := filepath.Join(dir, "ca.crt")
		if err := os.WriteFile(dst, ca.CertPEM, 0644); err != nil {
			fmt.Printf("    FAIL %s: %v\n", dst, err)
		} else {
			fmt.Printf("    OK   %s\n", dst)
		}
	}

	fmt.Println("\nCloud certificate generated and signed by internal CA.")
	fmt.Println("Gateway TLS cert: generated at first boot (self-signed) or uploaded via admin UI.")
	fmt.Println("Agent certificates (connect-app, health-app) are obtained via TPM enrollment.")
	fmt.Println("  POST /api/enroll — submit CSR generated with TPM-bound key")
}
