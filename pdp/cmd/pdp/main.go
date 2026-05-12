package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"pdp/config"
	"pdp/models"
	"pdp/pa"
	"pdp/pa/transport"
	"pdp/pki"
	"pdp/store"
)

func main() {
	configPath := flag.String("config", "", "Path to config.json")
	genConfig := flag.Bool("gen-config", false, "Generate default config.json and exit")
	createAdmin := flag.String("create-admin", "", "Create admin user (format: username:password:email)")
	devMode := flag.Bool("dev", false, "Development mode: self-signed TLS, no Vault PKI required")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("=== ZTNA PDP Service (PA + PE + Auth Broker) ===")

	var cfg *config.Config
	if *genConfig {
		cfg = config.DefaultConfig()
		outPath := "pdp-config.json"
		if *configPath != "" {
			outPath = *configPath
		}
		if err := cfg.SaveToFile(outPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
		fmt.Printf("Default config written to %s\n", outPath)
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

	// Validate JWT secret
	if cfg.JWTSecret == "" || cfg.JWTSecret == "CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32" {
		log.Fatal("[SECURITY] jwt_secret is not configured. Generate one with: openssl rand -hex 32")
	}
	if len(cfg.JWTSecret) < 32 {
		log.Fatal("[SECURITY] jwt_secret is too short (minimum 32 characters)")
	}

	// Ensure data directory
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("Failed to create data dir %s: %v", cfg.DataDir, err)
	}

	// ── TLS setup ──
	if *devMode {
		log.Println("[DEV] === Development mode enabled ===")
		log.Println("[DEV] Self-signed TLS certificates (no Vault PKI)")
		certPath, keyPath, caPath := setupDevTLS(cfg)
		cfg.TLSCert = certPath
		cfg.TLSKey = keyPath
		cfg.MTLSCA = caPath
		// Dev mode: no Vault PKI — enrollment/gateway signing are disabled
		cfg.PKIURL = ""
		cfg.PKIToken = ""
	} else {
		if strings.TrimSpace(cfg.PDPFQDN) == "" {
			log.Fatal("[SECURITY] pdp_fqdn is required (e.g. pdp.ztna.local)")
		}
		if strings.TrimSpace(cfg.PKIURL) == "" {
			log.Fatal("[SECURITY] pki_url is required")
		}
		if strings.TrimSpace(cfg.PKIToken) == "" {
			log.Fatal("[SECURITY] pki_token is required")
		}
		certPath, keyPath, caPath := setupVaultTLS(cfg)
		cfg.TLSCert = certPath
		cfg.TLSKey = keyPath
		cfg.MTLSCA = caPath
	}

	// ── Init store ──
	dataStore := store.New(cfg.DataDir)
	if err := dataStore.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	stopChan := make(chan struct{})
	dataStore.StartAutoSave(1*time.Minute, stopChan)
	log.Println("[STORE] SQLite database ready")

	// ── Init PA ──
	policyAdmin := pa.NewPolicyAdministrator(cfg, dataStore)
	policyAdmin.Auth.OIDC.RegisterNativeConnectAppClient()
	policyAdmin.Auth.OIDC.RegisterNativeAgentClient()

	// ── Test user ──
	ensureTestUser(policyAdmin)

	if *createAdmin != "" {
		createAdminUser(policyAdmin, *createAdmin)
	}

	policyAdmin.Sessions.StartCleanupLoop(5*time.Minute, stopChan)

	// ── Start server ──
	server, err := transport.NewServer(policyAdmin, cfg.ListenAddr, cfg.MTLSCA)
	if err != nil {
		log.Fatalf("Failed to initialize API server: %v", err)
	}

	go func() {
		if err := server.StartTLS(cfg.TLSCert, cfg.TLSKey); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	printStatus(cfg, dataStore)

	log.Println("=== ZTNA PDP running. Press Ctrl+C to stop. ===")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\n=== Shutting down... ===")
	close(stopChan)
	log.Println("=== Shutdown complete ===")
}

// ──────────────────────────────────────────────────────────────────────
// Dev Mode — generate self-signed TLS cert
// ──────────────────────────────────────────────────────────────────────

func setupDevTLS(cfg *config.Config) (certPath, keyPath, caPath string) {
	certPath = cfg.DataDir + "/pdp.crt"
	keyPath = cfg.DataDir + "/pdp.key"
	caPath = cfg.DataDir + "/ca-cert.pem"

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			log.Printf("[DEV] Reusing existing TLS certs")
			if _, err := os.Stat(caPath); os.IsNotExist(err) {
				caData, _ := os.ReadFile(certPath)
				os.WriteFile(caPath, caData, 0o644)
			}
			return
		}
	}

	log.Println("[DEV] Generating self-signed TLS certificate...")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"ZTNA Dev"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "pdp.ztna.local", "pdp.lab.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	keyBytes, _ := x509.MarshalECPrivateKey(key)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	os.WriteFile(keyPath, keyPEM, 0o600)
	os.WriteFile(certPath, certPEM, 0o644)
	os.WriteFile(caPath, certPEM, 0o644)
	log.Printf("[DEV] Self-signed TLS cert ready: %s", certPath)
	return
}

// ──────────────────────────────────────────────────────────────────────
// Production — Vault PKI TLS setup
// ──────────────────────────────────────────────────────────────────────

func setupVaultTLS(cfg *config.Config) (certPath, keyPath, caPath string) {
	certPath = cfg.DataDir + "/pdp.crt"
	keyPath = cfg.DataDir + "/pdp.key"
	caPath = cfg.DataDir + "/ca-cert.pem"
	encryptedKeyPath := cfg.DataDir + "/pdp_key.enc"

	vaultCfg := pki.VaultConfig{
		URL:        cfg.PKIURL,
		Token:      cfg.PKIToken,
		PKIPath:    cfg.PKIPath,
		CAFile:     cfg.PKICAFile,
		ServerName: cfg.PKIServerName,
		Timeout:    cfg.PKITimeout,
	}

	ctx := context.Background()
	privKey, keyPEM, err := pki.RestoreOrCreateKey(ctx, vaultCfg, keyPath, encryptedKeyPath)
	if err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Key error: %v", err)
	}

	enrollResult, err := pki.SelfEnroll(ctx, vaultCfg, cfg.PDPFQDN, cfg.PKIRolePDP, privKey)
	if err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Self-enrollment failed: %v", err)
	}

	if err := pki.SaveEnrolledCert(enrollResult, certPath, keyPath, cfg.DataDir); err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Save error: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Write error: %v", err)
	}

	renewCtx, _ := context.WithCancel(context.Background())
	go pki.SelfEnrollLoop(renewCtx, vaultCfg, cfg.PDPFQDN, cfg.PKIRolePDP, certPath, keyPath, cfg.DataDir, 24*time.Hour)
	return
}

// ── Helpers ──

func ensureTestUser(policyAdmin *pa.PolicyAdministrator) {
	users := policyAdmin.Store.ListUsers()
	for _, u := range users {
		if u.Username == "admin" {
			return
		}
	}
	user, err := policyAdmin.Auth.Users.Register(models.RegisterRequest{
		Username: "admin", Password: "admin", Email: "admin@ztna.local",
	})
	if err != nil {
		log.Printf("[INIT] Failed to create test user: %v", err)
		return
	}
	policyAdmin.Auth.Users.SetUserRole(user.ID, "admin")
	log.Printf("[INIT] Test user: admin / admin (role=admin)")
}

func createAdminUser(policyAdmin *pa.PolicyAdministrator, spec string) {
	parts := splitN(spec, ":", 3)
	if len(parts) < 3 {
		log.Fatalf("--create-admin format: username:password:email")
	}
	user, err := policyAdmin.Auth.Users.Register(models.RegisterRequest{
		Username: parts[0], Password: parts[1], Email: parts[2],
	})
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	policyAdmin.Auth.Users.SetUserRole(user.ID, "admin")
}

func splitN(s, sep string, n int) []string {
	result := make([]string, 0, n)
	for i := 0; i < n-1; i++ {
		idx := strings.Index(s, sep)
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
	log.Println("──────────────────────────────────────────")
	log.Printf("  Listen: %s", cfg.ListenAddr)
	log.Printf("  Data:   %s", cfg.DataDir)
	log.Printf("  Users:  %d", len(s.ListUsers()))
	log.Printf("  Rules:  %d", len(s.ListPolicyRules()))
	log.Println("──────────────────────────────────────────")
	log.Println("  Dashboard: https://localhost:8443/dashboard/")
	log.Println("  Admin:     admin / admin")
	log.Println("──────────────────────────────────────────")
}
