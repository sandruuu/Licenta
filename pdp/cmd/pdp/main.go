package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"pdp/config"
	"pdp/models"
	"pdp/pa"
	"pdp/pa/transport"
	"pdp/pki"
	"pdp/store"
)

type pdpIdentityState struct {
	active atomic.Pointer[tls.Certificate]
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("=== TrustCloud Service (PA + PE) ===")

	cfg := loadConfig("config.json")
	ensureDataDir(cfg)

	shutdownCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	pdpIdentity := initializePDPIdentity(shutdownCtx, cfg)

	stopChan := make(chan struct{})
	dataStore := initializeStore(cfg, stopChan)
	policyAdmin := initializePolicyAdministrator(cfg, dataStore, stopChan)
	startPolicyAdministratorTransport(cfg, policyAdmin, pdpIdentity)

	waitForShutdown(shutdownCtx, stopChan)
}

func loadConfig(path string) *config.Config {
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", path, err)
	}
	log.Printf("Config loaded from %s", path)
	return cfg
}

func ensureDataDir(cfg *config.Config) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("Failed to create data dir %s: %v", cfg.DataDir, err)
	}
}

func initializePDPIdentity(ctx context.Context, cfg *config.Config) *pdpIdentityState {
	state := &pdpIdentityState{}
	vaultCfg := pki.VaultConfig{
		URL:            cfg.PKIURL,
		Token:          cfg.PKIToken,
		PKIPath:        cfg.PKIPath,
		TransitKeyName: cfg.PKITransitKey,
		CAFile:         cfg.PKICAFile,
		ServerName:     cfg.PKIServerName,
		Timeout:        cfg.PKITimeout,
	}

	privKey, err := pki.RestoreOrCreateKey(ctx, vaultCfg, cfg.PDPKeyEncryptedPath)
	if err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Key error: %v", err)
	}

	enrollResult, err := pki.SelfEnroll(ctx, vaultCfg, cfg.PDPFQDN, cfg.PKIRolePDP, privKey)
	if err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Self-enrollment failed: %v", err)
	}

	if err := pki.SaveEnrolledCert(enrollResult, cfg.TLSCert, cfg.MTLSCA, cfg.DataDir); err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Save error: %v", err)
	}

	state.storeCertificate(enrollResult.Certificate)
	go pki.SelfEnrollLoop(ctx, vaultCfg, cfg.PDPFQDN, cfg.PKIRolePDP, privKey, cfg.TLSCert, cfg.MTLSCA, cfg.DataDir, cfg.Runtime.CertificateRenewBefore, cfg.Runtime.PKIRenewCheckInterval, state.storeCertificate)
	return state
}

func initializeStore(cfg *config.Config, stopChan <-chan struct{}) *store.Store {
	dataStore := store.NewWithDatabasePath(cfg.DataDir, cfg.DatabasePath)
	if err := dataStore.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	dataStore.StartAutoSave(cfg.Runtime.StoreAutoSaveInterval, stopChan)
	log.Println("[STORE] SQLite database ready")
	return dataStore
}

func initializePolicyAdministrator(cfg *config.Config, dataStore *store.Store, stopChan <-chan struct{}) *pa.PolicyAdministrator {
	// The PDP embeds PA and PE in one process. PA owns orchestration and
	// forwards normalized access context to the internal Policy Engine.
	policyAdmin := pa.NewPolicyAdministrator(cfg, dataStore)

	ensureBootstrapAdmin(policyAdmin, cfg.BootstrapAdmin)
	policyAdmin.Sessions.StartCleanupLoop(cfg.Runtime.SessionCleanupInterval, stopChan)
	policyAdmin.Enrollment.StartCleanupLoop(cfg.Runtime.EnrollmentCleanupInterval, stopChan)
	return policyAdmin
}

func startPolicyAdministratorTransport(cfg *config.Config, policyAdmin *pa.PolicyAdministrator, identity *pdpIdentityState) {
	// PA exposes the PDP control-plane surface over HTTPS/gRPC. PE stays
	// internal and is reached only through PolicyAdministrator methods.
	server, err := transport.NewServer(policyAdmin, cfg.ListenAddr, cfg.MTLSCA)
	if err != nil {
		log.Fatalf("Failed to initialize PA transport server: %v", err)
	}

	go func() {
		if err := server.StartTLS(identity.getCertificate); err != nil {
			log.Fatalf("PA transport server error: %v", err)
		}
	}()
}

func (s *pdpIdentityState) storeCertificate(cert *tls.Certificate) {
	if cert != nil {
		s.active.Store(cert)
	}
}

func (s *pdpIdentityState) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := s.active.Load()
	if cert == nil {
		return nil, fmt.Errorf("PDP TLS certificate is not initialized")
	}
	return cert, nil
}

func waitForShutdown(ctx context.Context, stopChan chan struct{}) {
	log.Println("=== TrustCloud running. Press Ctrl+C to stop. ===")
	<-ctx.Done()

	log.Println("\n=== Shutting down... ===")
	close(stopChan)
	log.Println("=== Shutdown complete ===")
}

func ensureBootstrapAdmin(policyAdmin *pa.PolicyAdministrator, admin config.BootstrapAdminConfig) {
	if !admin.Enabled {
		return
	}
	if admin.Password == "" || admin.Password == "admin" {
		log.Printf("[INIT] Refusing insecure bootstrap admin password; use self-registration or configure a strong bootstrap secret")
		return
	}
	users := policyAdmin.Store.ListUsers()
	for _, u := range users {
		if u.Username == admin.Username {
			return
		}
	}
	user, err := policyAdmin.Auth.Users.Register(models.RegisterRequest{
		Username: admin.Username,
		Password: admin.Password,
		Email:    admin.Email,
	})
	if err != nil {
		log.Printf("[INIT] Failed to create bootstrap admin: %v", err)
		return
	}
	role := admin.Role
	if role == "" || role == "admin" {
		role = "platform_admin"
	}
	policyAdmin.Auth.Users.SetUserRole(user.ID, role)
	log.Printf("[INIT] Bootstrap admin ensured: %s (role=%s)", admin.Username, role)
}
