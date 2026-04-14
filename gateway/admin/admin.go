// Package admin implements the Secure Alert Gateway management plane.
// It provides HTTP APIs + embedded web UI for:
//   - Admin account creation (from ADMIN_EMAIL / ADMIN_PASSWORD env vars)
//   - mTLS CSR generation & certificate installation
//   - Primary Authentication Source (IdP / OIDC) configuration
//   - CGNAT address pool management
//   - Resource/route definitions with CGNAT tunnel IPs
//   - TLS certificate management (public SSL)
//   - Session oversight via the session store
//   - Enrollment with cloud
package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gateway/internal/config"
	"gateway/internal/dns"
	"math/big"

	"gateway/internal/models"
	"gateway/sessionstore"
	"gateway/store"
	"gateway/syslog"

	"golang.org/x/crypto/bcrypt"
)

// Server is the admin management plane
type Server struct {
	cfg          *config.Config
	configPath   string
	mu           sync.RWMutex
	sessions     *sessionstore.Client
	syslogClient *syslog.Client
	store        *store.Store
	enrolled     bool
	startTime    time.Time
	// Admin console auth tokens (in-memory, survive only until restart)
	adminTokens map[string]time.Time
	// Track last activity per admin token for idle timeout
	tokenActivity map[string]time.Time
	// CSRF tokens: admin token → CSRF token
	csrfTokens map[string]string
	// Login rate limiting — per-IP failed attempt tracking
	loginAttempts   map[string]*loginAttemptInfo
	loginAttemptsMu sync.Mutex
}

// loginAttemptInfo tracks failed login attempts per IP for rate limiting
type loginAttemptInfo struct {
	failures    int
	lastTry     time.Time
	lockedUntil time.Time
}

// addLog persists an entry to the SQLite admin_logs table.
func (s *Server) addLog(entry models.LogEntry) {
	if err := s.store.InsertLog(entry); err != nil {
		log.Printf("[ADMIN] Failed to persist log: %v", err)
	}
}

// logInfo logs to syslog + captures in the local ring buffer.
func (s *Server) logInfo(event, message string, fields map[string]string) {
	s.syslogClient.Info(event, message, fields)
	s.addLog(models.LogEntry{
		Timestamp: time.Now(),
		Service:   "admin",
		Level:     "info",
		Event:     event,
		Message:   message,
		Fields:    fields,
	})
}

// logWarn logs to syslog + captures in the local ring buffer.
func (s *Server) logWarn(event, message string, fields map[string]string) {
	s.syslogClient.Warn(event, message, fields)
	s.addLog(models.LogEntry{
		Timestamp: time.Now(),
		Service:   "admin",
		Level:     "warn",
		Event:     event,
		Message:   message,
		Fields:    fields,
	})
}

// logError logs to syslog + captures in the local ring buffer.
func (s *Server) logError(event, message string, fields map[string]string) {
	s.syslogClient.Error(event, message, fields)
	s.addLog(models.LogEntry{
		Timestamp: time.Now(),
		Service:   "admin",
		Level:     "error",
		Event:     event,
		Message:   message,
		Fields:    fields,
	})
}

// New creates a new admin server
// GenerateSelfSignedCert creates a self-signed ECDSA P-256 TLS certificate
// for the gateway if no TLS cert is configured. Called at startup so the portal
// can serve HTTPS immediately without requiring manual certificate setup.
func GenerateSelfSignedCert(cfg *config.Config, configPath string) error {
	// Skip if TLS cert already configured and exists on disk
	if cfg.TLSCert != "" {
		if _, err := os.Stat(cfg.TLSCert); err == nil {
			// Check expiry — regenerate if expiring within 30 days
			certPEM, err := os.ReadFile(cfg.TLSCert)
			if err == nil {
				block, _ := pem.Decode(certPEM)
				if block != nil {
					cert, err := x509.ParseCertificate(block.Bytes)
					if err == nil && cert.NotAfter.After(time.Now().Add(30*24*time.Hour)) {
						return nil // cert exists and is valid for >30 days
					}
					if err == nil {
						log.Printf("[ADMIN] Self-signed cert expires in %d days, regenerating", int(time.Until(cert.NotAfter).Hours()/24))
					}
				}
			}
			// Fall through to regenerate
		}
	}

	fqdn := cfg.FQDN
	if fqdn == "" {
		fqdn = "localhost"
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fqdn,
			Organization: []string{"ZTNA Gateway"},
		},
		DNSNames:    []string{fqdn, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.MkdirAll("certs", 0755)
	certPath := "certs/gateway-ssl.crt"
	keyPath := "certs/gateway-ssl.key"

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	cfg.TLSCert = certPath
	cfg.TLSKey = keyPath
	if configPath != "" {
		cfg.SaveToFile(configPath)
	}

	log.Printf("[ADMIN] Self-signed TLS certificate generated for %s: %s", fqdn, certPath)
	return nil
}

func New(cfg *config.Config, configPath string, sessClient *sessionstore.Client, syslogClient *syslog.Client, db *store.Store) *Server {
	return &Server{
		cfg:           cfg,
		configPath:    configPath,
		sessions:      sessClient,
		syslogClient:  syslogClient,
		store:         db,
		startTime:     time.Now(),
		adminTokens:   make(map[string]time.Time),
		tokenActivity: make(map[string]time.Time),
		csrfTokens:    make(map[string]string),
		loginAttempts: make(map[string]*loginAttemptInfo),
	}
}

// AutoSetup creates the admin account from environment variables when requested
// This replaces the first-boot setup wizard — the admin is provisioned at startup.
func (s *Server) AutoSetup(email, password string) {
	if email == "" || password == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.IsSetupComplete() {
		log.Printf("[ADMIN] Setup already completed (admin: %s), skipping env-based setup", s.cfg.Setup.AdminEmail)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		log.Printf("[ADMIN] Failed to hash admin password: %v", err)
		return
	}

	s.cfg.Setup = &config.SetupConfig{
		Completed:     true,
		AdminEmail:    email,
		AdminPassHash: string(hash),
		SetupDate:     time.Now().Format(time.RFC3339),
	}
	s.cfg.SaveToFile(s.configPath)

	log.Printf("[ADMIN] Admin account auto-created from environment: %s", email)
	s.logInfo("setup.auto", fmt.Sprintf("Admin account auto-created from env vars: %s", email), nil)
}

// ListenAndServe starts the admin HTTP server
func (s *Server) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	// Start background cleanup for expired admin tokens
	go s.cleanupExpiredTokens()

	log.Printf("[ADMIN] Secure Alert Gateway management plane starting on %s", addr)
	s.logInfo("admin.start", fmt.Sprintf("Secure Alert Gateway management plane starting on %s", addr), nil)

	server := &http.Server{
		Addr:              addr,
		Handler:           s.withLogging(s.withCORS(http.MaxBytesHandler(mux, 1<<20))), // 1 MB body limit
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0, // 0 = no timeout (required for SSE streams)
		IdleTimeout:       120 * time.Second,
	}

	// Use TLS if certs are configured
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return server.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	if !s.cfg.DevMode {
		log.Printf("[ADMIN] WARNING: No TLS certificates configured. Set dev_mode=true to allow HTTP, or configure tls_cert/tls_key.")
	}
	log.Printf("[ADMIN] Starting in plain HTTP (development mode — NOT for production)")
	return server.ListenAndServe()
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// ── First-Boot Setup Wizard (no auth — only works before setup is complete) ──
	mux.HandleFunc("/api/setup/status", s.handleSetupStatus)
	mux.HandleFunc("/api/setup/complete", s.handleSetupComplete)
	mux.HandleFunc("/api/setup/step/token", s.handleSetupStepToken)
	mux.HandleFunc("/api/setup/step/password", s.handleSetupStepPassword)
	mux.HandleFunc("/api/setup/step/network", s.handleSetupStepNetwork)
	mux.HandleFunc("/api/setup/step/certificates", s.handleSetupStepCertificates)
	mux.HandleFunc("/api/setup/step/idp", s.handleSetupStepIdP)
	mux.HandleFunc("/api/setup/step/enroll", s.handleSetupStepEnroll)
	mux.HandleFunc("/api/setup/step/finish", s.handleSetupStepFinish)
	mux.HandleFunc("/api/setup/reset", s.withAuth(s.withCSRF(s.handleSetupReset)))

	// ── Admin Login (local account) ──────────────────────
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)

	// ── Health & status ──────────────────────────────────
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/stats", s.withAuth(s.handleStats))
	mux.HandleFunc("/api/events", s.withAuth(s.handleSSE))

	// ── Enrollment ───────────────────────────────────────
	mux.HandleFunc("/api/enrollment/enroll", s.withAuth(s.withCSRF(s.handleEnroll)))
	mux.HandleFunc("/api/enrollment/status", s.withAuth(s.handleEnrollmentStatus))

	// ── Configuration ────────────────────────────────────
	mux.HandleFunc("/api/config", s.withAuth(s.handleConfig))
	mux.HandleFunc("/api/config/save", s.withAuth(s.withCSRF(s.handleConfigSave)))

	// ── Settings: admin account & gateway identity ──────
	mux.HandleFunc("/api/settings/password", s.withAuth(s.withCSRF(s.handleChangePassword)))
	mux.HandleFunc("/api/settings/admin", s.withAuth(s.handleAdminInfo))

	// ── Resource management ──────────────────────────────
	mux.HandleFunc("/api/resources", s.withAuth(s.handleResources))
	mux.HandleFunc("/api/resources/add", s.withAuth(s.withCSRF(s.handleResourceAdd)))
	mux.HandleFunc("/api/resources/update", s.withAuth(s.withCSRF(s.handleResourceUpdate)))
	mux.HandleFunc("/api/resources/remove", s.withAuth(s.withCSRF(s.handleResourceRemove)))
	mux.HandleFunc("/api/resources/verify-cloud", s.withAuth(s.withCSRF(s.handleVerifyCloud)))
	mux.HandleFunc("/api/resources/toggle", s.withAuth(s.withCSRF(s.handleToggleResource)))

	// ── mTLS Certificate management ─────────────────────
	mux.HandleFunc("/api/certs/status", s.withAuth(s.handleCertStatus))
	mux.HandleFunc("/api/certs/generate-csr", s.withAuth(s.withCSRF(s.handleGenerateCSR)))
	mux.HandleFunc("/api/certs/install-mtls", s.withAuth(s.withCSRF(s.handleInstallMTLS)))
	mux.HandleFunc("/api/certs/upload-ssl", s.withAuth(s.withCSRF(s.handleUploadSSL)))

	// ── Primary Authentication Source (IdP/OIDC) ────────
	mux.HandleFunc("/api/idp", s.withAuth(s.handleIdPStatus))
	mux.HandleFunc("/api/idp/configure", s.withAuth(s.withCSRF(s.handleIdPConfigure)))

	// ── CGNAT Configuration ─────────────────────────────
	mux.HandleFunc("/api/cgnat", s.withAuth(s.handleCGNATStatus))
	mux.HandleFunc("/api/cgnat/configure", s.withAuth(s.withCSRF(s.handleCGNATConfigure)))

	// ── Session management (via session store) ──────────
	mux.HandleFunc("/api/sessions", s.withAuth(s.handleSessions))
	mux.HandleFunc("/api/sessions/revoke", s.withAuth(s.withCSRF(s.handleSessionRevoke)))

	// ── Admin Logs (in-memory ring buffer) ──────────────
	mux.HandleFunc("/api/logs", s.withAuth(s.handleLogs))

	// ── Secrets rotation ────────────────────────────────
	mux.HandleFunc("/api/secrets/rotate", s.withAuth(s.withCSRF(s.handleSecretsRotate)))
	mux.HandleFunc("/api/secrets/status", s.withAuth(s.handleSecretsStatus))

	// ── Access Policies (per-application) ───────────────
	mux.HandleFunc("/api/policies", s.withAuth(s.handlePolicies))
	mux.HandleFunc("/api/policies/save", s.withAuth(s.withCSRF(s.handlePolicySave)))

	// ── Admin UI (SPA) ──────────────────────────────────
	mux.HandleFunc("/", s.handleUI)
}

// ═══════════════════════════════════════════════════════════════
//  FIRST-BOOT SETUP WIZARD
// ═══════════════════════════════════════════════════════════════

// validateSetupToken checks the X-Setup-Token header against the stored setup token.
// Returns true if the token matches. Returns false and writes a 403 response if not.
// Includes rate limiting (max 5 attempts per IP) and token expiration (30 minutes).
func (s *Server) validateSetupToken(w http.ResponseWriter, r *http.Request) bool {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = fwd
	}

	// Rate limit setup token validation attempts
	if s.isLoginRateLimited(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "Too many setup attempts. Please try again later.",
		})
		return false
	}

	token := r.Header.Get("X-Setup-Token")
	if s.cfg.Setup == nil || s.cfg.Setup.SetupToken == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "No setup token configured. Restart the service to generate one.",
		})
		return false
	}

	// Check if the setup token has expired (30 minute validity)
	if s.cfg.IsSetupTokenExpired() {
		// Auto-regenerate an expired token
		newToken := s.cfg.GenerateSetupToken()
		s.cfg.SaveToFile(s.configPath)
		log.Printf("[ADMIN] Setup token expired — regenerated: %s", newToken)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "Setup token expired. A new token has been generated — check the container logs.",
		})
		return false
	}

	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Setup.SetupToken)) != 1 {
		s.recordLoginFailure(ip) // reuse login rate limiter
		s.logWarn("setup.token.invalid", fmt.Sprintf("Invalid setup token attempt from %s", ip), nil)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "Invalid setup token. Check the container logs for the token.",
		})
		return false
	}
	return true
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sd := ""
	hasAdmin := false
	hasFQDN := false
	if s.cfg.Setup != nil {
		sd = s.cfg.Setup.SetupDate
		hasAdmin = s.cfg.Setup.AdminEmail != "" && s.cfg.Setup.AdminPassHash != ""
	}
	hasFQDN = s.cfg.FQDN != ""
	requiresToken := s.cfg.Setup != nil && s.cfg.Setup.SetupToken != ""
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"completed":      s.cfg.IsSetupComplete(),
		"has_admin":      hasAdmin,
		"has_fqdn":       hasFQDN,
		"fqdn":           s.cfg.FQDN,
		"enrolled":       s.enrolled,
		"setup_date":     sd,
		"requires_token": requiresToken,
	})
}

func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.IsSetupComplete() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Setup already completed"})
		return
	}

	if !s.validateSetupToken(w, r) {
		return
	}

	var req models.SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if req.AdminEmail == "" || req.AdminPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Email and password are required"})
		return
	}
	if errMsg := config.ValidatePasswordStrength(req.AdminPassword); errMsg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errMsg})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.AdminPassword), 12)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
		return
	}

	s.cfg.Setup = &config.SetupConfig{
		Completed:     true,
		AdminEmail:    req.AdminEmail,
		AdminPassHash: string(hash),
		SetupDate:     time.Now().Format(time.RFC3339),
	}
	s.cfg.SaveToFile(s.configPath)

	s.logInfo("setup.complete", fmt.Sprintf("Setup completed by %s", req.AdminEmail), nil)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "completed",
		"message": "Secure Alert Gateway admin account created. You can now log in.",
	})
}

// handleSetupStepToken — Wizard Step 1: validate setup token only (no account creation)
func (s *Server) handleSetupStepToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.IsSetupComplete() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Setup already completed"})
		return
	}

	if !s.validateSetupToken(w, r) {
		return
	}

	s.logInfo("setup.step.token", "Setup token validated successfully", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "step": "token"})
}

// handleSetupStepPassword — Wizard Step 1: create admin credentials (does NOT mark completed)
func (s *Server) handleSetupStepPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.IsSetupComplete() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Setup already completed"})
		return
	}

	if !s.validateSetupToken(w, r) {
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Email and password are required"})
		return
	}
	if errMsg := config.ValidatePasswordStrength(req.Password); errMsg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errMsg})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
		return
	}

	if s.cfg.Setup == nil {
		s.cfg.Setup = &config.SetupConfig{}
	}
	s.cfg.Setup.AdminEmail = req.Email
	s.cfg.Setup.AdminPassHash = string(hash)
	s.cfg.SaveToFile(s.configPath)

	s.logInfo("setup.step.password", fmt.Sprintf("Admin credentials saved for %s", req.Email), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "step": "password"})
}

// handleSetupStepNetwork — Wizard Step 2: configure FQDN
func (s *Server) handleSetupStepNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.IsSetupComplete() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Setup already completed"})
		return
	}

	if !s.validateSetupToken(w, r) {
		return
	}

	var req struct {
		FQDN      string `json:"fqdn"`
		HTTPSMode string `json:"https_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if req.FQDN == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "FQDN is required"})
		return
	}

	if !isValidFQDN(req.FQDN) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid FQDN format: must be a valid domain name (e.g. gateway.example.com)"})
		return
	}

	s.cfg.FQDN = req.FQDN

	// Derive redirect_uri and other auth endpoints from the new FQDN + existing CloudURL
	s.cfg.DeriveAuthEndpoints()

	s.cfg.SaveToFile(s.configPath)

	s.logInfo("setup.step.network", fmt.Sprintf("FQDN configured: %s (https: %s)", req.FQDN, req.HTTPSMode), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "step": "network", "fqdn": req.FQDN})
}

// handleSetupStepCertificates — Setup: configure TLS certificate paths
func (s *Server) handleSetupStepCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.IsSetupComplete() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Setup already completed"})
		return
	}

	if !s.validateSetupToken(w, r) {
		return
	}

	var req struct {
		SSLCert     string `json:"ssl_cert"`
		SSLKey      string `json:"ssl_key"`
		CertPEM     string `json:"cert_pem"`
		KeyPEM      string `json:"key_pem"`
		LetsEncrypt bool   `json:"letsencrypt"`
		FQDN        string `json:"fqdn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Option 1: Upload certificate PEM content
	if req.CertPEM != "" && req.KeyPEM != "" {
		tlsCert, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid certificate/key pair: " + err.Error()})
			return
		}

		// Validate certificate expiration
		if len(tlsCert.Certificate) > 0 {
			parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
			if err == nil {
				if parsed.NotAfter.Before(time.Now()) {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Certificate has already expired"})
					return
				}
				if parsed.NotAfter.Before(time.Now().Add(24 * time.Hour)) {
					log.Printf("[ADMIN] WARNING: uploaded certificate expires within 24 hours (NotAfter=%s)", parsed.NotAfter.Format(time.RFC3339))
				}
			}
		}
		os.MkdirAll("certs", 0755)
		certPath := "certs/gateway-ssl.crt"
		keyPath := "certs/gateway-ssl.key"
		os.WriteFile(certPath, []byte(req.CertPEM), 0644)
		os.WriteFile(keyPath, []byte(req.KeyPEM), 0600)
		s.cfg.TLSCert = certPath
		s.cfg.TLSKey = keyPath
		s.cfg.SaveToFile(s.configPath)
		s.logInfo("setup.step.certificates", "SSL certificate uploaded and saved", nil)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "step": "certificates", "method": "upload"})
		return
	}

	// Option 2: Let's Encrypt (store intent — actual ACME happens on restart)
	if req.LetsEncrypt {
		s.cfg.LetsEncrypt = true
		if req.FQDN != "" {
			s.cfg.FQDN = req.FQDN
		}
		s.cfg.SaveToFile(s.configPath)
		s.logInfo("setup.step.certificates", "Let's Encrypt certificate requested", map[string]string{"fqdn": req.FQDN})
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "step": "certificates", "method": "letsencrypt"})
		return
	}

	// Option 3: Legacy path-based configuration
	if req.SSLCert != "" {
		s.cfg.TLSCert = req.SSLCert
	}
	if req.SSLKey != "" {
		s.cfg.TLSKey = req.SSLKey
	}
	s.cfg.SaveToFile(s.configPath)

	s.logInfo("setup.step.certificates", "TLS certificate paths configured", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "step": "certificates"})
}

// handleSetupStepIdP — Setup: configure Identity Provider (OIDC)
func (s *Server) handleSetupStepIdP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.IsSetupComplete() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Setup already completed"})
		return
	}

	if !s.validateSetupToken(w, r) {
		return
	}

	var req models.AuthSourceUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if s.cfg.AuthSource == nil {
		s.cfg.AuthSource = &config.AuthSourceConfig{}
	}
	as := s.cfg.AuthSource
	if req.Mode == "cloud" {
		if s.cfg.CloudURL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cloud_url must be configured before selecting built-in cloud IdP"})
			return
		}
		s.configureBuiltInAuthSourceLocked(s.cfg.CloudURL, as.ClientID, as.ClientSecret)
	} else {
		if req.Hostname != "" {
			as.Hostname = req.Hostname
		}
		if req.AuthURL != "" {
			as.AuthURL = req.AuthURL
		}
		if req.TokenURL != "" {
			as.TokenURL = req.TokenURL
		}
		if req.UserInfoURL != "" {
			as.UserInfoURL = req.UserInfoURL
		}
		if req.ClientID != "" {
			as.ClientID = req.ClientID
		}
		if req.ClientSecret != "" {
			as.ClientSecret = req.ClientSecret
		}
		if req.RedirectURI != "" {
			as.RedirectURI = req.RedirectURI
		}
		if req.Scopes != "" {
			as.Scopes = req.Scopes
		}
		if as.CallbackListenAddr == "" {
			as.CallbackListenAddr = ":443"
		}
	}
	s.cfg.SaveToFile(s.configPath)

	hostname := as.Hostname
	s.logInfo("setup.step.idp", fmt.Sprintf("IdP configured during setup: hostname=%s", hostname), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "step": "idp"})
}

// handleSetupStepEnroll — Wizard Step 3: cloud enrollment with token
func (s *Server) handleSetupStepEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()

	if s.cfg.IsSetupComplete() {
		s.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Setup already completed"})
		return
	}

	if !s.validateSetupToken(w, r) {
		s.mu.Unlock()
		return
	}

	var req struct {
		CloudURL string `json:"cloud_url"`
		Token    string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if req.CloudURL != "" {
		s.cfg.CloudURL = req.CloudURL
	}
	if req.Token != "" {
		s.cfg.EnrollmentToken = req.Token
	}
	s.cfg.SaveToFile(s.configPath)
	cloudURL := s.cfg.CloudURL
	enrollmentToken := s.cfg.EnrollmentToken
	fqdn := s.cfg.FQDN
	gatewayName := s.cfg.FQDN
	if gatewayName == "" {
		gatewayName = "ZTNA Gateway"
	}
	s.mu.Unlock()

	csrPEM, err := s.ensureGatewayCSR(fqdn)
	if err != nil {
		s.logError("setup.step.enroll", fmt.Sprintf("Failed to generate CSR: %v", err), nil)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate gateway CSR"})
		return
	}

	enrollReq := models.EnrollmentRequest{
		Token:  enrollmentToken,
		CSRPEM: csrPEM,
		FQDN:   fqdn,
		Name:   gatewayName,
	}
	body, _ := json.Marshal(enrollReq)
	httpReq, _ := http.NewRequest("POST", cloudURL+"/api/gateway/enroll", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: s.buildCloudTransport(),
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		// Cloud unreachable — save config anyway, enrollment can be retried later
		s.logWarn("setup.step.enroll", fmt.Sprintf("Cloud enrollment failed (will retry later): %v", err), nil)
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "saved",
			"step":    "enroll",
			"message": "Cloud configuration saved. Enrollment will be retried when cloud is reachable.",
		})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var enrollResp models.EnrollmentResponse
	json.Unmarshal(respBody, &enrollResp)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 && enrollResp.Status == "enrolled" {
		if err := s.installGatewayEnrollment(enrollResp); err != nil {
			s.logError("setup.step.enroll", fmt.Sprintf("Failed to persist enrollment artifacts: %v", err), nil)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "enrollment succeeded but local certificate installation failed"})
			return
		}
		s.enrolled = true
		s.logInfo("setup.step.enroll", "Gateway enrolled with cloud during setup", map[string]string{
			"gateway_id": enrollResp.GatewayID,
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "enrolled", "step": "enroll"})
	} else {
		s.logWarn("setup.step.enroll", fmt.Sprintf("Cloud enrollment response: %s", string(respBody)), nil)
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "saved",
			"step":    "enroll",
			"message": "Cloud configuration saved. Enrollment response: " + enrollResp.Status,
		})
	}
}

// handleSetupStepFinish — Final wizard step: marks setup as completed
// Creates a session token so the user can enter the admin interface directly.
func (s *Server) handleSetupStepFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.IsSetupComplete() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Setup already completed"})
		return
	}

	if !s.validateSetupToken(w, r) {
		return
	}

	if s.cfg.Setup == nil {
		s.cfg.Setup = &config.SetupConfig{}
	}

	s.cfg.Setup.Completed = true
	s.cfg.Setup.SetupDate = time.Now().Format(time.RFC3339)
	s.cfg.Setup.SetupToken = "" // clear one-time setup token
	s.cfg.SaveToFile(s.configPath)

	// Create a session token so the user enters the admin interface directly
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	csrfBytes := make([]byte, 32)
	rand.Read(csrfBytes)
	csrfToken := hex.EncodeToString(csrfBytes)

	s.adminTokens[token] = time.Now().Add(4 * time.Hour)
	s.csrfTokens[token] = csrfToken
	s.tokenActivity[token] = time.Now()

	// Set the admin token as an HttpOnly cookie (same as login)
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSCert != "",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   4 * 3600,
	})

	s.logInfo("setup.wizard.complete", "Setup wizard completed", nil)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "completed",
		"message":    "Setup wizard completed.",
		"csrf_token": csrfToken,
	})
}

// handleSetupReset — POST /api/setup/reset (authenticated)
// Clears setup state so the wizard can be re-entered. Generates a new setup token.
func (s *Server) handleSetupReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear setup state
	s.cfg.Setup = &config.SetupConfig{}
	token := s.cfg.GenerateSetupToken()

	// Invalidate all admin session tokens
	s.adminTokens = make(map[string]time.Time)
	s.tokenActivity = make(map[string]time.Time)

	s.cfg.SaveToFile(s.configPath)

	s.logInfo("setup.reset", "Setup wizard reset by admin — re-entering setup mode", nil)
	log.Printf("[ADMIN] ┌─────────────────────────────────────────────┐")
	log.Printf("[ADMIN] │  SETUP RESET — New Setup Token:             │")
	log.Printf("[ADMIN] │  %s              │", token)
	log.Printf("[ADMIN] └─────────────────────────────────────────────┘")

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "reset",
		"message": "Setup wizard has been reset. Check the container logs for the new setup token.",
	})
}

// ═══════════════════════════════════════════════════════════════
//  SETTINGS — ADMIN ACCOUNT & GATEWAY IDENTITY
// ═══════════════════════════════════════════════════════════════

// handleChangePassword — POST /api/settings/password (authenticated)
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if errMsg := config.ValidatePasswordStrength(req.NewPassword); errMsg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errMsg})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.Setup == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No admin account configured"})
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(s.cfg.Setup.AdminPassHash), []byte(req.CurrentPassword)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Current password is incorrect"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 12)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to hash password"})
		return
	}

	s.cfg.Setup.AdminPassHash = string(hash)
	// Invalidate all admin tokens — force re-login after password change
	s.adminTokens = make(map[string]time.Time)
	s.tokenActivity = make(map[string]time.Time)
	s.cfg.SaveToFile(s.configPath)

	s.logInfo("settings.password.changed", "Admin password changed — all sessions invalidated", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "Password changed successfully"})
}

// handleAdminInfo — GET /api/settings/admin (authenticated)
func (s *Server) handleAdminInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	email := ""
	setupDate := ""
	if s.cfg.Setup != nil {
		email = s.cfg.Setup.AdminEmail
		setupDate = s.cfg.Setup.SetupDate
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":      email,
		"fqdn":       s.cfg.FQDN,
		"enrolled":   s.enrolled,
		"setup_date": setupDate,
	})
}

// ═══════════════════════════════════════════════════════════════
//  ADMIN LOGIN (local account — NOT IdP)
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting by remote IP
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = fwd
	}
	if s.isLoginRateLimited(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Too many login attempts. Please try again later."})
		return
	}

	s.mu.RLock()
	setup := s.cfg.Setup
	s.mu.RUnlock()

	if setup == nil || !setup.Completed {
		writeJSON(w, http.StatusPreconditionFailed, map[string]string{"error": "Setup not completed"})
		return
	}

	var req models.LoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	// Generic error message to prevent account enumeration
	genericErr := "Invalid credentials"

	if req.Email != setup.AdminEmail {
		s.recordLoginFailure(ip)
		s.logWarn("login.failed", fmt.Sprintf("Login failed from %s", ip), nil)
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{Status: "denied", Error: genericErr})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(setup.AdminPassHash), []byte(req.Password)); err != nil {
		s.recordLoginFailure(ip)
		s.logWarn("login.failed", fmt.Sprintf("Login failed from %s", ip), nil)
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{Status: "denied", Error: genericErr})
		return
	}

	// Clear failed attempts on successful login
	s.clearLoginFailures(ip)

	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	csrfBytes := make([]byte, 32)
	rand.Read(csrfBytes)
	csrfToken := hex.EncodeToString(csrfBytes)

	s.mu.Lock()
	s.adminTokens[token] = time.Now().Add(4 * time.Hour)
	s.csrfTokens[token] = csrfToken
	s.tokenActivity[token] = time.Now()
	s.mu.Unlock()

	// Set the admin token as an HttpOnly, Secure, SameSite=Strict cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSCert != "",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   4 * 3600, // 4 hours
	})

	s.logInfo("login.success", fmt.Sprintf("Admin logged in: %s", req.Email), nil)
	writeJSON(w, http.StatusOK, models.LoginResponse{Status: "authorized", CsrfToken: csrfToken})
}

// handleLogout clears the admin session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read token from cookie to invalidate server-side
	if cookie, err := r.Cookie("admin_token"); err == nil {
		s.mu.Lock()
		delete(s.adminTokens, cookie.Value)
		delete(s.csrfTokens, cookie.Value)
		s.mu.Unlock()
	}

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSCert != "",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// isLoginRateLimited checks if the IP is currently locked out.
func (s *Server) isLoginRateLimited(ip string) bool {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()
	info, ok := s.loginAttempts[ip]
	if !ok {
		return false
	}
	return time.Now().Before(info.lockedUntil)
}

// recordLoginFailure tracks a failed login and applies exponential backoff.
func (s *Server) recordLoginFailure(ip string) {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()
	info, ok := s.loginAttempts[ip]
	if !ok {
		info = &loginAttemptInfo{}
		s.loginAttempts[ip] = info
	}
	info.failures++
	info.lastTry = time.Now()
	// Exponential backoff: 1s, 2s, 4s, 8s, 16s... capped at 5 minutes
	lockDuration := time.Duration(1<<min(info.failures-1, 8)) * time.Second
	if lockDuration > 5*time.Minute {
		lockDuration = 5 * time.Minute
	}
	// Start lockout after 3 failures
	if info.failures >= 3 {
		info.lockedUntil = time.Now().Add(lockDuration)
	}
}

// clearLoginFailures resets the failure counter for an IP.
func (s *Server) clearLoginFailures(ip string) {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()
	delete(s.loginAttempts, ip)
}

// withAuth is middleware that requires a valid admin token.
// During initial setup, only health and login are allowed without auth.
func (s *Server) withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		setupDone := s.cfg.IsSetupComplete()
		s.mu.RUnlock()

		if !setupDone {
			// During setup, only health and login endpoints bypass auth
			path := r.URL.Path
			if path == "/api/health" || path == "/api/login" {
				handler(w, r)
				return
			}
			// All other endpoints need a valid token even during setup
		}

		// Read admin token from HttpOnly cookie (preferred) or header (legacy/API)
		token := ""
		if cookie, err := r.Cookie("admin_token"); err == nil {
			token = cookie.Value
		}
		if token == "" {
			token = r.Header.Get("X-Admin-Token")
		}
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Admin token required"})
			return
		}

		s.mu.RLock()
		var validToken bool
		var expired bool
		var matchedToken string
		for storedToken, expiry := range s.adminTokens {
			if subtle.ConstantTimeCompare([]byte(token), []byte(storedToken)) == 1 {
				validToken = true
				expired = time.Now().After(expiry)
				matchedToken = storedToken
				break
			}
		}
		// Check idle timeout (30 minutes of inactivity)
		if validToken && !expired && matchedToken != "" {
			if lastAct, ok := s.tokenActivity[matchedToken]; ok {
				if time.Since(lastAct) > 30*time.Minute {
					expired = true // treat as expired due to inactivity
				}
			}
		}
		s.mu.RUnlock()

		if !validToken || expired {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid or expired token"})
			return
		}
		// Update last activity timestamp
		s.mu.Lock()
		s.tokenActivity[matchedToken] = time.Now()
		s.mu.Unlock()
		handler(w, r)
	}
}

// cleanupExpiredTokens periodically removes expired admin tokens from memory.
func (s *Server) cleanupExpiredTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, expiry := range s.adminTokens {
			idle := false
			if lastAct, ok := s.tokenActivity[token]; ok {
				idle = now.Sub(lastAct) > 30*time.Minute
			}
			if now.After(expiry) || idle {
				delete(s.adminTokens, token)
				delete(s.csrfTokens, token)
				delete(s.tokenActivity, token)
			}
		}
		s.mu.Unlock()
	}
}

// withCSRF is middleware that validates the X-CSRF-Token header on state-changing requests.
func (s *Server) withCSRF(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only enforce CSRF on state-changing methods
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			// Read admin token from cookie (preferred) or header (legacy)
			adminToken := ""
			if cookie, err := r.Cookie("admin_token"); err == nil {
				adminToken = cookie.Value
			}
			if adminToken == "" {
				adminToken = r.Header.Get("X-Admin-Token")
			}
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "CSRF token required"})
				return
			}
			s.mu.RLock()
			expected, ok := s.csrfTokens[adminToken]
			s.mu.RUnlock()
			if !ok || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(expected)) != 1 {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "Invalid CSRF token"})
				return
			}
		}
		handler(w, r)
	}
}

// ═══════════════════════════════════════════════════════════════
//  HEALTH & STATS
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	storeStatus := "healthy"
	if err := s.sessions.Health(); err != nil {
		storeStatus = "unhealthy"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "healthy",
		"service":      "secure-alert-gateway-admin",
		"uptime":       time.Since(s.startTime).String(),
		"enrolled":     s.enrolled,
		"store_status": storeStatus,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionCount, _ := s.sessions.Count()
	storeStatus := "healthy"
	if err := s.sessions.Health(); err != nil {
		storeStatus = "unhealthy"
	}

	resources, _ := s.store.ListResources()
	stats := models.AdminStats{
		ActiveSessions: sessionCount,
		TotalResources: len(resources),
		UptimeSeconds:  int64(time.Since(s.startTime).Seconds()),
		PortalStatus:   "unknown",
		StoreStatus:    storeStatus,
		SyslogStatus:   "healthy",
		SetupComplete:  s.cfg.IsSetupComplete(),
		Enrolled:       s.enrolled,
		CGNATEnabled:   s.cfg.CGNAT != nil && s.cfg.CGNAT.Enabled,
		MTLSConfigured: s.cfg.MTLSCert != "",
		IdPConfigured:  s.cfg.AuthSource != nil && s.cfg.AuthSource.ClientID != "",
		Resources:      toResourceConfigs(resources),
	}
	writeJSON(w, http.StatusOK, stats)
}

// ═══════════════════════════════════════════════════════════════
//  SSE — SERVER-SENT EVENTS (live dashboard stream)
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send initial event immediately
	s.writeSSEEvent(w, flusher)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			s.writeSSEEvent(w, flusher)
		}
	}
}

func (s *Server) writeSSEEvent(w http.ResponseWriter, flusher http.Flusher) {
	s.mu.RLock()
	sessionCount, _ := s.sessions.Count()
	storeOK := s.sessions.Health() == nil
	enrolled := s.enrolled
	mtls := s.cfg.MTLSCert != ""
	idp := s.cfg.AuthSource != nil && s.cfg.AuthSource.ClientID != ""
	cgnat := s.cfg.CGNAT != nil && s.cfg.CGNAT.Enabled
	uptime := int64(time.Since(s.startTime).Seconds())
	s.mu.RUnlock()

	nRes := s.store.CountResources()

	data := map[string]interface{}{
		"active_sessions": sessionCount,
		"total_resources": nRes,
		"uptime_seconds":  uptime,
		"store_ok":        storeOK,
		"syslog_ok":       true,
		"enrolled":        enrolled,
		"mtls_configured": mtls,
		"idp_configured":  idp,
		"cgnat_enabled":   cgnat,
	}

	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
	flusher.Flush()
}

// ═══════════════════════════════════════════════════════════════
//  mTLS CSR GENERATION & CERTIFICATE INSTALLATION
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleGenerateCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.CSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.CommonName == "" {
		s.mu.RLock()
		req.CommonName = s.cfg.FQDN
		s.mu.RUnlock()
	}
	if req.CommonName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "FQDN must be configured before generating CSR"})
		return
	}
	if req.Organization == "" {
		req.Organization = "Secure Alert Gateway"
	}

	// Generate ECDSA P-256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Key generation failed"})
		return
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
			Country:      []string{req.Country},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CSR generation failed"})
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, _ := x509.MarshalECPrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.MkdirAll("certs", 0755)
	keyPath := "certs/mtls-gateway.key"
	os.WriteFile(keyPath, keyPEM, 0600)

	s.mu.Lock()
	s.cfg.MTLSKey = keyPath
	s.cfg.MTLSCSR = string(csrPEM)
	s.cfg.SaveToFile(s.configPath)
	s.mu.Unlock()

	s.logInfo("certs.csr_generated", fmt.Sprintf("mTLS CSR generated for CN=%s", req.CommonName), nil)
	writeJSON(w, http.StatusOK, models.CSRResponse{CSRPEM: string(csrPEM), KeyPath: keyPath})
}

func (s *Server) handleInstallMTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid PEM certificate"})
		return
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid certificate: " + err.Error()})
		return
	}

	os.MkdirAll("certs", 0755)
	certPath := "certs/mtls-gateway.crt"
	os.WriteFile(certPath, []byte(req.CertPEM), 0644)

	s.mu.Lock()
	s.cfg.MTLSCert = certPath
	s.cfg.MTLSCSR = ""
	s.cfg.SaveToFile(s.configPath)
	s.mu.Unlock()

	s.logInfo("certs.mtls_installed", "mTLS client certificate installed", nil)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "installed",
		"message": "mTLS certificate installed. Secure Alert Gateway authenticated with cloud.",
	})
}

func (s *Server) handleUploadSSL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if _, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid cert/key pair: " + err.Error()})
		return
	}

	os.MkdirAll("certs", 0755)
	certPath := "certs/gateway-ssl.crt"
	keyPath := "certs/gateway-ssl.key"
	os.WriteFile(certPath, []byte(req.CertPEM), 0644)
	os.WriteFile(keyPath, []byte(req.KeyPEM), 0600)

	s.mu.Lock()
	s.cfg.TLSCert = certPath
	s.cfg.TLSKey = keyPath
	s.cfg.SaveToFile(s.configPath)
	s.mu.Unlock()

	s.logInfo("certs.ssl_uploaded", "Public SSL certificate uploaded", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "uploaded"})
}

func (s *Server) handleCertStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certInfo := map[string]interface{}{
		"ssl_enabled":     s.cfg.TLSCert != "",
		"ssl_cert_path":   s.cfg.TLSCert,
		"ssl_key_path":    s.cfg.TLSKey,
		"mtls_configured": s.cfg.MTLSCert != "",
		"mtls_cert_path":  s.cfg.MTLSCert,
		"mtls_key_path":   s.cfg.MTLSKey,
		"csr_pending":     s.cfg.MTLSCSR != "",
	}

	if s.cfg.TLSCert != "" {
		if info := readCertInfo(s.cfg.TLSCert); info != nil {
			certInfo["ssl_subject"] = info["subject"]
			certInfo["ssl_issuer"] = info["issuer"]
			certInfo["ssl_not_after"] = info["not_after"]
		}
	}
	if s.cfg.MTLSCert != "" {
		if info := readCertInfo(s.cfg.MTLSCert); info != nil {
			certInfo["mtls_subject"] = info["subject"]
			certInfo["mtls_issuer"] = info["issuer"]
			certInfo["mtls_not_after"] = info["not_after"]
		}
	}

	writeJSON(w, http.StatusOK, certInfo)
}

func readCertInfo(path string) map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return map[string]interface{}{
		"subject":   cert.Subject.String(),
		"issuer":    cert.Issuer.String(),
		"not_after": cert.NotAfter.Format(time.RFC3339),
	}
}

// ═══════════════════════════════════════════════════════════════
//  PRIMARY AUTHENTICATION SOURCE (IdP / OIDC)
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleIdPStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cfg.AuthSource == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"configured": false})
		return
	}
	as := s.cfg.AuthSource
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"configured":        as.ClientID != "",
		"hostname":          as.Hostname,
		"auth_url":          as.AuthURL,
		"token_url":         as.TokenURL,
		"userinfo_url":      as.UserInfoURL,
		"client_id":         as.ClientID,
		"redirect_uri":      as.RedirectURI,
		"scopes":            as.Scopes,
		"client_secret_set": as.ClientSecret != "",
	})
}

func (s *Server) handleIdPConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AuthSourceUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	if s.cfg.AuthSource == nil {
		s.cfg.AuthSource = &config.AuthSourceConfig{}
	}
	as := s.cfg.AuthSource
	if req.Hostname != "" {
		as.Hostname = req.Hostname
	}
	if req.AuthURL != "" {
		as.AuthURL = req.AuthURL
	}
	if req.TokenURL != "" {
		as.TokenURL = req.TokenURL
	}
	if req.UserInfoURL != "" {
		as.UserInfoURL = req.UserInfoURL
	}
	if req.ClientID != "" {
		as.ClientID = req.ClientID
	}
	if req.ClientSecret != "" {
		as.ClientSecret = req.ClientSecret
	}
	if req.RedirectURI != "" {
		as.RedirectURI = req.RedirectURI
	}
	if req.Scopes != "" {
		as.Scopes = req.Scopes
	}
	s.cfg.SaveToFile(s.configPath)
	s.mu.Unlock()

	s.logInfo("idp.configured", fmt.Sprintf("IdP configured: hostname=%s", req.Hostname), nil)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "configured",
		"message": "Primary Authentication Source (IdP) has been configured.",
	})
}

// ═══════════════════════════════════════════════════════════════
//  CGNAT ADDRESS POOL CONFIGURATION
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleCGNATStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cfg.CGNAT == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}
	cg := s.cfg.CGNAT
	resources, _ := s.store.ListResources()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":      cg.Enabled,
		"pool_start":   cg.PoolStart,
		"pool_end":     cg.PoolEnd,
		"subnet_mask":  cg.SubnetMask,
		"next_ip":      s.store.NextTunnelIP(),
		"assigned_ips": countAssignedIPs(resources),
	})
}

func (s *Server) handleCGNATConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.CGNATUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	if s.cfg.CGNAT == nil {
		s.cfg.CGNAT = &config.CGNATConfig{}
	}
	s.cfg.CGNAT.Enabled = req.Enabled
	if req.PoolStart != "" {
		s.cfg.CGNAT.PoolStart = req.PoolStart
	}
	if req.PoolEnd != "" {
		s.cfg.CGNAT.PoolEnd = req.PoolEnd
	}
	if req.SubnetMask != "" {
		s.cfg.CGNAT.SubnetMask = req.SubnetMask
	}
	s.cfg.SaveToFile(s.configPath)
	s.mu.Unlock()

	s.logInfo("cgnat.configured", fmt.Sprintf("CGNAT configured: %s - %s", req.PoolStart, req.PoolEnd), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "configured"})
}

func countAssignedIPs(resources []config.Resource) int {
	n := 0
	for _, r := range resources {
		if r.TunnelIP != "" {
			n++
		}
	}
	return n
}

// ═══════════════════════════════════════════════════════════════
//  ENROLLMENT
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var incoming struct {
		Token    string `json:"token"`
		CloudURL string `json:"cloud_url,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if incoming.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enrollment token is required"})
		return
	}

	s.mu.Lock()
	if incoming.CloudURL != "" {
		s.cfg.CloudURL = incoming.CloudURL
		s.cfg.SaveToFile(s.configPath)
	}
	cloudURL := s.cfg.CloudURL
	fqdn := s.cfg.FQDN
	gatewayName := fqdn
	if gatewayName == "" {
		gatewayName = "ZTNA Gateway"
	}
	s.mu.Unlock()

	if cloudURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cloud_url is not configured"})
		return
	}

	// Generate CSR for the gateway
	csrPEM, err := s.ensureGatewayCSR(fqdn)
	if err != nil {
		s.logError("enrollment.failed", fmt.Sprintf("Failed to generate CSR: %v", err), nil)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate gateway CSR"})
		return
	}

	req := models.EnrollmentRequest{
		Token:  incoming.Token,
		CSRPEM: csrPEM,
		FQDN:   fqdn,
		Name:   gatewayName,
	}
	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", cloudURL+"/api/gateway/enroll", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: s.buildCloudTransport(),
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		s.logError("enrollment.failed", fmt.Sprintf("Enrollment failed: %v", err), nil)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "cloud unreachable"})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var enrollResp models.EnrollmentResponse
	json.Unmarshal(respBody, &enrollResp)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 && enrollResp.Status == "enrolled" {
		if err := s.installGatewayEnrollment(enrollResp); err != nil {
			s.logError("enrollment.failed", fmt.Sprintf("Enrollment persisted failed: %v", err), nil)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "enrollment succeeded but local installation failed"})
			return
		}
		s.enrolled = true
		s.logInfo("enrollment.success", "Gateway enrolled with cloud", map[string]string{
			"gateway_id": enrollResp.GatewayID,
		})
	}
	writeJSON(w, http.StatusOK, enrollResp)
}

func (s *Server) handleEnrollmentStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enrolled":  s.enrolled,
		"cloud_url": s.cfg.CloudURL,
	})
}

// ═══════════════════════════════════════════════════════════════
//  CONFIGURATION
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	resources, _ := s.store.ListResources()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"listen_addr":     s.cfg.ListenAddr,
		"cloud_url":       s.cfg.CloudURL,
		"internal_dns":    s.cfg.InternalDNS,
		"session_timeout": s.cfg.SessionTimeout,
		"resources":       resources,
		"tls_enabled":     s.cfg.TLSCert != "",
		"cgnat_enabled":   s.cfg.CGNAT != nil && s.cfg.CGNAT.Enabled,
	})
}

func (s *Server) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if v, ok := updates["listen_addr"].(string); ok {
		s.cfg.ListenAddr = v
	}
	if v, ok := updates["cloud_url"].(string); ok {
		s.cfg.CloudURL = v
	}
	if v, ok := updates["internal_dns"].(string); ok {
		s.cfg.InternalDNS = v
	}
	if v, ok := updates["session_timeout"].(float64); ok {
		s.cfg.SessionTimeout = int(v)
	}

	if err := s.cfg.SaveToFile(s.configPath); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.logInfo("config.updated", "Gateway configuration updated", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// ═══════════════════════════════════════════════════════════════
//  RESOURCES
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	resources, _ := s.store.ListResources()
	writeJSON(w, http.StatusOK, resources)
}

func (s *Server) handleResourceAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var res config.Resource
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if res.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	// Validate resource name (must be a valid DNS label)
	if !dns.IsValidResourceName(res.Name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be alphanumeric with hyphens only (max 63 chars, no leading/trailing hyphens)"})
		return
	}

	// Validate internal IP if provided
	if res.InternalIP != "" && net.ParseIP(res.InternalIP) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid internal_ip format"})
		return
	}

	// Validate tunnel IP is in CGNAT range if provided
	if res.TunnelIP != "" {
		tip := net.ParseIP(res.TunnelIP)
		if tip == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tunnel_ip format"})
			return
		}
		_, cgnatNet, _ := net.ParseCIDR("100.64.0.0/10")
		if !cgnatNet.Contains(tip) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tunnel_ip must be in the CGNAT range (100.64.0.0/10)"})
			return
		}
	}

	// Validate port range
	if res.Port < 0 || res.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "port must be between 0 and 65535"})
		return
	}

	// Validate protocol
	validProtocols := map[string]bool{"rdp": true, "ssh": true, "http": true, "https": true, "tcp": true, "": true}
	if !validProtocols[res.Protocol] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol must be one of: rdp, ssh, http, https, tcp"})
		return
	}

	if res.Type == "" {
		// infer type from protocol for backward compat
		switch res.Protocol {
		case "ssh":
			res.Type = "ssh"
		case "rdp":
			res.Type = "rdp"
		default:
			res.Type = "web"
		}
	}
	if res.Protocol == "" {
		switch res.Type {
		case "ssh":
			res.Protocol = "ssh"
		case "rdp":
			res.Protocol = "rdp"
		default:
			res.Protocol = "https"
		}
	}
	if res.SessionDuration == 0 {
		res.SessionDuration = 480
	}
	// Default enabled to true for new resources
	if !res.Enabled {
		res.Enabled = true
	}
	res.CreatedAt = time.Now().Format(time.RFC3339)

	// Handle cert PEM upload — save to disk, store paths
	if res.CertPEM != "" && res.KeyPEM != "" {
		os.MkdirAll("certs", 0755)
		safeName := hex.EncodeToString([]byte(res.Name))[:16]
		certPath := fmt.Sprintf("certs/app-%s.crt", safeName)
		keyPath := fmt.Sprintf("certs/app-%s.key", safeName)
		os.WriteFile(certPath, []byte(res.CertPEM), 0644)
		os.WriteFile(keyPath, []byte(res.KeyPEM), 0600)
		res.CertPEM = certPath
		res.KeyPEM = keyPath
	}

	// Check for duplicate name
	if existing, _ := s.store.GetResource(res.Name); existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "application with this name already exists"})
		return
	}
	// Check for duplicate CloudClientID
	if res.CloudClientID != "" && s.store.HasResourceWithClientID(res.CloudClientID) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an application with this Client ID is already linked"})
		return
	}
	if res.TunnelIP == "" && s.cfg.CGNAT != nil && s.cfg.CGNAT.Enabled {
		res.TunnelIP = s.store.NextTunnelIP()
	}
	if err := s.store.CreateResource(&res); err != nil {
		log.Printf("[ADMIN] Failed to create resource: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to persist resource"})
		return
	}

	s.logInfo("resource.added", fmt.Sprintf("Application added: %s (type=%s)", res.Name, res.Type), map[string]string{
		"resource": res.Name,
		"type":     res.Type,
		"admin":    s.cfg.Setup.AdminEmail,
	})
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleResourceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req config.Resource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Capture old resource for audit diff
	oldRes, _ := s.store.GetResource(req.Name)

	// Preserve created_at from existing resource
	if req.CreatedAt == "" {
		if oldRes != nil {
			req.CreatedAt = oldRes.CreatedAt
		}
	}

	// Handle cert PEM upload — save to disk
	if req.CertPEM != "" && req.KeyPEM != "" && !isPath(req.CertPEM) {
		os.MkdirAll("certs", 0755)
		safeName := hex.EncodeToString([]byte(req.Name))[:16]
		certPath := fmt.Sprintf("certs/app-%s.crt", safeName)
		keyPath := fmt.Sprintf("certs/app-%s.key", safeName)
		os.WriteFile(certPath, []byte(req.CertPEM), 0644)
		os.WriteFile(keyPath, []byte(req.KeyPEM), 0600)
		req.CertPEM = certPath
		req.KeyPEM = keyPath
	}

	if err := s.store.UpdateResource(req.Name, &req); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "application not found"})
		return
	}

	// Build audit diff fields
	auditFields := map[string]string{"admin": s.cfg.Setup.AdminEmail}
	if oldRes != nil {
		if oldRes.InternalIP != req.InternalIP {
			auditFields["old_internal_ip"] = oldRes.InternalIP
			auditFields["new_internal_ip"] = req.InternalIP
		}
		if oldRes.TunnelIP != req.TunnelIP {
			auditFields["old_tunnel_ip"] = oldRes.TunnelIP
			auditFields["new_tunnel_ip"] = req.TunnelIP
		}
		if oldRes.Port != req.Port {
			auditFields["old_port"] = fmt.Sprintf("%d", oldRes.Port)
			auditFields["new_port"] = fmt.Sprintf("%d", req.Port)
		}
		if oldRes.Protocol != req.Protocol {
			auditFields["old_protocol"] = oldRes.Protocol
			auditFields["new_protocol"] = req.Protocol
		}
		if oldRes.Enabled != req.Enabled {
			auditFields["old_enabled"] = fmt.Sprintf("%v", oldRes.Enabled)
			auditFields["new_enabled"] = fmt.Sprintf("%v", req.Enabled)
		}
	}
	s.logInfo("resource.updated", fmt.Sprintf("Application updated: %s", req.Name), auditFields)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func isPath(s string) bool {
	return len(s) > 0 && (s[0] == '/' || s[0] == '.' || (len(s) > 1 && s[1] == ':'))
}

func (s *Server) handleResourceRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := s.store.DeleteResource(req.Name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}

	s.logInfo("resource.removed", fmt.Sprintf("Resource removed: %s", req.Name), map[string]string{"admin": s.cfg.Setup.AdminEmail})
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// handleVerifyCloud validates per-app credentials with the cloud and returns app metadata.
func (s *Server) handleVerifyCloud(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		APIHostname  string `json:"api_hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.ClientID == "" || req.ClientSecret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id and client_secret are required"})
		return
	}

	// Use cloud URL from config only — do not allow user-provided URLs (SSRF prevention)
	cloudURL := s.cfg.CloudURL
	if req.APIHostname != "" {
		// Validate the hostname is an HTTPS URL matching the configured cloud domain
		if req.APIHostname != cloudURL {
			log.Printf("[ADMIN] verify-cloud: ignoring user-provided api_hostname %q, using configured cloud URL", req.APIHostname)
		}
	}

	// Call cloud /api/gateway/app-info
	body, _ := json.Marshal(map[string]string{
		"client_id":     req.ClientID,
		"client_secret": req.ClientSecret,
	})

	tr := s.buildCloudTransport()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Post(cloudURL+"/api/gateway/app-info", "application/json", bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "cannot reach cloud: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.Unmarshal(respBody, &errResp)
		msg := errResp["error"]
		if msg == "" {
			msg = "invalid credentials"
		}
		writeJSON(w, resp.StatusCode, map[string]string{"error": msg})
		return
	}

	// Forward the cloud response (app metadata)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

// handleToggleResource enables or disables an application.
func (s *Server) handleToggleResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := s.store.ToggleResource(req.Name, req.Enabled); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}

	state := "enabled"
	if !req.Enabled {
		state = "disabled"
	}
	s.logInfo("app.toggled", fmt.Sprintf("Application %s: %s", state, req.Name), map[string]string{
		"resource": req.Name,
		"enabled":  fmt.Sprintf("%v", req.Enabled),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": state})
}

// ═══════════════════════════════════════════════════════════════
//  SESSIONS
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.sessions.ListActive()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := s.sessions.Revoke(req.SessionID); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	s.logInfo("session.revoked", fmt.Sprintf("Session revoked: %s", req.SessionID), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ═══════════════════════════════════════════════════════════════
//  ADMIN LOGS (in-memory ring buffer)
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	event := r.URL.Query().Get("event")

	limit := 500
	if lim := r.URL.Query().Get("limit"); lim != "" {
		var n int
		fmt.Sscanf(lim, "%d", &n)
		if n > 0 {
			limit = n
		}
	}

	entries, err := s.store.ListLogs(level, event, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

// ═══════════════════════════════════════════════════════════════
//  ACCESS POLICIES (per-application)
// ═══════════════════════════════════════════════════════════════

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	resources, _ := s.store.ListResources()

	type appPolicy struct {
		Name        string `json:"name"`
		Protocol    string `json:"protocol"`
		MFARequired bool   `json:"mfa_required"`
		Port        int    `json:"port"`
		TunnelIP    string `json:"tunnel_ip"`
	}

	policies := make([]appPolicy, len(resources))
	for i, r := range resources {
		policies[i] = appPolicy{
			Name:        r.Name,
			Protocol:    r.Protocol,
			MFARequired: r.MFARequired,
			Port:        r.Port,
			TunnelIP:    r.TunnelIP,
		}
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handlePolicySave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name        string `json:"name"`
		MFARequired bool   `json:"mfa_required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := s.store.SetMFARequired(req.Name, req.MFARequired); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "application not found"})
		return
	}

	s.logInfo("policy.updated", fmt.Sprintf("Policy updated for %s: mfa=%v", req.Name, req.MFARequired), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// ═══════════════════════════════════════════════════════════════
//  ADMIN UI (SPA)
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ss := setupState{
		Completed: s.cfg.IsSetupComplete(),
		HasAdmin:  s.cfg.Setup != nil && s.cfg.Setup.AdminEmail != "" && s.cfg.Setup.AdminPassHash != "",
	}
	s.mu.RUnlock()
	handleUIRequest(w, r, ss)
}

// ═══════════════════════════════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════════════════════════════

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Only allow same-origin or localhost origins
		if origin != "" && isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Token, X-Setup-Token, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Security headers (OWASP)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isAllowedOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	hostname := parsed.Hostname()
	switch hostname {
	case "localhost", "127.0.0.1", "::1":
		return parsed.Scheme == "http" || parsed.Scheme == "https"
	}
	return false
}

// fqdnRegex validates FQDN format: labels separated by dots, 2+ char TLD, max 253 chars.
var fqdnRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func isValidFQDN(fqdn string) bool {
	return len(fqdn) <= 253 && fqdnRegex.MatchString(fqdn)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[ADMIN] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// buildCloudTransport creates an HTTP transport for cloud communication.
// Uses CloudCA (or TLSCA fallback) for certificate validation.
// Loads mTLS client cert when available (post-enrollment).
func (s *Server) buildCloudTransport() *http.Transport {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	s.mu.RLock()
	caPath := s.cfg.CloudCA
	tlsCAPath := s.cfg.TLSCA
	certPath := s.cfg.MTLSCert
	keyPath := s.cfg.MTLSKey
	s.mu.RUnlock()

	// CA: prefer CloudCA, fall back to TLSCA
	effectiveCA := caPath
	if effectiveCA == "" {
		effectiveCA = tlsCAPath
	}
	if effectiveCA != "" {
		caPEM, err := os.ReadFile(effectiveCA)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caPEM) {
				tlsCfg.RootCAs = pool
			} else {
				log.Printf("[ADMIN] WARNING: could not parse cloud CA from %s, falling back to system roots", effectiveCA)
			}
		} else {
			log.Printf("[ADMIN] WARNING: could not read cloud CA file %s: %v", effectiveCA, err)
		}
	} else {
		log.Printf("[ADMIN] WARNING: No CloudCA/TLSCA configured — using system trust store for cloud TLS verification")
	}

	// Certificate pinning: verify server cert SHA-256 fingerprint
	s.mu.RLock()
	pinSHA := s.cfg.CloudCertSHA256
	s.mu.RUnlock()
	if pinSHA != "" {
		pinned := strings.ToLower(strings.ReplaceAll(pinSHA, ":", ""))
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no server certificate presented")
			}
			h := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := hex.EncodeToString(h[:])
			if got != pinned {
				return fmt.Errorf("cloud cert fingerprint mismatch: got %s, want %s", got, pinned)
			}
			return nil
		}
	}

	// mTLS client cert (post-enrollment)
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			tlsCfg.Certificates = []tls.Certificate{cert}
			log.Printf("[ADMIN] Cloud transport using mTLS client cert from %s", certPath)
		} else {
			log.Printf("[ADMIN] WARNING: could not load mTLS client cert: %v (pre-enrollment is OK)", err)
		}
	}

	return &http.Transport{TLSClientConfig: tlsCfg}
}

// ═══════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════

func toResourceConfigs(resources []config.Resource) []models.ResourceConfig {
	result := make([]models.ResourceConfig, len(resources))
	for i, r := range resources {
		var hosts []models.InternalHost
		for _, h := range r.InternalHosts {
			hosts = append(hosts, models.InternalHost{Host: h.Host, Ports: h.Ports})
		}
		result[i] = models.ResourceConfig{
			Name:            r.Name,
			Type:            r.Type,
			InternalIP:      r.InternalIP,
			TunnelIP:        r.TunnelIP,
			Port:            r.Port,
			Protocol:        r.Protocol,
			MFARequired:     r.MFARequired,
			ExternalURL:     r.ExternalURL,
			InternalURL:     r.InternalURL,
			InternalHosts:   hosts,
			SessionDuration: r.SessionDuration,
			CertSource:      r.CertSource,
			PassHeaders:     r.PassHeaders,
			CreatedAt:       r.CreatedAt,
		}
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) ensureGatewayCSR(commonName string) (string, error) {
	s.mu.RLock()
	existingCSR := s.cfg.MTLSCSR
	keyPath := s.cfg.MTLSKey
	s.mu.RUnlock()

	if existingCSR != "" && keyPath != "" {
		if _, err := os.Stat(keyPath); err == nil {
			return existingCSR, nil
		}
	}

	if commonName == "" {
		return "", fmt.Errorf("FQDN must be configured before generating mTLS CSR")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Secure Alert Gateway"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return "", err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll("certs", 0755); err != nil {
		return "", err
	}
	keyPath = "certs/mtls-gateway.key"
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", err
	}

	s.mu.Lock()
	s.cfg.MTLSKey = keyPath
	s.cfg.MTLSCSR = string(csrPEM)
	s.cfg.SaveToFile(s.configPath)
	s.mu.Unlock()

	return string(csrPEM), nil
}

func (s *Server) installGatewayEnrollment(enrollResp models.EnrollmentResponse) error {
	if err := os.MkdirAll("certs", 0755); err != nil {
		return err
	}

	certPath := "certs/mtls-gateway.crt"
	if err := config.AtomicWriteFile(certPath, []byte(enrollResp.CertPEM), 0644); err != nil {
		return err
	}

	caPath := ""
	if enrollResp.CAPEM != "" {
		caPath = "certs/cloud-ca.crt"
		if err := config.AtomicWriteFile(caPath, []byte(enrollResp.CAPEM), 0644); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.cfg.MTLSCert = certPath
	s.cfg.MTLSCSR = ""
	s.cfg.EnrollmentToken = "" // Clear enrollment token after successful enrollment
	if caPath != "" {
		s.cfg.CloudCA = caPath
	}
	if s.cfg.AuthSource == nil || s.cfg.AuthSource.ClientID == "" {
		s.configureBuiltInAuthSourceLocked(s.cfg.CloudURL, enrollResp.OIDCClientID, enrollResp.OIDCClientSecret)
	}
	if enrollResp.OIDCAuthURL != "" {
		s.cfg.AuthSource.AuthURL = enrollResp.OIDCAuthURL
	}
	if enrollResp.OIDCTokenURL != "" {
		s.cfg.AuthSource.TokenURL = enrollResp.OIDCTokenURL
	}
	s.cfg.SaveToFile(s.configPath)
	s.mu.Unlock()

	return nil
}

func (s *Server) configureBuiltInAuthSourceLocked(cloudURL, clientID, clientSecret string) {
	if s.cfg.AuthSource == nil {
		s.cfg.AuthSource = &config.AuthSourceConfig{}
	}
	as := s.cfg.AuthSource
	parsed, err := url.Parse(cloudURL)
	if err == nil {
		as.Hostname = parsed.Hostname()
	}
	as.AuthURL = strings.TrimRight(cloudURL, "/") + "/auth/authorize"
	as.TokenURL = strings.TrimRight(cloudURL, "/") + "/auth/token"
	as.UserInfoURL = strings.TrimRight(cloudURL, "/") + "/auth/userinfo"
	if clientID != "" {
		as.ClientID = clientID
	}
	if clientSecret != "" {
		as.ClientSecret = clientSecret
	}
	if s.cfg.FQDN != "" {
		as.RedirectURI = "https://" + s.cfg.FQDN + "/auth/callback"
	}
	if as.Scopes == "" {
		as.Scopes = "openid profile email"
	}
	if as.CallbackListenAddr == "" {
		as.CallbackListenAddr = ":443"
	}
}
