package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud/admin"
	"cloud/certs"
	"cloud/idp"
	"cloud/models"
	"cloud/util"

	"github.com/go-webauthn/webauthn/webauthn"
)

// enrollRateEntry tracks per-IP enrollment rate limiting.
type enrollRateEntry struct {
	count   int
	resetAt time.Time
}

// Server is the HTTP API server for the ZTNA Cloud component
type Server struct {
	pa         *admin.PolicyAdministrator
	mux        *http.ServeMux
	addr       string
	mtlsCAPool *x509.CertPool

	enrollLimiterMu sync.Mutex
	enrollLimiter   map[string]*enrollRateEntry

	authLimiterMu sync.Mutex
	authLimiter   map[string]*enrollRateEntry // reuse: per-IP rate limit for login/register
}

// NewServer creates a new API server.
// Gateway and device endpoints always require mTLS, so the client CA is mandatory.
func NewServer(pa *admin.PolicyAdministrator, addr, mtlsCAPath string) (*Server, error) {
	if strings.TrimSpace(mtlsCAPath) == "" {
		return nil, fmt.Errorf("strict mTLS requires mtls_ca to be configured on the cloud server")
	}

	s := &Server{
		pa:            pa,
		mux:           http.NewServeMux(),
		addr:          addr,
		enrollLimiter: make(map[string]*enrollRateEntry),
		authLimiter:   make(map[string]*enrollRateEntry),
	}

	pool, err := loadCertPool(mtlsCAPath)
	if err != nil {
		return nil, err
	}
	s.mtlsCAPool = pool
	log.Printf("[API] mTLS client cert verification enabled (CA: %s)", mtlsCAPath)

	s.registerRoutes()
	return s, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse client CA")
	}
	return caCertPool, nil
}

// registerRoutes sets up all API endpoints
func (s *Server) registerRoutes() {
	// ─────────────────────────────────────────────
	// Public endpoints (no auth required)
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/verify-mfa", s.handleVerifyMFA)
	s.mux.HandleFunc("/api/auth/mfa-step-up", s.handleMFAStepUp)
	s.mux.HandleFunc("/api/auth/register", s.handleRegister)
	s.mux.HandleFunc("/health", s.handleHealthCheck)
	s.mux.HandleFunc("/api/ca/cert", s.handleCACert)                   // Public: returns CA certificate PEM
	s.mux.HandleFunc("/api/cert-fingerprint", s.handleCertFingerprint) // Public: returns server TLS cert SHA-256 fingerprint

	// ─────────────────────────────────────────────
	// Browser auth flow endpoints (Duo-like)
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/auth/login", s.handleWebLoginPage)                   // Serve login HTML page
	s.mux.HandleFunc("/api/auth/start-session", s.handleStartSession)       // Connect-app creates pending session
	s.mux.HandleFunc("/api/auth/session-status", s.handleSessionStatus)     // Connect-app polls session status
	s.mux.HandleFunc("/api/auth/session-info", s.handleSessionInfo)         // Browser gets session device health
	s.mux.HandleFunc("/api/auth/complete-session", s.handleCompleteSession) // Browser completes auth

	// ─────────────────────────────────────────────
	// OIDC / OAuth2 endpoints (Cloud acts as IdP)
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/auth/authorize", s.handleOIDCAuthorize)               // OIDC Authorization endpoint
	s.mux.HandleFunc("/auth/federated/callback", s.handleFederatedCallback)  // External IdP callback
	s.mux.HandleFunc("/auth/token", s.handleOIDCToken)                       // OIDC Token endpoint
	s.mux.HandleFunc("/auth/userinfo", s.handleOIDCUserInfo)                 // OIDC UserInfo endpoint
	s.mux.HandleFunc("/api/auth/oidc-complete", s.handleOIDCCompleteSession) // Browser completes OIDC auth
	s.mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)                 // JWKS public key endpoint

	// ─────────────────────────────────────────────
	// Device health endpoint (called directly by device-health-app)
	// The device-health-app sends health reports directly to the cloud.
	// This data is NOT sent via connect-app.
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/device/health-report", s.requireClientCert(http.HandlerFunc(s.handleDirectDeviceHealthReport)))

	// ─────────────────────────────────────────────
	// Device push MFA endpoints (called by device-health-app, mTLS required)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/device/push-challenges", s.requireClientCert(http.HandlerFunc(s.handleDevicePushChallenges)))
	s.mux.Handle("/api/device/push-challenges/respond", s.requireClientCert(http.HandlerFunc(s.handleDevicePushRespond)))

	// ─────────────────────────────────────────────
	// Gateway endpoints (strict mTLS + enrolled gateway identity)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/gateway/authorize", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleGatewayAuthorize))))
	s.mux.Handle("/api/gateway/device-report", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleDeviceReport))))
	s.mux.Handle("/api/gateway/validate-token", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleValidateToken))))
	s.mux.Handle("/api/gateway/session-validate", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleSessionValidate))))
	s.mux.Handle("/api/gateway/revoked-serials", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleRevokedSerials))))

	// ─────────────────────────────────────────────
	// Authenticated user endpoints (JWT auth)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/auth/enroll-mfa", s.adminAuthMiddleware(http.HandlerFunc(s.handleEnrollMFA)))
	s.mux.Handle("/api/auth/activate-mfa", s.adminAuthMiddleware(http.HandlerFunc(s.handleActivateMFA)))
	s.mux.Handle("/api/auth/revoke-token", s.adminAuthMiddleware(http.HandlerFunc(s.handleRevokeToken)))

	// WebAuthn / Passkey endpoints
	s.mux.Handle("/api/mfa/webauthn/register/begin", s.adminAuthMiddleware(http.HandlerFunc(s.handleWebAuthnRegisterBegin)))
	s.mux.Handle("/api/mfa/webauthn/register/finish", s.adminAuthMiddleware(http.HandlerFunc(s.handleWebAuthnRegisterFinish)))
	s.mux.HandleFunc("/api/mfa/webauthn/authenticate/begin", s.handleWebAuthnAuthenticateBegin)
	s.mux.HandleFunc("/api/mfa/webauthn/authenticate/finish", s.handleWebAuthnAuthenticateFinish)

	// Push MFA endpoints (browser-side, uses MFA token)
	s.mux.HandleFunc("/api/mfa/push/begin", s.handlePushBegin)
	s.mux.HandleFunc("/api/mfa/push/status", s.handlePushStatus)

	// ─────────────────────────────────────────────
	// Admin endpoints (JWT auth + admin role)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/admin/users", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminUsers)))
	s.mux.Handle("/api/admin/rules", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminRules)))
	s.mux.Handle("/api/admin/rules/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminRuleByID)))
	s.mux.Handle("/api/admin/sessions", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSessions)))
	s.mux.Handle("/api/admin/sessions/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSessionByID)))
	s.mux.Handle("/api/admin/audit", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAudit)))

	// ─────────────────────────────────────────────
	// Device enrollment endpoints
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/api/enroll", s.handleDeviceEnroll)                                                           // Device submits CSR (no auth — bootstrapping)
	s.mux.HandleFunc("/api/enroll/status", s.handleEnrollmentStatus)                                                // Device polls enrollment status
	s.mux.HandleFunc("/api/enroll/renew", s.handleCertRenewal)                                                      // Device renews short-lived cert
	s.mux.HandleFunc("/api/enroll/start-session", s.handleEnrollStartSession)                                       // Device starts browser-based enrollment
	s.mux.HandleFunc("/api/enroll/complete-session", s.handleEnrollCompleteSession)                                 // Browser completes enrollment after OIDC login
	s.mux.HandleFunc("/api/enroll/session-status", s.handleEnrollSessionStatus)                                     // Device polls enrollment session status
	s.mux.Handle("/api/admin/enrollments", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminEnrollments)))       // List enrollments
	s.mux.Handle("/api/admin/enrollments/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminEnrollmentAction))) // Approve/revoke

	// ─────────────────────────────────────────────
	// PDP Admin endpoints (resources, dashboard)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/admin/resources", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminResources)))
	s.mux.Handle("/api/admin/resources/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminResourceByID)))
	s.mux.Handle("/api/admin/device-health", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDeviceHealth)))
	s.mux.Handle("/api/admin/device-health/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDeviceHealthByID)))
	s.mux.Handle("/api/admin/resources-generate-cert", s.adminAuthMiddleware(http.HandlerFunc(s.handleGenerateCert)))
	s.mux.Handle("/api/admin/resources-regenerate-secret/", s.adminAuthMiddleware(http.HandlerFunc(s.handleRegenerateSecret)))
	s.mux.Handle("/api/admin/dashboard", s.adminAuthMiddleware(http.HandlerFunc(s.handleDashboardStats)))

	// Gateway app-info endpoint (credential-based, requires mTLS)
	s.mux.Handle("/api/gateway/app-info", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleAppInfo))))

	// ─────────────────────────────────────────────
	// Gateway enrollment & lifecycle endpoints
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/api/gateway/enroll", s.handleGatewayEnroll)                                                                    // One-time token enrollment (no auth)
	s.mux.Handle("/api/gateway/renew-cert", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleGatewayRenewCert)))) // Cert renewal (mTLS identity)
	s.mux.Handle("/api/gateway/resources", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleGatewayResources))))  // Resource sync (mTLS identity)

	// Admin gateway management
	s.mux.Handle("/api/admin/gateways", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminGateways)))
	s.mux.Handle("/api/admin/gateways/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminGatewayByID)))

	// ─────────────────────────────────────────────
	// Dashboard SPA (serve React build)
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/dashboard/", s.handleDashboardSPA)
	s.mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
	})
}

// StartTLS begins listening for HTTPS requests
func (s *Server) StartTLS(certFile, keyFile string) error {
	handler := loggingMiddleware(securityHeadersMiddleware(corsMiddleware(s.pa.Cfg.CORSOrigins)(s.mux)))
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	tlsConfig.ClientCAs = s.mtlsCAPool
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	server := &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("[API] Server starting on %s (TLS)", s.addr)
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ─────────────────────────────────────────────
// Health check
// ─────────────────────────────────────────────

// handleCACert returns the Cloud's internal CA certificate (public info, no auth needed).
// Gateways use this to add the Cloud CA to their client cert verification pool.
func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.pa.CA == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CA not initialized"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(s.pa.CA.CertPEM)
}

// handleCertFingerprint returns the SHA-256 fingerprint of the cloud server's TLS certificate.
// Operators can use this value to configure cloud_cert_sha256 in gateway/connect/health configs.
func (s *Server) handleCertFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	certPath := s.pa.Cfg.TLSCert
	if certPath == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "TLS cert not configured"})
		return
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot read TLS cert"})
		return
	}
	fp, err := certs.CertFingerprint(certPEM)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot compute fingerprint"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sha256": fp})
}

func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	status := "ok"

	// Check database connectivity
	if err := s.pa.Store.Ping(); err != nil {
		checks["db"] = "error"
		status = "degraded"
	} else {
		checks["db"] = "ok"
	}

	// Check CA loaded
	if s.pa.CA != nil {
		checks["ca"] = "ok"
	} else {
		checks["ca"] = "not_configured"
	}

	// Check IdP JWT signing keys
	if _, err := s.pa.IdP.JWT.GetJWKSJSON(); err != nil {
		checks["idp"] = "error"
		status = "degraded"
	} else {
		checks["idp"] = "ok"
	}

	httpStatus := http.StatusOK
	if status == "degraded" {
		httpStatus = http.StatusServiceUnavailable
	}

	writeJSON(w, httpStatus, map[string]interface{}{
		"status":  status,
		"service": "ztna-cloud",
		"checks":  checks,
	})
}

// handleJWKS serves the JSON Web Key Set for JWT verification (ES256 public key)
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	jwksJSON, err := s.pa.IdP.JWT.GetJWKSJSON()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate JWKS"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(jwksJSON)
}

// ─────────────────────────────────────────────
// Authentication endpoints
// ─────────────────────────────────────────────

// checkAuthRateLimit enforces per-IP rate limiting on authentication endpoints.
// Returns true if the request should be rejected (rate limit exceeded).
func (s *Server) checkAuthRateLimit(w http.ResponseWriter, r *http.Request) bool {
	ip, _, _ := strings.Cut(r.RemoteAddr, ":")
	s.authLimiterMu.Lock()
	defer s.authLimiterMu.Unlock()

	entry, ok := s.authLimiter[ip]
	now := time.Now()
	if !ok || now.After(entry.resetAt) {
		s.authLimiter[ip] = &enrollRateEntry{count: 1, resetAt: now.Add(15 * time.Minute)}
		return false
	}
	entry.count++
	if entry.count > 10 { // max 10 auth attempts per IP per 15 minutes
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests, try again later"})
		return true
	}
	return false
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	// Note: login endpoint is exempt from CSRF validation because
	// there is no existing session to protect — the credentials themselves
	// are the authentication factor. Rate limiting prevents brute force.

	var req models.LoginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := s.pa.IdP.Login(req)
	if err != nil {
		log.Printf("[AUTH] Login error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
		return
	}

	status := http.StatusOK
	if resp.Status == "denied" {
		status = http.StatusUnauthorized
	}

	writeJSON(w, status, resp)
}

func (s *Server) handleVerifyMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	// CSRF validation for browser-based MFA requests
	if origin := r.Header.Get("Origin"); origin != "" {
		if !validateCSRF(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "CSRF validation failed"})
			return
		}
	}

	var req models.MFAVerifyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := s.pa.IdP.VerifyMFA(req)
	if err != nil {
		log.Printf("[AUTH] MFA verify error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verification failed"})
		return
	}

	status := http.StatusOK
	if resp.Status == "denied" {
		status = http.StatusUnauthorized
	}

	writeJSON(w, status, resp)
}

// POST /api/auth/mfa-step-up
// Accepts an auth token (MFADone=false) and returns a temporary MFA token
// plus the user's configured MFA methods. Called by the login page when
// the policy engine requires MFA for resource access.
func (s *Server) handleMFAStepUp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		if !validateCSRF(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "CSRF validation failed"})
			return
		}
	}

	var req models.MFAStepUpRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.AuthToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "auth_token is required"})
		return
	}

	// Parse the auth token WITHOUT requiring MFADone=true
	claims, err := s.pa.IdP.ParseToken(req.AuthToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, models.MFAStepUpResponse{
			Status:  "denied",
			Message: "Invalid or expired auth token",
		})
		return
	}

	// Look up user to get configured MFA methods
	user, exists := s.pa.IdP.Users.GetUser(claims.UserID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, models.MFAStepUpResponse{
			Status:  "denied",
			Message: "User not found",
		})
		return
	}

	if !user.MFAEnabled() {
		writeJSON(w, http.StatusBadRequest, models.MFAStepUpResponse{
			Status:  "denied",
			Message: "No MFA methods configured for this user",
		})
		return
	}

	// Issue a temporary MFA token carrying the user's methods
	mfaToken, err := s.pa.IdP.JWT.GenerateMFAToken(user.ID, user.Username, user.Role, user.MFAMethods)
	if err != nil {
		log.Printf("[AUTH] MFA step-up token error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to issue MFA token"})
		return
	}

	log.Printf("[AUTH] MFA step-up: %s — issued MFA token, methods=%v", user.Username, user.MFAMethods)

	writeJSON(w, http.StatusOK, models.MFAStepUpResponse{
		Status:     "mfa_required",
		Message:    "MFA verification required",
		MFAToken:   mfaToken,
		MFAMethods: user.MFAMethods,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	var req models.RegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, err := s.pa.IdP.Users.Register(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration failed", err)
		return
	}

	writeJSON(w, http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "User registered successfully",
		Data: map[string]string{
			"user_id":  user.ID,
			"username": user.Username,
		},
	})
}

func (s *Server) handleEnrollMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	resp, err := s.pa.IdP.Users.EnrollMFA(userID, s.pa.Cfg.TOTPIssuer)
	if err != nil {
		writeError(w, http.StatusBadRequest, "MFA enrollment failed", err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleActivateMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID := r.Header.Get("X-User-ID")

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if err := s.pa.IdP.Users.ActivateMFA(userID, body.Code); err != nil {
		writeError(w, http.StatusBadRequest, "MFA activation failed", err)
		return
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "MFA activated successfully",
	})
}

// ─────────────────────────────────────────────
// WebAuthn endpoints
// ─────────────────────────────────────────────

// POST /api/mfa/webauthn/register/begin — requires JWT auth
// Starts the WebAuthn credential registration ceremony.
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.pa.IdP.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	user, exists := s.pa.IdP.Users.GetUser(userID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	existingCreds, err := s.loadWebAuthnCredentials(userID)
	if err != nil {
		log.Printf("[WEBAUTHN] Failed to load credentials for %s: %v", userID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	opts, err := s.pa.IdP.WebAuthn.BeginRegistration(user, existingCreds)
	if err != nil {
		log.Printf("[WEBAUTHN] BeginRegistration error for %s: %v", user.Username, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start registration"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(opts)
}

// POST /api/mfa/webauthn/register/finish — requires JWT auth
// Completes the WebAuthn credential registration ceremony.
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.pa.IdP.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	user, exists := s.pa.IdP.Users.GetUser(userID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	existingCreds, err := s.loadWebAuthnCredentials(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	cred, err := s.pa.IdP.WebAuthn.FinishRegistration(user, existingCreds, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration failed", err)
		return
	}

	// Persist the credential
	credJSON, _ := json.Marshal(cred)
	credID, _ := util.GenerateID("wc")

	// Read optional friendly name from query param
	credName := r.URL.Query().Get("name")
	if credName == "" {
		credName = "Passkey"
	}

	dbCred := &models.WebAuthnCredential{
		ID:             credID,
		UserID:         userID,
		CredentialID:   hex.EncodeToString(cred.ID),
		CredentialJSON: string(credJSON),
		Name:           credName,
		CreatedAt:      time.Now(),
	}

	if err := s.pa.Store.SaveWebAuthnCredential(dbCred); err != nil {
		log.Printf("[WEBAUTHN] Failed to save credential for %s: %v", user.Username, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save credential"})
		return
	}

	// Add "webauthn" to user's MFA methods if not already present
	s.pa.IdP.Users.AddMFAMethod(userID, "webauthn")

	log.Printf("[WEBAUTHN] Credential registered for user %s (name=%s)", user.Username, credName)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "Passkey registered successfully",
		"name":    credName,
	})
}

// POST /api/mfa/webauthn/authenticate/begin — uses MFA token (no full JWT auth)
// Starts the WebAuthn authentication ceremony during MFA step-up.
func (s *Server) handleWebAuthnAuthenticateBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.pa.IdP.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
		return
	}

	var body struct {
		MFAToken string `json:"mfa_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	claims, err := s.pa.IdP.JWT.ValidateMFAToken(body.MFAToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA token"})
		return
	}

	user, exists := s.pa.IdP.Users.GetUser(claims.UserID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	creds, err := s.loadWebAuthnCredentials(claims.UserID)
	if err != nil || len(creds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no WebAuthn credentials registered"})
		return
	}

	opts, err := s.pa.IdP.WebAuthn.BeginAuthentication(user, creds)
	if err != nil {
		log.Printf("[WEBAUTHN] BeginAuthentication error for %s: %v", user.Username, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start authentication"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(opts)
}

// POST /api/mfa/webauthn/authenticate/finish — uses MFA token
// Completes the WebAuthn authentication ceremony (MFA verification).
func (s *Server) handleWebAuthnAuthenticateFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.pa.IdP.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
		return
	}

	// The MFA token is passed as a query param since the body is the
	// authenticator response that go-webauthn reads from r.Body.
	mfaToken := r.URL.Query().Get("mfa_token")
	if mfaToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mfa_token required"})
		return
	}

	claims, err := s.pa.IdP.JWT.ValidateMFAToken(mfaToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA token"})
		return
	}

	user, exists := s.pa.IdP.Users.GetUser(claims.UserID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	creds, err := s.loadWebAuthnCredentials(claims.UserID)
	if err != nil || len(creds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no WebAuthn credentials registered"})
		return
	}

	updatedCred, err := s.pa.IdP.WebAuthn.FinishAuthentication(user, creds, r)
	if err != nil {
		log.Printf("[WEBAUTHN] FinishAuthentication error for %s: %v", user.Username, err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "WebAuthn verification failed"})
		return
	}

	// Update the credential's sign count in the database
	credJSON, _ := json.Marshal(updatedCred)
	s.pa.Store.UpdateWebAuthnCredentialJSON(hex.EncodeToString(updatedCred.ID), string(credJSON))

	// Issue full auth token with MFA completed
	authToken, err := s.pa.IdP.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
		return
	}

	log.Printf("[WEBAUTHN] MFA verified via WebAuthn for user %s", user.Username)
	writeJSON(w, http.StatusOK, models.MFAVerifyResponse{
		Status:    "authenticated",
		Message:   "WebAuthn authentication successful",
		AuthToken: authToken,
	})
}

// loadWebAuthnCredentials loads and deserialises all WebAuthn credentials for a user.
func (s *Server) loadWebAuthnCredentials(userID string) ([]webauthn.Credential, error) {
	dbCreds, err := s.pa.Store.GetWebAuthnCredentials(userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(dbCreds))
	for _, dc := range dbCreds {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(dc.CredentialJSON), &c); err != nil {
			log.Printf("[WEBAUTHN] Corrupt credential %s: %v", dc.ID, err)
			continue
		}
		creds = append(creds, c)
	}
	return creds, nil
}

// ─────────────────────────────────────────────
// Push MFA endpoints
// ─────────────────────────────────────────────

// POST /api/mfa/push/begin — browser initiates a push challenge (uses MFA token)
func (s *Server) handlePushBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		MFAToken string `json:"mfa_token"`
		DeviceID string `json:"device_id"` // which device to push to
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	claims, err := s.pa.IdP.JWT.ValidateMFAToken(body.MFAToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA token"})
		return
	}

	// If no specific device given, find the user's most recently seen device
	deviceID := body.DeviceID
	if deviceID == "" {
		deviceID = s.findUserDevice(claims.UserID)
		if deviceID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no enrolled device found for push"})
			return
		}
	}

	sourceIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		sourceIP = strings.SplitN(fwd, ",", 2)[0]
	}

	ch, err := s.pa.IdP.Push.CreateChallenge(claims.UserID, claims.Username, deviceID, sourceIP)
	if err != nil {
		log.Printf("[PUSH] Failed to create challenge: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create push challenge"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":       "pending",
		"challenge_id": ch.ID,
		"device_id":    deviceID,
		"message":      "Push notification sent to your device",
	})
}

// GET /api/mfa/push/status?challenge_id=...&mfa_token=... — browser polls
func (s *Server) handlePushStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	challengeID := r.URL.Query().Get("challenge_id")
	mfaToken := r.URL.Query().Get("mfa_token")

	if challengeID == "" || mfaToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_id and mfa_token required"})
		return
	}

	claims, err := s.pa.IdP.JWT.ValidateMFAToken(mfaToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA token"})
		return
	}

	ch, err := s.pa.IdP.Push.GetStatus(challengeID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "challenge not found"})
		return
	}

	// Verify the challenge belongs to this user
	if ch.UserID != claims.UserID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "challenge does not belong to this user"})
		return
	}

	response := map[string]string{
		"status":       ch.Status,
		"challenge_id": ch.ID,
	}

	// If approved, issue the full auth token
	if ch.Status == "approved" {
		user, exists := s.pa.IdP.Users.GetUser(claims.UserID)
		if !exists {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
			return
		}

		authToken, err := s.pa.IdP.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", true)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
			return
		}
		response["auth_token"] = authToken
		response["message"] = "Push approved — authenticated"
		log.Printf("[PUSH] MFA verified via push approval for user %s", user.Username)
	}

	writeJSON(w, http.StatusOK, response)
}

// GET /api/device/push-challenges — device polls for pending challenges (mTLS required)
func (s *Server) handleDevicePushChallenges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract device ID from mTLS certificate CN
	var certCN string
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		certCN = r.TLS.VerifiedChains[0][0].Subject.CommonName
	}
	if certCN == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing client certificate identity"})
		return
	}

	challenges := s.pa.IdP.Push.GetPendingForDevice(certCN)
	if challenges == nil {
		challenges = make([]*models.PushChallenge, 0)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenges": challenges,
	})
}

// POST /api/device/push-challenges/respond — device approves/denies (mTLS required)
func (s *Server) handleDevicePushRespond(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract device ID from mTLS certificate CN
	var certCN string
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		certCN = r.TLS.VerifiedChains[0][0].Subject.CommonName
	}
	if certCN == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing client certificate identity"})
		return
	}

	var body struct {
		ChallengeID string `json:"challenge_id"`
		Decision    string `json:"decision"` // "approved" or "denied"
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Verify the challenge belongs to this device
	ch, err := s.pa.IdP.Push.GetStatus(body.ChallengeID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "challenge not found"})
		return
	}
	if ch.DeviceID != certCN {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "challenge does not belong to this device"})
		return
	}

	if err := s.pa.IdP.Push.Respond(body.ChallengeID, body.Decision); err != nil {
		writeError(w, http.StatusBadRequest, "push response failed", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "Response recorded: " + body.Decision,
	})
}

// findUserDevice finds the most recently seen device for a user.
func (s *Server) findUserDevice(userID string) string {
	// Look up device_users table for the user's registered device
	devices := s.pa.Store.GetUserDevices(userID)
	if len(devices) > 0 {
		return devices[0]
	}
	return ""
}

// ─────────────────────────────────────────────
// Gateway endpoints (called by PEP gateway)
// ─────────────────────────────────────────────

func (s *Server) handleGatewayAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req models.AccessRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	decision := s.pa.AuthorizeAccess(req)
	writeJSON(w, http.StatusOK, decision)
}

func (s *Server) handleDeviceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var report models.DeviceHealthReport
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&report); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	s.pa.ReportDeviceHealth(&report)

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Device health report received",
	})
}

// handleDirectDeviceHealthReport handles health reports sent directly by the
// device-health-app. Requires a valid client certificate (mTLS). The device_id
// in the report body must match the certificate's CN to prevent spoofing.
//
// Flow: device-health-app → POST /api/device/health-report → cloud stores health
//
//	connect-app → gateway → cloud /api/gateway/authorize → cloud looks up stored health
func (s *Server) handleDirectDeviceHealthReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract device identity from mTLS certificate CN
	var certCN string
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		certCN = r.TLS.VerifiedChains[0][0].Subject.CommonName
	}
	if certCN == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing client certificate identity"})
		return
	}

	var report models.DeviceHealthReport
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&report); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if report.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
		return
	}

	// Bind device_id to certificate CN — prevent impersonation
	if report.DeviceID != certCN {
		log.Printf("[API] Device health report rejected: device_id=%q does not match cert CN=%q", report.DeviceID, certCN)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device_id does not match certificate identity"})
		return
	}

	// Set reported time if not provided
	if report.ReportedAt.IsZero() {
		report.ReportedAt = time.Now()
	}

	s.pa.ReportDeviceHealth(&report)

	log.Printf("[API] Device health report received directly from device-health-app: device=%s score=%d",
		report.DeviceID, report.OverallScore)

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Device health report received",
	})
}

func (s *Server) handleValidateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	claims, err := s.pa.IdP.ValidateToken(body.Token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"valid": "false",
			"error": "invalid or expired token",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":    true,
		"user_id":  claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
	})
}

func (s *Server) handleSessionValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	session, err := s.pa.Sessions.ValidateSession(body.SessionID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"valid": "false",
			"error": "invalid or expired session",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"session": session,
	})
}

// ─────────────────────────────────────────────
// Admin endpoints
// ─────────────────────────────────────────────

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	users := s.pa.IdP.Users.ListUsers()

	// Strip sensitive fields
	type safeUser struct {
		ID         string   `json:"id"`
		Username   string   `json:"username"`
		Email      string   `json:"email"`
		MFAEnabled bool     `json:"mfa_enabled"`
		MFAMethods []string `json:"mfa_methods"`
		Role       string   `json:"role"`
		Disabled   bool     `json:"disabled"`
		CreatedAt  string   `json:"created_at"`
		LastLogin  string   `json:"last_login,omitempty"`
	}

	safeUsers := make([]safeUser, 0, len(users))
	for _, u := range users {
		su := safeUser{
			ID:         u.ID,
			Username:   u.Username,
			Email:      u.Email,
			MFAEnabled: u.MFAEnabled(),
			MFAMethods: u.MFAMethods,
			Role:       u.Role,
			Disabled:   u.Disabled,
			CreatedAt:  u.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if !u.LastLoginAt.IsZero() {
			su.LastLogin = u.LastLoginAt.Format("2006-01-02 15:04:05")
		}
		safeUsers = append(safeUsers, su)
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    safeUsers,
	})
}

func (s *Server) handleAdminRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := s.pa.Rules.ListRules()
		writeJSON(w, http.StatusOK, models.APIResponse{
			Success: true,
			Data:    rules,
		})

	case http.MethodPost:
		var rule models.PolicyRule
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if err := s.pa.Rules.CreateRule(&rule); err != nil {
			writeError(w, http.StatusBadRequest, "failed to create rule", err)
			return
		}
		writeJSON(w, http.StatusCreated, models.APIResponse{
			Success: true,
			Message: "Rule created",
			Data:    rule,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminRuleByID(w http.ResponseWriter, r *http.Request) {
	// Extract rule ID from URL: /api/admin/rules/{id}
	ruleID := strings.TrimPrefix(r.URL.Path, "/api/admin/rules/")
	if ruleID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule ID required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rule, err := s.pa.Rules.GetRule(ruleID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: rule})

	case http.MethodPut:
		var rule models.PolicyRule
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		rule.ID = ruleID
		if err := s.pa.Rules.UpdateRule(&rule); err != nil {
			writeError(w, http.StatusBadRequest, "failed to update rule", err)
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Rule updated", Data: rule})

	case http.MethodDelete:
		if err := s.pa.Rules.DeleteRule(ruleID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Rule deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	sessions := s.pa.Sessions.ListActiveSessions()
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    sessions,
	})
}

func (s *Server) handleAdminSessionByID(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/admin/sessions/")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session ID required"})
		return
	}

	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := s.pa.Sessions.RevokeSession(sessionID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	s.pa.Audit.LogEvent("session_revoked", r.Header.Get("X-User-ID"),
		r.Header.Get("X-Username"), r.RemoteAddr, "", "",
		"Session revoked: "+sessionID, true)

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Session revoked",
	})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	entries := s.pa.Audit.GetRecentEntries(limit)
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    entries,
	})
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError logs the real error server-side and returns a sanitized message to the client.
func writeError(w http.ResponseWriter, status int, userMsg string, err error) {
	log.Printf("[ERROR] %s: %v", userMsg, err)
	writeJSON(w, status, map[string]string{"error": userMsg})
}

// generateClientCredentials creates Duo-style per-app credentials.
// ClientID: "DI" + 18 hex chars (20 chars total)
// ClientSecret: 40 hex chars
func generateClientCredentials() (clientID, clientSecret string, err error) {
	idBytes := make([]byte, 9)
	if _, err = rand.Read(idBytes); err != nil {
		return
	}
	clientID = "DI" + hex.EncodeToString(idBytes)

	secretBytes := make([]byte, 20)
	if _, err = rand.Read(secretBytes); err != nil {
		return
	}
	clientSecret = hex.EncodeToString(secretBytes)
	return
}

// ─────────────────────────────────────────────
// Browser Auth Flow Handlers (Duo-like)
// ─────────────────────────────────────────────

// handleWebLoginPage serves the login HTML page with a CSRF token cookie
func (s *Server) handleWebLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate and set CSRF token as a cookie (double-submit cookie pattern)
	csrfToken := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false, // Must be readable by JavaScript for double-submit
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	// Find the web/login.html file relative to the executable
	htmlPath := findWebFile("login.html")
	if htmlPath == "" {
		http.Error(w, "Login page not found", http.StatusInternalServerError)
		log.Printf("[API] login.html not found in any search path")
		return
	}

	// Prevent caching so the CSRF cookie is always freshly set
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.ServeFile(w, r, htmlPath)
}

// generateCSRFToken creates a cryptographically random CSRF token
func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// validateCSRF checks the double-submit cookie CSRF token.
// The token from the X-CSRF-Token header must match the csrf_token cookie.
func validateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		return false
	}
	headerToken := r.Header.Get("X-CSRF-Token")
	if headerToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(headerToken)) == 1
}

// findWebFile locates a web asset file by searching common paths
func findWebFile(filename string) string {
	// Common locations to search
	searchPaths := []string{
		filepath.Join("web", filename),
		filepath.Join("..", "cloud", "web", filename),
	}

	// Add path relative to executable
	if exe, err := os.Executable(); err == nil {
		searchPaths = append(searchPaths, filepath.Join(filepath.Dir(exe), "web", filename))
	}

	// Add path relative to source file
	if _, srcFile, _, ok := runtime.Caller(0); ok {
		searchPaths = append(searchPaths, filepath.Join(filepath.Dir(srcFile), "..", "web", filename))
	}

	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// handleStartSession creates a pending browser auth session (called by connect-app)
func (s *Server) handleStartSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req models.StartAuthSessionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	sessionID, err := util.GenerateID("auth")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate session ID"})
		return
	}

	session := &models.PendingAuthSession{
		ID:           sessionID,
		DeviceID:     req.DeviceID,
		Hostname:     req.Hostname,
		Status:       "pending",
		DeviceHealth: req.DeviceHealth,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}

	s.pa.Store.SavePendingAuth(session)

	// Store device health if provided
	if req.DeviceHealth != nil && req.DeviceID != "" {
		req.DeviceHealth.DeviceID = req.DeviceID
		s.pa.ReportDeviceHealth(req.DeviceHealth)
	}

	// Build auth URL - the browser page URL with session parameter
	// Use the request host to build the URL
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	authURL := fmt.Sprintf("%s://%s/auth/login?session=%s", scheme, r.Host, sessionID)

	log.Printf("[API] Browser auth session created: %s (device=%s, host=%s)", sessionID, req.DeviceID, req.Hostname)

	writeJSON(w, http.StatusOK, models.StartAuthSessionResponse{
		SessionID: sessionID,
		AuthURL:   authURL,
		ExpiresIn: 300,
	})
}

// handleSessionStatus returns the current status of a pending auth session (polled by connect-app)
func (s *Server) handleSessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}

	session, ok := s.pa.Store.GetPendingAuth(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, models.AuthSessionStatusResponse{
			Status:  "expired",
			Message: "Session not found or expired",
		})
		return
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		s.pa.Store.DeletePendingAuth(sessionID)
		writeJSON(w, http.StatusOK, models.AuthSessionStatusResponse{
			Status:  "expired",
			Message: "Session expired",
		})
		return
	}

	resp := models.AuthSessionStatusResponse{
		Status:  session.Status,
		Message: "Waiting for user authentication",
	}

	if session.Status == "authenticated" {
		resp.AuthToken = session.AuthToken
		resp.Message = "Authentication successful"
		// Clean up the session after token is retrieved
		s.pa.Store.DeletePendingAuth(sessionID)
	} else if session.Status == "denied" {
		resp.Message = "Access denied by security policy"
		s.pa.Store.DeletePendingAuth(sessionID)
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleSessionInfo returns session info including device health (for the browser login page)
func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}

	session, ok := s.pa.Store.GetPendingAuth(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id":    session.ID,
		"device_id":     session.DeviceID,
		"hostname":      session.Hostname,
		"device_health": session.DeviceHealth,
		"status":        session.Status,
	})
}

// handleCompleteSession is called by the browser after successful login.
// It validates the auth token, evaluates policy, and marks the session as authenticated or denied.
func (s *Server) handleCompleteSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	session, ok := s.pa.Store.GetPendingAuth(req.SessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found or expired"})
		return
	}

	// Validate the auth token
	claims, err := s.pa.IdP.ValidateToken(req.AuthToken)
	if err != nil {
		session.Status = "denied"
		s.pa.Store.SavePendingAuth(session)
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success":  false,
			"decision": "denied",
			"message":  "Invalid authentication token",
		})
		return
	}

	// Build an access request for policy evaluation
	accessReq := models.AccessRequest{
		UserID:    claims.UserID,
		Username:  claims.Username,
		DeviceID:  session.DeviceID,
		SourceIP:  r.RemoteAddr,
		Resource:  "ztna-access", // general access
		Protocol:  "https",
		AuthToken: req.AuthToken,
	}

	// Load device health from session snapshot or store
	if session.DeviceHealth != nil {
		accessReq.DeviceHealth = session.DeviceHealth
	} else if session.DeviceID != "" {
		if health, ok := s.pa.Store.GetDeviceHealth(session.DeviceID); ok {
			accessReq.DeviceHealth = health
		}
	}

	// Health gate: require device-health-app to be running and reporting
	if accessReq.DeviceHealth == nil && session.DeviceID != "" {
		log.Printf("[API] Session denied: device_id=%s has no health data (HDA not running)", session.DeviceID)
		session.Status = "denied"
		s.pa.Store.SavePendingAuth(session)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":  false,
			"decision": "denied",
			"message":  "Device Health App is not running or has not reported device status. Start Device Health App and try again.",
		})
		return
	}

	// Evaluate policy
	decision := s.pa.Engine.Evaluate(accessReq)

	log.Printf("[API] Session complete: user=%s decision=%s risk=%d",
		claims.Username, decision.Decision, decision.RiskScore)

	switch decision.Decision {
	case "allow":
		session.Status = "authenticated"
		session.AuthToken = req.AuthToken
		session.UserID = claims.UserID
		session.Username = claims.Username
		s.pa.Store.SavePendingAuth(session)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":    true,
			"decision":   "allow",
			"message":    "Access granted",
			"risk_score": decision.RiskScore,
		})

	case "mfa_required":
		// If user already completed MFA (has MFADone in token), allow anyway
		if claims.MFADone {
			session.Status = "authenticated"
			session.AuthToken = req.AuthToken
			session.UserID = claims.UserID
			session.Username = claims.Username
			s.pa.Store.SavePendingAuth(session)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":    true,
				"decision":   "allow",
				"message":    "Access granted (MFA verified)",
				"risk_score": decision.RiskScore,
			})
		} else {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":  false,
				"decision": "mfa_required",
				"message":  decision.Reason,
			})
		}

	default: // "deny", "restrict"
		session.Status = "denied"
		s.pa.Store.SavePendingAuth(session)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":  false,
			"decision": decision.Decision,
			"message":  decision.Reason,
		})
	}
}

// ─────────────────────────────────────────────
// PDP Resource management handlers
// ─────────────────────────────────────────────

func (s *Server) handleAdminResources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resources := s.pa.Store.ListResources()
		writeJSON(w, http.StatusOK, resources)

	case http.MethodPost:
		var res models.Resource
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&res); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		// Validate required fields
		if res.Name == "" || res.Type == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and type are required"})
			return
		}

		validTypes := map[string]bool{"ssh": true, "rdp": true, "web": true, "gateway": true}
		if !validTypes[res.Type] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be ssh, rdp, web, or gateway"})
			return
		}

		now := time.Now()
		res.ID, _ = util.GenerateID("res")
		res.CreatedAt = now
		res.UpdatedAt = now
		if res.CertMode == "" {
			res.CertMode = "manual"
		}
		// enabled defaults to true for new resources (explicit false in JSON is not possible with this approach)
		res.Enabled = true

		// Auto-generate per-app credentials (Duo-style)
		cid, csec, err := generateClientCredentials()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate credentials"})
			return
		}
		res.ClientID = cid
		res.ClientSecret = csec

		// Auto-generate self-signed cert if requested
		if res.CertMode == "self-signed" {
			domain := res.CertDomain
			if domain == "" {
				domain = res.Host
			}
			certPEM, keyPEM, err := certs.GenerateSelfSignedCert(domain, 365)
			if err != nil {
				log.Printf("[PDP] Failed to generate self-signed cert for %s: %v", domain, err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate certificate"})
				return
			}
			res.CertPEM = string(certPEM)
			res.KeyPEM = string(keyPEM)
			res.CertExpiry = now.Add(365 * 24 * time.Hour).Format(time.RFC3339)
			res.CertDomain = domain
		}

		s.pa.Store.SaveResource(&res)

		log.Printf("[PDP] Resource created: %s (%s) type=%s host=%s", res.ID, res.Name, res.Type, res.Host)

		writeJSON(w, http.StatusCreated, res)

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminResourceByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/resources/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "resource ID required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		res, ok := s.pa.Store.GetResource(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
			return
		}
		writeJSON(w, http.StatusOK, res)

	case http.MethodPut:
		existing, ok := s.pa.Store.GetResource(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
			return
		}

		// Decode into a map to detect which fields were actually sent (PATCH semantics)
		var fields map[string]json.RawMessage
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&fields); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		// Start from the existing resource and only overwrite fields that were sent
		updated := *existing
		updated.UpdatedAt = time.Now()

		if v, ok := fields["name"]; ok {
			json.Unmarshal(v, &updated.Name)
		}
		if v, ok := fields["description"]; ok {
			json.Unmarshal(v, &updated.Description)
		}
		if v, ok := fields["type"]; ok {
			json.Unmarshal(v, &updated.Type)
		}
		if v, ok := fields["host"]; ok {
			json.Unmarshal(v, &updated.Host)
		}
		if v, ok := fields["port"]; ok {
			json.Unmarshal(v, &updated.Port)
		}
		if v, ok := fields["external_url"]; ok {
			json.Unmarshal(v, &updated.ExternalURL)
		}
		if v, ok := fields["enabled"]; ok {
			json.Unmarshal(v, &updated.Enabled)
		}
		if v, ok := fields["tags"]; ok {
			json.Unmarshal(v, &updated.Tags)
		}
		if v, ok := fields["metadata"]; ok {
			json.Unmarshal(v, &updated.Metadata)
		}
		if v, ok := fields["allowed_roles"]; ok {
			json.Unmarshal(v, &updated.AllowedRoles)
		}
		if v, ok := fields["require_mfa"]; ok {
			json.Unmarshal(v, &updated.RequireMFA)
		}
		if v, ok := fields["cert_mode"]; ok {
			json.Unmarshal(v, &updated.CertMode)
		}
		if v, ok := fields["cert_pem"]; ok {
			json.Unmarshal(v, &updated.CertPEM)
		}
		if v, ok := fields["key_pem"]; ok {
			json.Unmarshal(v, &updated.KeyPEM)
		}
		if v, ok := fields["cert_expiry"]; ok {
			json.Unmarshal(v, &updated.CertExpiry)
		}
		if v, ok := fields["cert_domain"]; ok {
			json.Unmarshal(v, &updated.CertDomain)
		}

		s.pa.Store.SaveResource(&updated)
		log.Printf("[PDP] Resource updated: %s (%s)", updated.ID, updated.Name)
		writeJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		if !s.pa.Store.DeleteResource(id) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
			return
		}
		log.Printf("[PDP] Resource deleted: %s", id)
		writeJSON(w, http.StatusOK, map[string]string{"message": "resource deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleRegenerateSecret generates a new ClientSecret for a resource (ClientID stays the same).
func (s *Server) handleRegenerateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/admin/resources-regenerate-secret/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "resource ID required"})
		return
	}

	res, ok := s.pa.Store.GetResource(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}

	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate secret"})
		return
	}
	res.ClientSecret = hex.EncodeToString(secretBytes)
	res.UpdatedAt = time.Now()
	s.pa.Store.SaveResource(res)

	log.Printf("[PDP] Secret regenerated for resource: %s (%s)", res.ID, res.Name)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"client_id":     res.ClientID,
		"client_secret": res.ClientSecret,
	})
}

// handleAppInfo validates per-app credentials and returns app metadata.
// Called by gateway when an admin links an application.
func (s *Server) handleAppInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.ClientID == "" || req.ClientSecret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id and client_secret are required"})
		return
	}

	res, ok := s.pa.Store.GetResourceByClientID(req.ClientID)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	if res.ClientSecret != "" && subtle.ConstantTimeCompare([]byte(res.ClientSecret), []byte(req.ClientSecret)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":          res.ID,
		"name":        res.Name,
		"type":        res.Type,
		"description": res.Description,
		"enabled":     res.Enabled,
		"require_mfa": res.RequireMFA,
	})
}

func (s *Server) handleAdminDeviceHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	reports := s.pa.Store.ListDeviceHealth()
	if reports == nil {
		reports = []*models.DeviceHealthReport{}
	}
	// Show newest reports first to make recent device activity visible in dashboard.
	sort.SliceStable(reports, func(i, j int) bool {
		return reports[i].ReportedAt.After(reports[j].ReportedAt)
	})

	writeJSON(w, http.StatusOK, reports)
}

func (s *Server) handleAdminDeviceHealthByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	deviceID := strings.TrimPrefix(r.URL.Path, "/api/admin/device-health/")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device ID required"})
		return
	}

	report, ok := s.pa.Store.GetDeviceHealth(deviceID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleGenerateCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		ResourceID string `json:"resource_id"`
		Domain     string `json:"domain"`
		ValidDays  int    `json:"valid_days"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	res, ok := s.pa.Store.GetResource(req.ResourceID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}

	domain := req.Domain
	if domain == "" {
		domain = res.Host
	}
	validDays := req.ValidDays
	if validDays <= 0 {
		validDays = 365
	}

	certPEM, keyPEM, err := certs.GenerateSelfSignedCert(domain, validDays)
	if err != nil {
		log.Printf("[PDP] Failed to generate cert for %s: %v", domain, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate certificate"})
		return
	}

	res.CertPEM = string(certPEM)
	res.KeyPEM = string(keyPEM)
	res.CertMode = "self-signed"
	res.CertDomain = domain
	res.CertExpiry = time.Now().Add(time.Duration(validDays) * 24 * time.Hour).Format(time.RFC3339)
	res.UpdatedAt = time.Now()
	s.pa.Store.SaveResource(res)

	log.Printf("[PDP] Certificate generated for resource %s (domain=%s, days=%d)", res.ID, domain, validDays)

	info, _ := certs.ParseCertPEM(res.CertPEM)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Certificate generated",
		"cert_info": info,
	})
}

// ─────────────────────────────────────────────
// Dashboard stats endpoint
// ─────────────────────────────────────────────

func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	users := s.pa.Store.ListUsers()
	sessions := s.pa.Store.ListSessions()
	resources := s.pa.Store.ListResources()
	rules := s.pa.Store.ListPolicyRules()
	audit := s.pa.Store.GetAuditLog(50)

	activeSessions := 0
	for _, sess := range sessions {
		if !sess.Revoked && !sess.ExpiresAt.Before(time.Now()) {
			activeSessions++
		}
	}

	recentDenials := 0
	for _, entry := range audit {
		if entry.Decision == "deny" {
			recentDenials++
		}
	}

	var totalRisk float64
	healthCount := 0
	healthyDevices := 0
	allDeviceHealth := s.pa.Store.ListDeviceHealth()
	for _, dh := range allDeviceHealth {
		totalRisk += float64(100 - dh.OverallScore)
		healthCount++
		if dh.OverallScore >= 70 {
			healthyDevices++
		}
	}
	avgRisk := 0.0
	if healthCount > 0 {
		avgRisk = totalRisk / float64(healthCount)
	}

	stats := models.DashboardStats{
		TotalUsers:     len(users),
		ActiveSessions: activeSessions,
		TotalResources: len(resources),
		TotalPolicies:  len(rules),
		RecentDenials:  recentDenials,
		AverageRisk:    int(avgRisk),
		HealthyDevices: healthyDevices,
		TotalDevices:   healthCount,
	}

	writeJSON(w, http.StatusOK, stats)
}

// ─────────────────────────────────────────────
// Dashboard SPA handler
// ─────────────────────────────────────────────

func (s *Server) handleDashboardSPA(w http.ResponseWriter, r *http.Request) {
	// Serve from cloud/dashboard/dist/
	distDir := findDashboardDir()
	if distDir == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "dashboard not built - run: cd cloud/dashboard && npm run build"})
		return
	}

	// Strip /dashboard/ prefix and sanitize against path traversal
	filePath := strings.TrimPrefix(r.URL.Path, "/dashboard/")
	if filePath == "" {
		filePath = "index.html"
	}

	// Prevent path traversal: clean the path and verify it stays within distDir
	cleanedPath := filepath.Clean(filePath)
	if strings.Contains(cleanedPath, "..") || filepath.IsAbs(cleanedPath) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	fullPath := filepath.Join(distDir, cleanedPath)

	// Double-check: resolved path must be within distDir
	absDistDir, _ := filepath.Abs(distDir)
	absFullPath, _ := filepath.Abs(fullPath)
	if !strings.HasPrefix(absFullPath, absDistDir+string(filepath.Separator)) && absFullPath != absDistDir {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		// SPA fallback: serve index.html for client-side routing
		fullPath = filepath.Join(distDir, "index.html")
	}

	http.ServeFile(w, r, fullPath)
}

func findDashboardDir() string {
	candidates := []string{
		"cloud/dashboard/dist",
		"dashboard/dist",
		"../cloud/dashboard/dist",
	}
	// Also check relative to executable
	if execPath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(execPath), "dashboard", "dist"))
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}

// ─────────────────────────────────────────────
// OIDC / OAuth2 Handlers (Cloud as IdP)
// ─────────────────────────────────────────────

// handleOIDCAuthorize is the OIDC Authorization Endpoint.
// The gateway redirects the user's browser here to start authentication.
//
// GET /auth/authorize?client_id=gateway_1&response_type=code&redirect_uri=https://gateway/auth/callback&state=xyz&scope=openid
//
// Flow:
//  1. Validates client_id and redirect_uri
//  2. Creates an OIDC authorize session
//  3. Serves the login page with the OIDC session context
//  4. After user authenticates, the login page calls /api/auth/oidc-complete
//  5. Cloud generates an authorization code and redirects to Gateway's callback
func (s *Server) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID := r.URL.Query().Get("client_id")
	responseType := r.URL.Query().Get("response_type")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	nonce := r.URL.Query().Get("nonce")

	// Validate required parameters
	if clientID == "" || redirectURI == "" {
		http.Error(w, "Missing required parameters: client_id, redirect_uri", http.StatusBadRequest)
		return
	}

	if responseType != "code" {
		http.Error(w, "Unsupported response_type. Only 'code' is supported.", http.StatusBadRequest)
		return
	}

	// Validate client_id
	client, err := s.pa.IdP.OIDC.ValidateClientID(clientID)
	if err != nil {
		log.Printf("[OIDC] Invalid client_id %s: %v", clientID, err)
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect_uri
	if !s.pa.IdP.OIDC.ValidateRedirectURI(client, redirectURI) {
		log.Printf("[OIDC] Invalid redirect_uri %s for client %s", redirectURI, clientID)
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Create an OIDC authorize session
	oidcSession, err := s.pa.IdP.OIDC.CreateAuthorizeSession(clientID, redirectURI, state, scope, codeChallenge, codeChallengeMethod, nonce)
	if err != nil {
		log.Printf("[OIDC] Failed to create authorize session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("[OIDC] Authorize request: client=%s redirect=%s state=%s session=%s",
		clientID, redirectURI, state, oidcSession.ID)

	// ── Identity Broker: check if this gateway uses federated auth ──
	gw, found := s.pa.Store.GetGatewayByOIDCClientID(clientID)
	if found && gw.AuthMode == "federated" && gw.FederationConfig != nil {
		// Federated mode: redirect to external IdP instead of login page
		pkceVerifier, pkceChallenge, err := idp.GeneratePKCE()
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		fedState := oidcSession.ID // use OIDC session ID as the external state
		fedNonce := nonce

		extAuthURL, err := s.pa.IdP.Federation.GenerateExternalAuthURL(
			gw.FederationConfig,
			s.federatedCallbackURL(),
			fedState, fedNonce, pkceChallenge,
		)
		if err != nil {
			log.Printf("[FEDERATION] Failed to generate external auth URL: %v", err)
			http.Error(w, "Federation configuration error", http.StatusInternalServerError)
			return
		}

		// Store federation session for callback
		fedSession := &idp.FederationSession{
			ID:            oidcSession.ID,
			OIDCSessionID: oidcSession.ID,
			GatewayID:     gw.ID,
			Issuer:        gw.FederationConfig.Issuer,
			PKCEVerifier:  pkceVerifier,
			Nonce:         fedNonce,
			State:         fedState,
			CreatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(5 * time.Minute),
		}
		s.pa.IdP.OIDC.CreateFederationSession(fedSession)

		log.Printf("[FEDERATION] Redirecting to external IdP: gateway=%s issuer=%s", gw.Name, gw.FederationConfig.Issuer)
		http.Redirect(w, r, extAuthURL, http.StatusFound)
		return
	}

	// ── Builtin mode: show login page ──
	loginURL := fmt.Sprintf("/auth/login?oidc_session=%s", oidcSession.ID)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// federatedCallbackURL returns the cloud's federated callback URL based on request host.
func (s *Server) federatedCallbackURL() string {
	host := s.pa.Cfg.WebAuthnRPID
	if host == "" {
		host = "localhost" + s.pa.Cfg.ListenAddr
	}
	return fmt.Sprintf("https://%s/auth/federated/callback", host)
}

// handleFederatedCallback receives the authorization code from the external IdP
// after the user authenticates there. It exchanges the code, maps claims,
// provisions the user, issues a cloud JWT, and completes the OIDC session.
//
// GET /auth/federated/callback?code=xxx&state=oidc_session_id
func (s *Server) handleFederatedCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.Printf("[FEDERATION] External IdP returned error: %s — %s", errParam, errDesc)
		http.Error(w, "External IdP error: "+errParam+": "+errDesc, http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}

	// Retrieve the federation session (one-time use)
	fedSession, ok := s.pa.IdP.OIDC.GetFederationSession(state)
	if !ok {
		http.Error(w, "Unknown or expired federation session", http.StatusBadRequest)
		return
	}

	if time.Now().After(fedSession.ExpiresAt) {
		http.Error(w, "Federation session expired", http.StatusBadRequest)
		return
	}

	// Look up the gateway to get the federation config
	gw, found := s.pa.Store.GetGateway(fedSession.GatewayID)
	if !found || gw.FederationConfig == nil {
		http.Error(w, "Gateway federation configuration not found", http.StatusInternalServerError)
		return
	}

	// Exchange the code at the external IdP's token endpoint
	tokenResp, err := s.pa.IdP.Federation.ExchangeExternalCode(
		gw.FederationConfig, code,
		s.federatedCallbackURL(),
		fedSession.PKCEVerifier,
	)
	if err != nil {
		log.Printf("[FEDERATION] Code exchange failed: %v", err)
		http.Error(w, "Federation code exchange failed", http.StatusBadGateway)
		return
	}

	// Extract identity from the external id_token
	claims, err := s.pa.IdP.Federation.MapExternalClaims(
		tokenResp.IDToken,
		gw.FederationConfig.ClaimMapping,
	)
	if err != nil {
		log.Printf("[FEDERATION] Claim mapping failed: %v", err)
		http.Error(w, "Failed to extract identity from external IdP", http.StatusBadGateway)
		return
	}

	// Auto-provision or find the federated user
	authSource := gw.FederationConfig.Issuer
	user, err := s.pa.IdP.Users.FindOrCreateFederatedUser(
		claims.Subject, authSource, claims.Username, claims.Email,
	)
	if err != nil {
		log.Printf("[FEDERATION] User provisioning failed: %v", err)
		http.Error(w, "User provisioning failed", http.StatusInternalServerError)
		return
	}

	// Issue cloud JWT with MFADone=false (MFA step-up handled at access time)
	authToken, err := s.pa.IdP.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", false)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	// Complete the OIDC authorize session → generate authorization code
	authCode, err := s.pa.IdP.OIDC.CompleteAuthorizeSession(
		fedSession.OIDCSessionID, authToken,
		user.ID, user.Username, user.Role,
	)
	if err != nil {
		log.Printf("[FEDERATION] OIDC session completion failed: %v", err)
		http.Error(w, "OIDC session completion failed", http.StatusInternalServerError)
		return
	}

	// Build redirect URL back to the Gateway callback
	redirectURL := authCode.RedirectURI + "?code=" + url.QueryEscape(authCode.Code)
	oidcSess, ok := s.pa.IdP.OIDC.GetAuthorizeSession(fedSession.OIDCSessionID)
	if ok && oidcSess.State != "" {
		redirectURL += "&state=" + url.QueryEscape(oidcSess.State)
	}

	log.Printf("[FEDERATION] User authenticated via external IdP: user=%s source=%s → redirect to gateway",
		user.Username, authSource)

	s.pa.Audit.LogEvent("federated_login", user.ID, user.Username,
		r.RemoteAddr, "", "", "Federated auth via "+authSource+" for gateway "+gw.Name, true)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleOIDCCompleteSession is called by the browser login page after the user
// successfully authenticates (login + MFA). It generates an authorization code
// and returns the redirect URL back to the gateway callback.
//
// POST /api/auth/oidc-complete
// Body: { "oidc_session": "oidc_xxx", "auth_token": "jwt..." }
//
// Response: { "redirect_url": "https://gateway/auth/callback?code=xxx&state=yyy" }
func (s *Server) handleOIDCCompleteSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		OIDCSession string `json:"oidc_session"`
		AuthToken   string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.OIDCSession == "" || req.AuthToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "oidc_session and auth_token are required"})
		return
	}

	// Validate the auth token — allow MFADone=false because MFA enforcement
	// happens at resource access time via the policy engine, not at OIDC completion.
	claims, err := s.pa.IdP.ParseToken(req.AuthToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid auth token"})
		return
	}

	// Get user for role info
	user, exists := s.pa.IdP.Users.GetUser(claims.UserID)
	role := claims.Role
	if exists {
		role = user.Role
	}

	// Generate authorization code and complete the OIDC session
	authCode, err := s.pa.IdP.OIDC.CompleteAuthorizeSession(
		req.OIDCSession, req.AuthToken,
		claims.UserID, claims.Username, role,
	)
	if err != nil {
		log.Printf("[OIDC] Complete session failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "OIDC session completion failed"})
		return
	}

	// Build redirect URL back to the Gateway callback
	redirectURL := authCode.RedirectURI + "?code=" + url.QueryEscape(authCode.Code)
	oidcSess, ok := s.pa.IdP.OIDC.GetAuthorizeSession(req.OIDCSession)
	if ok && oidcSess.State != "" {
		redirectURL += "&state=" + url.QueryEscape(oidcSess.State)
	}

	log.Printf("[OIDC] Authorization code issued: user=%s → redirect to %s",
		claims.Username, authCode.RedirectURI)

	s.pa.Audit.LogEvent("oidc_authorize", claims.UserID, claims.Username,
		r.RemoteAddr, "", "", "Authorization code issued for "+authCode.ClientID, true)

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_url": redirectURL,
	})
}

// handleOIDCToken is the OIDC Token Endpoint.
// The gateway calls this backend-to-backend to exchange an authorization code for tokens.
//
// POST /auth/token
// Content-Type: application/x-www-form-urlencoded (or application/json)
// Body: client_id, client_secret, grant_type=authorization_code, code, redirect_uri
//
// Response: { "access_token": "jwt...", "token_type": "Bearer", "expires_in": 3600, "id_token": "jwt..." }
func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Support both form-encoded and JSON
	var clientID, clientSecret, grantType, code, redirectURI, codeVerifier, refreshTokenParam string

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			GrantType    string `json:"grant_type"`
			Code         string `json:"code"`
			RedirectURI  string `json:"redirect_uri"`
			CodeVerifier string `json:"code_verifier"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		clientID = req.ClientID
		clientSecret = req.ClientSecret
		grantType = req.GrantType
		code = req.Code
		redirectURI = req.RedirectURI
		codeVerifier = req.CodeVerifier
		refreshTokenParam = req.RefreshToken
	} else {
		// application/x-www-form-urlencoded
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form data"})
			return
		}
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
		grantType = r.FormValue("grant_type")
		code = r.FormValue("code")
		redirectURI = r.FormValue("redirect_uri")
		codeVerifier = r.FormValue("code_verifier")
		refreshTokenParam = r.FormValue("refresh_token")
	}

	// Validate grant_type
	if grantType != "authorization_code" && grantType != "refresh_token" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code and refresh_token grant types are supported",
		})
		return
	}

	// ── Handle refresh_token grant ──
	if grantType == "refresh_token" {
		if refreshTokenParam == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "refresh_token is required",
			})
			return
		}

		newRT, newToken, err := s.pa.IdP.OIDC.RefreshAccessToken(refreshTokenParam, clientID, clientSecret)
		if err != nil {
			log.Printf("[OIDC] Refresh token failed: %v", err)
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": err.Error(),
			})
			return
		}

		// Issue a new JWT for this user
		token, err := s.pa.IdP.JWT.GenerateAuthToken(newRT.UserID, newRT.Username, newRT.Role, "", "", true)
		if err != nil {
			log.Printf("[OIDC] Failed to issue token during refresh: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":             "server_error",
				"error_description": "failed to issue access token",
			})
			return
		}

		s.pa.Audit.LogEvent("oidc_token_refresh", newRT.UserID, newRT.Username,
			r.RemoteAddr, "", "", "Token refresh for "+clientID, true)

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"access_token":  token,
			"token_type":    "Bearer",
			"expires_in":    int(s.pa.Cfg.JWTExpiry.Seconds()),
			"refresh_token": newToken,
			"user_id":       newRT.UserID,
			"username":      newRT.Username,
			"role":          newRT.Role,
		})
		return
	}

	// Validate required params
	if clientID == "" || code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "client_id and code are required",
		})
		return
	}

	// Exchange the authorization code
	authCode, refreshToken, err := s.pa.IdP.OIDC.ExchangeCode(code, clientID, clientSecret, redirectURI, codeVerifier)
	if err != nil {
		log.Printf("[OIDC] Token exchange failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	// The auth_token was already issued during login. Return it as the access_token.
	// Generate a fresh id_token that includes the OIDC nonce for replay protection.
	log.Printf("[OIDC] Token exchange successful: user=%s client=%s", authCode.Username, clientID)

	idToken := authCode.AuthToken
	if authCode.Nonce != "" {
		// Issue a new JWT with nonce embedded (OIDC Core 1.0 §3.1.2.1).
		// Preserve the MFADone status from the original auth token.
		originalClaims, parseErr := s.pa.IdP.ParseToken(authCode.AuthToken)
		mfaDone := parseErr == nil && originalClaims.MFADone
		freshToken, err := s.pa.IdP.JWT.GenerateAuthToken(
			authCode.UserID, authCode.Username, authCode.Role, "", authCode.Nonce, mfaDone,
		)
		if err == nil {
			idToken = freshToken
		}
	}

	s.pa.Audit.LogEvent("oidc_token_exchange", authCode.UserID, authCode.Username,
		r.RemoteAddr, "", "", "Token exchange for "+clientID, true)

	response := map[string]interface{}{
		"access_token":  authCode.AuthToken,
		"token_type":    "Bearer",
		"expires_in":    int(s.pa.Cfg.JWTExpiry.Seconds()),
		"id_token":      idToken,
		"refresh_token": refreshToken,
		"user_id":       authCode.UserID,
		"username":      authCode.Username,
		"role":          authCode.Role,
	}
	if authCode.Nonce != "" {
		response["nonce"] = authCode.Nonce
	}

	writeJSON(w, http.StatusOK, response)
}

// ─────────────────────────────────────────────
// OIDC UserInfo
// ─────────────────────────────────────────────

// handleOIDCUserInfo implements the standard OIDC UserInfo Endpoint.
// GET /auth/userinfo — requires Bearer access_token from the token endpoint.
func (s *Server) handleOIDCUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ztna"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	claims, err := s.pa.IdP.ValidateToken(parts[1])
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ztna", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	// Look up full user record for email
	email := ""
	if user, ok := s.pa.Store.GetUser(claims.UserID); ok {
		email = user.Email
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sub":                claims.Subject,
		"user_id":            claims.UserID,
		"preferred_username": claims.Username,
		"email":              email,
		"role":               claims.Role,
	})
}

// ─────────────────────────────────────────────
// Token Revocation
// ─────────────────────────────────────────────

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Re-parse the caller's own token to get JTI and expiry
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing token"})
		return
	}

	claims, err := s.pa.IdP.ValidateToken(parts[1])
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	if claims.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token has no JTI"})
		return
	}

	expiresAt := time.Now().Add(s.pa.Cfg.JWTExpiry) // fallback
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	s.pa.Store.RevokeToken(claims.ID, expiresAt)
	s.pa.Audit.LogEvent("token_revoked", claims.UserID, claims.Username,
		r.RemoteAddr, "", "", "User revoked own token", true)

	log.Printf("[AUTH] Token revoked: jti=%s user=%s", claims.ID, claims.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ─────────────────────────────────────────────
// Device Enrollment
// ─────────────────────────────────────────────

// checkEnrollRateLimit enforces per-IP rate limiting (5 requests/minute) on enrollment endpoints.
func (s *Server) checkEnrollRateLimit(ip string) bool {
	s.enrollLimiterMu.Lock()
	defer s.enrollLimiterMu.Unlock()

	now := time.Now()
	entry, ok := s.enrollLimiter[ip]
	if !ok || now.After(entry.resetAt) {
		s.enrollLimiter[ip] = &enrollRateEntry{count: 1, resetAt: now.Add(time.Minute)}
		return true
	}
	entry.count++
	return entry.count <= 5
}

// computeCSRFingerprint extracts the public key from a PEM-encoded CSR and returns its SHA-256 hex fingerprint.
// This prevents clients from spoofing the fingerprint field.
func computeCSRFingerprint(csrPEM string) (string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature invalid: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:]), nil
}

func (s *Server) handleDeviceEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Per-IP rate limiting
	clientIP := strings.SplitN(r.RemoteAddr, ":", 2)[0]
	if !s.checkEnrollRateLimit(clientIP) {
		log.Printf("[ENROLL] Rate limit exceeded for IP %s", clientIP)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again later"})
		return
	}

	var req models.EnrollmentRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.DeviceID == "" || req.CSRPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id and csr_pem are required"})
		return
	}

	// Server-side fingerprint computation — ignore client-declared value
	csrFingerprint, err := computeCSRFingerprint(req.CSRPEM)
	if err != nil {
		log.Printf("[ENROLL] Invalid CSR from device %s: %v", req.DeviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
		return
	}

	// Check for existing pending/approved enrollment for this device+component
	component := req.Component
	if component == "" {
		component = "tunnel" // default for backward compatibility
	}

	if existing, found := s.pa.Store.GetDeviceEnrollmentByComponent(req.DeviceID, component); found {
		if existing.Status == "pending" {
			// First-come binding: reject if fingerprint doesn't match
			if existing.PublicKeyFingerprint != "" && csrFingerprint != "" &&
				existing.PublicKeyFingerprint != csrFingerprint {
				log.Printf("[ENROLL] Rejected duplicate enrollment with different key: device=%s component=%s", req.DeviceID, component)
				writeJSON(w, http.StatusForbidden, models.EnrollmentResponse{
					Status:  "rejected",
					Message: "Enrollment already pending with a different device key",
				})
				return
			}
			writeJSON(w, http.StatusOK, models.EnrollmentResponse{
				ID:      existing.ID,
				Status:  "pending",
				Message: "Enrollment request already pending admin approval",
			})
			return
		}
		if existing.Status == "approved" && existing.ExpiresAt.After(time.Now()) {
			if existing.PublicKeyFingerprint == csrFingerprint {
				// Same key — cert is still valid
				writeJSON(w, http.StatusConflict, models.EnrollmentResponse{
					ID:      existing.ID,
					Status:  "approved",
					Message: "Device already has a valid certificate for this component",
				})
				return
			}
			// Different key (e.g. TPM recreated) — revoke old and allow re-enrollment
			log.Printf("[ENROLL] Device %s re-enrolling with new key (old_fp=%s, new_fp=%s) — revoking old",
				req.DeviceID, existing.PublicKeyFingerprint[:16], csrFingerprint[:16])
			if existing.CertSerial != "" {
				s.pa.Store.RevokeCertSerial(existing.CertSerial, existing.DeviceID, existing.ExpiresAt)
			}
			existing.Status = "revoked"
			s.pa.Store.SaveDeviceEnrollment(existing)
		}
	}

	// Generate 256-bit enrollment ID (unpredictable, not guessable)
	idBytes := make([]byte, 32)
	rand.Read(idBytes)
	enrollmentID := hex.EncodeToString(idBytes)

	enrollment := &models.DeviceEnrollment{
		ID:                   enrollmentID,
		DeviceID:             req.DeviceID,
		Component:            component,
		Hostname:             req.Hostname,
		PublicKeyFingerprint: csrFingerprint,
		Status:               "pending",
		CSRPEM:               req.CSRPEM,
		EnrolledAt:           time.Now(),
	}

	s.pa.Store.SaveDeviceEnrollment(enrollment)

	log.Printf("[ENROLL] New enrollment request: id=%s device=%s component=%s hostname=%s fingerprint=%s",
		enrollmentID, req.DeviceID, component, req.Hostname, csrFingerprint)

	// Auto-approve health component enrollments (HDA has no browser for OIDC)
	if component == "health" && s.pa.CA != nil {
		certPEM, signErr := certs.SignCSR([]byte(req.CSRPEM), s.pa.CA.CertPEM, s.pa.CA.KeyPEM, 1)
		if signErr == nil {
			certSerial := ""
			if block, _ := pem.Decode(certPEM); block != nil {
				if parsedCert, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
					certSerial = parsedCert.SerialNumber.String()
				}
			}
			certFP, _ := certs.CertFingerprint(certPEM)

			enrollment.Status = "approved"
			enrollment.CertPEM = string(certPEM)
			enrollment.CertFingerprint = certFP
			enrollment.CertSerial = certSerial
			enrollment.ExpiresAt = time.Now().Add(24 * time.Hour)
			enrollment.ApprovedBy = "system (auto-approved health)"
			s.pa.Store.SaveDeviceEnrollment(enrollment)

			s.pa.Audit.LogEvent("enrollment_approved", "", "system",
				r.RemoteAddr, "", "", "Health device "+req.DeviceID+" auto-approved", true)

			log.Printf("[ENROLL] Auto-approved health enrollment: device=%s serial=%s", req.DeviceID, certSerial)

			writeJSON(w, http.StatusOK, models.EnrollmentResponse{
				ID:      enrollmentID,
				Status:  "approved",
				Message: "Health enrollment auto-approved",
			})
			return
		}
		log.Printf("[ENROLL] Failed to auto-sign health CSR: %v, falling back to pending", signErr)
	}

	writeJSON(w, http.StatusAccepted, models.EnrollmentResponse{
		ID:      enrollmentID,
		Status:  "pending",
		Message: "Enrollment request submitted, awaiting admin approval",
	})
}

func (s *Server) handleEnrollmentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Only allow lookup by enrollment ID (256-bit secret), not by predictable device_id
	enrollmentID := r.URL.Query().Get("id")
	if enrollmentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
		return
	}

	enrollment, found := s.pa.Store.GetDeviceEnrollment(enrollmentID)
	if !found {
		writeJSON(w, http.StatusNotFound, models.EnrollmentResponse{Status: "not_found", Message: "No enrollment found"})
		return
	}

	resp := models.EnrollmentResponse{
		ID:     enrollment.ID,
		Status: enrollment.Status,
	}

	if enrollment.Status == "approved" {
		resp.CertPEM = enrollment.CertPEM
		if s.pa.CA != nil {
			resp.CAPEM = string(s.pa.CA.CertPEM)
		}
		resp.Message = "Certificate issued"
	} else if enrollment.Status == "pending" {
		resp.Message = "Awaiting admin approval"
	} else if enrollment.Status == "revoked" {
		resp.Message = "Enrollment has been revoked"
	}

	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────
// OIDC-Based Auto-Enrollment (browser flow)
// ─────────────────────────────────────────────

// handleEnrollStartSession creates a pending browser enrollment session (called by connect-app).
// The connect-app opens the returned auth_url in the user's browser for OIDC login.
func (s *Server) handleEnrollStartSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Per-IP rate limiting
	clientIP := strings.SplitN(r.RemoteAddr, ":", 2)[0]
	if !s.checkEnrollRateLimit(clientIP) {
		log.Printf("[ENROLL] Rate limit exceeded for IP %s", clientIP)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again later"})
		return
	}

	var req models.EnrollmentRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.DeviceID == "" || req.CSRPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id and csr_pem are required"})
		return
	}

	// Server-side fingerprint computation
	csrFingerprint, err := computeCSRFingerprint(req.CSRPEM)
	if err != nil {
		log.Printf("[ENROLL] Invalid CSR from device %s: %v", req.DeviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
		return
	}

	component := req.Component
	if component == "" {
		component = "tunnel"
	}

	// Check for existing valid enrollment — allow re-enrollment if key changed
	if existing, found := s.pa.Store.GetDeviceEnrollmentByComponent(req.DeviceID, component); found {
		if existing.Status == "approved" && existing.ExpiresAt.After(time.Now()) {
			if existing.PublicKeyFingerprint == csrFingerprint {
				// Same key — cert is still valid, no need to re-enroll
				writeJSON(w, http.StatusConflict, map[string]string{"error": "device already has a valid certificate for this component"})
				return
			}
			// Different key (e.g. TPM key recreated) — revoke old and allow re-enrollment
			log.Printf("[ENROLL] Device %s re-enrolling with new key (old_fp=%s, new_fp=%s) — revoking old enrollment",
				req.DeviceID, existing.PublicKeyFingerprint[:16], csrFingerprint[:16])
			if existing.CertSerial != "" {
				s.pa.Store.RevokeCertSerial(existing.CertSerial, existing.DeviceID, existing.ExpiresAt)
			}
			existing.Status = "revoked"
			s.pa.Store.SaveDeviceEnrollment(existing)
		}
	}

	sessionID, err := util.GenerateID("enroll")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate session ID"})
		return
	}

	session := &models.PendingEnrollSession{
		ID:                   sessionID,
		DeviceID:             req.DeviceID,
		Component:            component,
		Hostname:             req.Hostname,
		CSRPEM:               req.CSRPEM,
		PublicKeyFingerprint: csrFingerprint,
		Status:               "pending",
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(5 * time.Minute),
	}

	s.pa.Store.SavePendingEnroll(session)

	// Build auth URL — same login page, with enroll_session parameter
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	authURL := fmt.Sprintf("%s://%s/auth/login?enroll_session=%s", scheme, r.Host, sessionID)

	log.Printf("[ENROLL] Browser enrollment session created: %s (device=%s, host=%s)", sessionID, req.DeviceID, req.Hostname)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": sessionID,
		"auth_url":   authURL,
		"expires_in": 300,
	})
}

// handleEnrollCompleteSession is called by the browser after the user logs in.
// It validates the auth token, signs the CSR, and stores the enrollment.
func (s *Server) handleEnrollCompleteSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	session, ok := s.pa.Store.GetPendingEnroll(req.SessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrollment session not found or expired"})
		return
	}

	if session.ExpiresAt.Before(time.Now()) {
		s.pa.Store.DeletePendingEnroll(req.SessionID)
		writeJSON(w, http.StatusGone, map[string]string{"error": "enrollment session expired"})
		return
	}

	// Validate the auth token
	claims, err := s.pa.IdP.ValidateToken(req.AuthToken)
	if err != nil {
		session.Status = "denied"
		s.pa.Store.SavePendingEnroll(session)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authentication token"})
		return
	}

	// Sign the CSR — identity comes from OIDC, no admin approval needed
	if s.pa.CA == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CA not initialized"})
		return
	}

	certPEM, err := certs.SignCSR([]byte(session.CSRPEM), s.pa.CA.CertPEM, s.pa.CA.KeyPEM, 1)
	if err != nil {
		log.Printf("[ENROLL] Failed to sign CSR for device %s: %v", session.DeviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
		return
	}

	// Extract serial number
	certSerial := ""
	if block, _ := pem.Decode(certPEM); block != nil {
		if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certSerial = parsedCert.SerialNumber.String()
		}
	}

	certFingerprint, _ := certs.CertFingerprint(certPEM)

	// Save enrollment record (auto-approved via OIDC)
	enrollment := &models.DeviceEnrollment{
		ID:                   session.ID,
		DeviceID:             session.DeviceID,
		Component:            session.Component,
		Hostname:             session.Hostname,
		PublicKeyFingerprint: session.PublicKeyFingerprint,
		CertFingerprint:      certFingerprint,
		CertSerial:           certSerial,
		Status:               "approved",
		CSRPEM:               session.CSRPEM,
		CertPEM:              string(certPEM),
		EnrolledAt:           time.Now(),
		ExpiresAt:            time.Now().Add(24 * time.Hour),
		ApprovedBy:           claims.Username + " (OIDC)",
		UserID:               claims.UserID,
		Username:             claims.Username,
	}
	s.pa.Store.SaveDeviceEnrollment(enrollment)

	// Record device-user binding (owner role — this user enrolled the device)
	s.pa.Store.SaveDeviceUser(&models.DeviceUser{
		DeviceID: session.DeviceID,
		UserID:   claims.UserID,
		Username: claims.Username,
		Role:     "owner",
		BoundAt:  time.Now(),
	})

	// Update pending session with cert so connect-app can poll for it
	session.Status = "authenticated"
	session.AuthToken = req.AuthToken
	session.UserID = claims.UserID
	session.Username = claims.Username
	session.CertPEM = string(certPEM)
	if s.pa.CA != nil {
		session.CAPEM = string(s.pa.CA.CertPEM)
	}
	s.pa.Store.SavePendingEnroll(session)

	s.pa.Audit.LogEvent("enrollment_approved", "", claims.Username,
		r.RemoteAddr, "", "", "Device "+session.DeviceID+" enrolled via OIDC", true)

	log.Printf("[ENROLL] Auto-approved via OIDC: device=%s user=%s serial=%s",
		session.DeviceID, claims.Username, certSerial)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device enrolled successfully",
	})
}

// handleEnrollSessionStatus returns the enrollment session status (polled by connect-app).
func (s *Server) handleEnrollSessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}

	session, ok := s.pa.Store.GetPendingEnroll(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"status":  "expired",
			"message": "Session not found or expired",
		})
		return
	}

	resp := map[string]interface{}{
		"status": session.Status,
	}

	if session.Status == "authenticated" {
		resp["cert_pem"] = session.CertPEM
		resp["ca_pem"] = session.CAPEM
		resp["message"] = "Device enrolled successfully"
	} else if session.Status == "pending" {
		resp["message"] = "Waiting for user authentication"
	} else if session.Status == "denied" {
		resp["message"] = "Authentication failed"
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminEnrollments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	enrollments := s.pa.Store.ListDeviceEnrollments()
	writeJSON(w, http.StatusOK, enrollments)
}

func (s *Server) handleAdminEnrollmentAction(w http.ResponseWriter, r *http.Request) {
	// Parse: /api/admin/enrollments/{id}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/enrollments/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected /api/admin/enrollments/{id}/{action}"})
		return
	}
	enrollmentID := parts[0]
	action := parts[1]

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	enrollment, found := s.pa.Store.GetDeviceEnrollment(enrollmentID)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrollment not found"})
		return
	}

	adminUser := r.Header.Get("X-Username")

	switch action {
	case "approve":
		if enrollment.Status != "pending" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enrollment is not pending"})
			return
		}
		if s.pa.CA == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CA not initialized"})
			return
		}

		// Sign the CSR with the internal CA — short-lived cert (24h, BeyondCorp model)
		certPEM, err := certs.SignCSR([]byte(enrollment.CSRPEM), s.pa.CA.CertPEM, s.pa.CA.KeyPEM, 1)
		if err != nil {
			log.Printf("[ENROLL] Failed to sign CSR for %s: %v", enrollmentID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
			return
		}

		// Extract serial number from signed certificate
		certSerial := ""
		if block, _ := pem.Decode(certPEM); block != nil {
			if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
				certSerial = parsedCert.SerialNumber.String()
			}
		}

		fingerprint, _ := certs.CertFingerprint(certPEM)
		enrollment.Status = "approved"
		enrollment.CertPEM = string(certPEM)
		enrollment.CertFingerprint = fingerprint
		enrollment.CertSerial = certSerial
		enrollment.ExpiresAt = time.Now().Add(24 * time.Hour)
		enrollment.ApprovedBy = adminUser
		s.pa.Store.SaveDeviceEnrollment(enrollment)

		s.pa.Audit.LogEvent("enrollment_approved", "", adminUser,
			r.RemoteAddr, "", "", "Approved device "+enrollment.DeviceID, true)

		log.Printf("[ENROLL] Approved: id=%s device=%s by=%s", enrollmentID, enrollment.DeviceID, adminUser)

		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      enrollmentID,
			Status:  "approved",
			CertPEM: string(certPEM),
			CAPEM:   string(s.pa.CA.CertPEM),
			Message: "Certificate issued",
		})

	case "revoke":
		// Save cert serial to revoked_certs for gateway cache sync
		if enrollment.CertSerial != "" {
			s.pa.Store.RevokeCertSerial(enrollment.CertSerial, enrollment.DeviceID, enrollment.ExpiresAt)
		}
		enrollment.Status = "revoked"
		s.pa.Store.SaveDeviceEnrollment(enrollment)

		s.pa.Audit.LogEvent("enrollment_revoked", "", adminUser,
			r.RemoteAddr, "", "", "Revoked device "+enrollment.DeviceID, true)

		log.Printf("[ENROLL] Revoked: id=%s device=%s by=%s", enrollmentID, enrollment.DeviceID, adminUser)

		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      enrollmentID,
			Status:  "revoked",
			Message: "Device enrollment revoked",
		})

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action: " + action + " (expected: approve, revoke)"})
	}
}

// handleCertRenewal handles POST /api/enroll/renew — device agents renew short-lived certs
func (s *Server) handleCertRenewal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req models.EnrollmentRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.DeviceID == "" || req.CSRPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id and csr_pem are required"})
		return
	}

	// Server-side fingerprint computation from CSR — ignore client-declared value
	csrFingerprint, err := computeCSRFingerprint(req.CSRPEM)
	if err != nil {
		log.Printf("[ENROLL] Invalid CSR in renewal for device %s: %v", req.DeviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
		return
	}

	enrollment, found := s.pa.Store.GetDeviceEnrollmentByDeviceID(req.DeviceID)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no enrollment found for device"})
		return
	}

	if enrollment.Status != "approved" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "enrollment is not approved (status: " + enrollment.Status + ")"})
		return
	}

	// Verify server-computed fingerprint matches enrollment — prevents key substitution
	if enrollment.PublicKeyFingerprint != csrFingerprint {
		log.Printf("[ENROLL] Renewal rejected: fingerprint mismatch for device %s (stored=%s computed=%s)",
			req.DeviceID, enrollment.PublicKeyFingerprint, csrFingerprint)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "public key fingerprint does not match enrollment"})
		return
	}

	if s.pa.CA == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CA not initialized"})
		return
	}

	// Revoke the old certificate serial (prevents replay in overlap window)
	if enrollment.CertSerial != "" {
		s.pa.Store.RevokeCertSerial(enrollment.CertSerial, enrollment.DeviceID, enrollment.ExpiresAt)
	}

	// Sign new CSR with 1-day validity
	certPEM, err := certs.SignCSR([]byte(req.CSRPEM), s.pa.CA.CertPEM, s.pa.CA.KeyPEM, 1)
	if err != nil {
		log.Printf("[ENROLL] Renewal: failed to sign CSR for device %s: %v", req.DeviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
		return
	}

	// Extract serial from new cert
	certSerial := ""
	if block, _ := pem.Decode(certPEM); block != nil {
		if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certSerial = parsedCert.SerialNumber.String()
		}
	}

	fingerprint, _ := certs.CertFingerprint(certPEM)
	enrollment.CertPEM = string(certPEM)
	enrollment.CertFingerprint = fingerprint
	enrollment.CertSerial = certSerial
	enrollment.ExpiresAt = time.Now().Add(24 * time.Hour)
	s.pa.Store.SaveDeviceEnrollment(enrollment)

	log.Printf("[ENROLL] Renewed cert for device=%s serial=%s", req.DeviceID, certSerial)

	writeJSON(w, http.StatusOK, models.EnrollmentResponse{
		ID:      enrollment.ID,
		Status:  "approved",
		CertPEM: string(certPEM),
		CAPEM:   string(s.pa.CA.CertPEM),
		Message: "Certificate renewed (24h validity)",
	})
}

// handleRevokedSerials handles GET /api/gateway/revoked-serials — gateway syncs revocation cache
func (s *Server) handleRevokedSerials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	serials := s.pa.Store.GetRevokedSerials()
	if serials == nil {
		serials = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"revoked_serials": serials,
	})
}

// ═══════════════════════════════════════════════════════════════════════
// Gateway Enrollment & Management
// ═══════════════════════════════════════════════════════════════════════

// handleGatewayEnroll handles POST /api/gateway/enroll — one-time token enrollment.
// The gateway sends a token + CSR; the cloud validates the token, signs the CSR,
// creates an OIDC client, and returns the mTLS cert + OIDC credentials.
func (s *Server) handleGatewayEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Rate limiting
	ip := strings.SplitN(r.RemoteAddr, ":", 2)[0]
	if !s.checkEnrollRateLimit(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many enrollment attempts"})
		return
	}

	var req models.GatewayEnrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Token == "" || req.CSRPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token and csr_pem are required"})
		return
	}

	// Look up gateway by enrollment token
	gw, found := s.pa.Store.GetGatewayByToken(req.Token)
	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid enrollment token"})
		return
	}

	// Check token expiry
	if gw.TokenExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, gw.TokenExpiresAt)
		if err == nil && time.Now().After(expiresAt) {
			writeJSON(w, http.StatusGone, map[string]string{"error": "enrollment token has expired"})
			return
		}
	}

	// Check gateway isn't already enrolled
	if gw.Status == "enrolled" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "gateway is already enrolled"})
		return
	}

	// Validate and sign the CSR
	csrPEM := []byte(req.CSRPEM)
	certPEM, err := certs.SignCSR(csrPEM, s.pa.CA.CertPEM, s.pa.CA.KeyPEM, 7)
	if err != nil {
		log.Printf("[GATEWAY-ENROLL] CSR signing failed for gateway %s: %v", gw.ID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
		return
	}

	// Parse cert to extract fingerprint and serial
	certBlock, _ := pem.Decode(certPEM)
	var certFingerprint, certSerial string
	if certBlock != nil {
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err == nil {
			fp := sha256.Sum256(cert.Raw)
			certFingerprint = hex.EncodeToString(fp[:])
			certSerial = cert.SerialNumber.String()
		}
	}

	// Generate OIDC client credentials for this gateway
	oidcClientID := "gw-" + gw.ID
	oidcSecretBytes := make([]byte, 32)
	if _, err := rand.Read(oidcSecretBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate OIDC credentials"})
		return
	}
	oidcClientSecret := hex.EncodeToString(oidcSecretBytes)

	// Build redirect URIs from gateway FQDN
	fqdn := req.FQDN
	if fqdn == "" {
		fqdn = gw.FQDN
	}
	redirectURIs := []string{
		fmt.Sprintf("https://%s/auth/callback", fqdn),
		"https://localhost:9443/auth/callback",
		"https://127.0.0.1:9443/auth/callback",
	}

	// Register OIDC client
	s.pa.IdP.OIDC.RegisterClient(&idp.OIDCClient{
		ClientID:     oidcClientID,
		ClientSecret: oidcClientSecret,
		RedirectURIs: redirectURIs,
		Name:         "Gateway: " + gw.Name,
	})

	// Update gateway record
	now := time.Now()
	gw.Status = "enrolled"
	gw.EnrollmentToken = "" // consume the one-time token
	gw.TokenExpiresAt = ""
	gw.CertPEM = string(certPEM)
	gw.CertFingerprint = certFingerprint
	gw.CertSerial = certSerial
	gw.CertExpiresAt = now.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	gw.OIDCClientID = oidcClientID
	gw.OIDCClientSecret = oidcClientSecret
	if fqdn != "" {
		gw.FQDN = fqdn
	}
	if req.Name != "" {
		gw.Name = req.Name
	}
	gw.UpdatedAt = now
	gw.LastSeenAt = now
	s.pa.Store.SaveGateway(gw)

	// Build OIDC URLs
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	log.Printf("[GATEWAY-ENROLL] Gateway enrolled: id=%s name=%s fqdn=%s oidc_client=%s",
		gw.ID, gw.Name, gw.FQDN, oidcClientID)

	writeJSON(w, http.StatusOK, models.GatewayEnrollResponse{
		Status:           "enrolled",
		GatewayID:        gw.ID,
		CertPEM:          string(certPEM),
		CAPEM:            string(s.pa.CA.CertPEM),
		OIDCClientID:     oidcClientID,
		OIDCClientSecret: oidcClientSecret,
		OIDCAuthURL:      baseURL + "/auth/authorize",
		OIDCTokenURL:     baseURL + "/auth/token",
		Message:          "Gateway enrolled successfully. Certificate valid for 7 days.",
	})
}

// handleGatewayRenewCert handles POST /api/gateway/renew-cert — renew mTLS certificate.
// The gateway identity is derived from the authenticated mTLS certificate (set by
// gatewayAuthMiddleware in the request context). The gateway sends a new CSR;
// the cloud validates that the CSR CN matches the authenticated gateway's FQDN,
// signs it with 7-day validity, and updates the enrollment record.
func (s *Server) handleGatewayRenewCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract authenticated gateway from middleware context
	gw, ok := gatewayFromContext(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "gateway identity not found in request context"})
		return
	}

	var req struct {
		CSRPEM string `json:"csr_pem"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.CSRPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "csr_pem is required"})
		return
	}

	// Validate that the CSR CN matches the authenticated gateway's FQDN
	csrBlock, _ := pem.Decode([]byte(req.CSRPEM))
	if csrBlock == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR PEM"})
		return
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
		return
	}
	if csr.Subject.CommonName != gw.FQDN {
		log.Printf("[GATEWAY] Cert renewal rejected: CSR CN=%q does not match gateway FQDN=%q (id=%s)", csr.Subject.CommonName, gw.FQDN, gw.ID)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "CSR CommonName does not match authenticated gateway FQDN"})
		return
	}

	// Sign the new CSR
	certPEM, err := certs.SignCSR([]byte(req.CSRPEM), s.pa.CA.CertPEM, s.pa.CA.KeyPEM, 7)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
		return
	}

	// Extract fingerprint + serial from new cert
	certBlock, _ := pem.Decode(certPEM)
	if certBlock != nil {
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err == nil {
			fp := sha256.Sum256(cert.Raw)
			gw.CertFingerprint = hex.EncodeToString(fp[:])
			gw.CertSerial = cert.SerialNumber.String()
		}
	}

	now := time.Now()
	gw.CertPEM = string(certPEM)
	gw.CertExpiresAt = now.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	gw.UpdatedAt = now
	gw.LastSeenAt = now
	s.pa.Store.SaveGateway(gw)

	log.Printf("[GATEWAY] Cert renewed for gateway %s (serial=%s)", gw.ID, gw.CertSerial)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "renewed",
		"cert_pem": string(certPEM),
		"ca_pem":   string(s.pa.CA.CertPEM),
		"message":  "Certificate renewed (7-day validity)",
	})
}

// handleGatewayResources handles GET /api/gateway/resources — resource sync.
// The gateway identity is derived from the authenticated mTLS certificate (set by
// gatewayAuthMiddleware in the request context). No query parameter needed.
func (s *Server) handleGatewayResources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Extract authenticated gateway from middleware context
	gw, ok := gatewayFromContext(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "gateway identity not found in request context"})
		return
	}

	// Update last seen
	gw.LastSeenAt = time.Now()
	s.pa.Store.SaveGateway(gw)

	// Build resource list — if gateway has assigned resources, use those; otherwise return all
	allResources := s.pa.Store.ListResources()
	var syncResources []models.GatewayResourceSync

	assignedSet := make(map[string]bool)
	for _, rid := range gw.AssignedResources {
		assignedSet[rid] = true
	}

	for _, res := range allResources {
		if !res.Enabled {
			continue
		}
		// If gateway has specific assignments, filter; otherwise include all
		if len(assignedSet) > 0 && !assignedSet[res.ID] {
			continue
		}
		syncResources = append(syncResources, models.GatewayResourceSync{
			ID:           res.ID,
			Name:         res.Name,
			Type:         res.Type,
			Host:         res.Host,
			Port:         res.Port,
			ClientID:     res.ClientID,
			ClientSecret: res.ClientSecret,
			AllowedRoles: res.AllowedRoles,
			RequireMFA:   res.RequireMFA,
			Enabled:      res.Enabled,
		})
	}

	if syncResources == nil {
		syncResources = []models.GatewayResourceSync{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"gateway_id": gw.ID,
		"resources":  syncResources,
		"count":      len(syncResources),
	})
}

// handleAdminGateways handles GET/POST /api/admin/gateways — list or create gateways.
func (s *Server) handleAdminGateways(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		gateways := s.pa.Store.ListGateways()
		if gateways == nil {
			gateways = []*models.Gateway{}
		}
		// Strip sensitive fields from list response
		type gatewayListItem struct {
			ID                string                   `json:"id"`
			Name              string                   `json:"name"`
			FQDN              string                   `json:"fqdn"`
			Status            string                   `json:"status"`
			ListenAddr        string                   `json:"listen_addr,omitempty"`
			PublicIP          string                   `json:"public_ip,omitempty"`
			OIDCClientID      string                   `json:"oidc_client_id,omitempty"`
			EnrollmentToken   string                   `json:"enrollment_token,omitempty"`
			TokenExpiresAt    string                   `json:"token_expires_at,omitempty"`
			CertExpiresAt     string                   `json:"cert_expires_at,omitempty"`
			AssignedResources []string                 `json:"assigned_resources,omitempty"`
			AuthMode          string                   `json:"auth_mode"`
			FederationConfig  *models.FederationConfig `json:"federation_config,omitempty"`
			CreatedAt         time.Time                `json:"created_at"`
			UpdatedAt         time.Time                `json:"updated_at"`
			LastSeenAt        time.Time                `json:"last_seen_at,omitempty"`
		}
		items := make([]gatewayListItem, 0, len(gateways))
		for _, gw := range gateways {
			fc := gw.FederationConfig
			if fc != nil {
				// Don't expose client_secret in list
				fc = &models.FederationConfig{
					Issuer:        fc.Issuer,
					ClientID:      fc.ClientID,
					Scopes:        fc.Scopes,
					ClaimMapping:  fc.ClaimMapping,
					AutoDiscovery: fc.AutoDiscovery,
				}
			}
			items = append(items, gatewayListItem{
				ID:                gw.ID,
				Name:              gw.Name,
				FQDN:              gw.FQDN,
				Status:            gw.Status,
				ListenAddr:        gw.ListenAddr,
				PublicIP:          gw.PublicIP,
				OIDCClientID:      gw.OIDCClientID,
				EnrollmentToken:   gw.EnrollmentToken,
				TokenExpiresAt:    gw.TokenExpiresAt,
				CertExpiresAt:     gw.CertExpiresAt,
				AssignedResources: gw.AssignedResources,
				AuthMode:          gw.AuthMode,
				FederationConfig:  fc,
				CreatedAt:         gw.CreatedAt,
				UpdatedAt:         gw.UpdatedAt,
				LastSeenAt:        gw.LastSeenAt,
			})
		}
		writeJSON(w, http.StatusOK, items)

	case http.MethodPost:
		// Create a new gateway with a one-time enrollment token
		var req struct {
			Name              string   `json:"name"`
			FQDN              string   `json:"fqdn,omitempty"`
			AssignedResources []string `json:"assigned_resources,omitempty"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
			return
		}

		// Generate gateway ID
		idBytes := make([]byte, 16)
		rand.Read(idBytes)
		gatewayID := hex.EncodeToString(idBytes)

		// Generate one-time enrollment token (32 bytes, 1-hour expiry)
		tokenBytes := make([]byte, 32)
		rand.Read(tokenBytes)
		enrollToken := hex.EncodeToString(tokenBytes)

		now := time.Now()
		gw := &models.Gateway{
			ID:                gatewayID,
			Name:              req.Name,
			FQDN:              req.FQDN,
			EnrollmentToken:   enrollToken,
			TokenExpiresAt:    now.Add(1 * time.Hour).Format(time.RFC3339),
			Status:            "pending",
			AssignedResources: req.AssignedResources,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		s.pa.Store.SaveGateway(gw)

		log.Printf("[ADMIN] Gateway created: id=%s name=%s token_expires=%s", gw.ID, gw.Name, gw.TokenExpiresAt)

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"id":               gw.ID,
			"name":             gw.Name,
			"enrollment_token": enrollToken,
			"token_expires_at": gw.TokenExpiresAt,
			"status":           gw.Status,
			"message":          "Gateway created. Use the enrollment token to register the gateway within 1 hour.",
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleAdminGatewayByID handles GET/PUT/DELETE /api/admin/gateways/{id}
func (s *Server) handleAdminGatewayByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/gateways/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "gateway ID required"})
		return
	}

	// Handle action suffixes like /api/admin/gateways/{id}/regenerate-token
	parts := strings.SplitN(id, "/", 2)
	id = parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch r.Method {
	case http.MethodGet:
		gw, found := s.pa.Store.GetGateway(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
			return
		}
		// Don't expose secrets in GET
		gw.OIDCClientSecret = ""
		gw.CertPEM = ""
		if gw.FederationConfig != nil {
			gw.FederationConfig.ClientSecret = ""
		}
		writeJSON(w, http.StatusOK, gw)

	case http.MethodPut:
		gw, found := s.pa.Store.GetGateway(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
			return
		}

		var req struct {
			Name              string                   `json:"name,omitempty"`
			FQDN              string                   `json:"fqdn,omitempty"`
			AssignedResources []string                 `json:"assigned_resources,omitempty"`
			AuthMode          string                   `json:"auth_mode,omitempty"`
			FederationConfig  *models.FederationConfig `json:"federation_config,omitempty"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		if req.Name != "" {
			gw.Name = req.Name
		}
		if req.FQDN != "" {
			gw.FQDN = req.FQDN
		}
		if req.AssignedResources != nil {
			gw.AssignedResources = req.AssignedResources
		}
		if req.AuthMode == "builtin" || req.AuthMode == "federated" {
			gw.AuthMode = req.AuthMode
			if req.AuthMode == "builtin" {
				gw.FederationConfig = nil
			}
		}
		if req.FederationConfig != nil && gw.AuthMode == "federated" {
			// Preserve existing client_secret if the incoming one is empty
			// (admin dashboard strips secrets from GET responses)
			if req.FederationConfig.ClientSecret == "" && gw.FederationConfig != nil {
				req.FederationConfig.ClientSecret = gw.FederationConfig.ClientSecret
			}
			gw.FederationConfig = req.FederationConfig
		}
		gw.UpdatedAt = time.Now()
		s.pa.Store.SaveGateway(gw)

		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		gw, found := s.pa.Store.GetGateway(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
			return
		}
		// Revoke the gateway's certificate serial before deleting
		if gw.CertSerial != "" {
			expiresAt := time.Now().Add(7 * 24 * time.Hour) // keep in revocation list for at least one cert lifetime
			s.pa.Store.RevokeCertSerial(gw.CertSerial, gw.ID, expiresAt)
			log.Printf("[ADMIN] Revoked cert serial %s for gateway %s before deletion", gw.CertSerial, id)
		}
		s.pa.Store.DeleteGateway(id)
		log.Printf("[ADMIN] Gateway deleted: id=%s", id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	case http.MethodPost:
		// POST with action suffix
		if action == "regenerate-token" {
			gw, found := s.pa.Store.GetGateway(id)
			if !found {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
				return
			}

			tokenBytes := make([]byte, 32)
			rand.Read(tokenBytes)
			gw.EnrollmentToken = hex.EncodeToString(tokenBytes)
			gw.TokenExpiresAt = time.Now().Add(1 * time.Hour).Format(time.RFC3339)
			gw.Status = "pending"
			gw.UpdatedAt = time.Now()
			s.pa.Store.SaveGateway(gw)

			log.Printf("[ADMIN] Gateway enrollment token regenerated: id=%s", id)

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"enrollment_token": gw.EnrollmentToken,
				"token_expires_at": gw.TokenExpiresAt,
				"message":          "New enrollment token generated (1-hour expiry).",
			})
		} else if action == "revoke" {
			gw, found := s.pa.Store.GetGateway(id)
			if !found {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
				return
			}
			gw.Status = "revoked"
			gw.EnrollmentToken = ""
			gw.UpdatedAt = time.Now()
			s.pa.Store.SaveGateway(gw)

			// Revoke the gateway's certificate if it has one
			if gw.CertSerial != "" {
				expiresOn := time.Now().Add(7 * 24 * time.Hour)
				s.pa.Store.RevokeCertSerial(gw.CertSerial, "gateway:"+gw.ID, expiresOn)
			}

			log.Printf("[ADMIN] Gateway revoked: id=%s name=%s", gw.ID, gw.Name)
			writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action: " + action})
		}

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}
