package transport

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"pdp/certs"
	"pdp/events"
	"pdp/idp"
	"pdp/metrics"
	"pdp/models"
	"pdp/pa"
	"pdp/pa/catalog"
	"pdp/pa/devices"
	paenrollment "pdp/pa/enrollment"
	pagateway "pdp/pa/gateway"
	paresources "pdp/pa/resources"
	"pdp/pki"
	"pdp/util"

	"github.com/go-webauthn/webauthn/webauthn"
)

// enrollRateEntry tracks per-IP enrollment rate limiting.
type enrollRateEntry struct {
	count   int
	resetAt time.Time
}

// Server is the HTTP API server for the ZTNA PDP component.
type Server struct {
	pa             *pa.PolicyAdministrator
	mux            *http.ServeMux
	addr           string
	mtlsCAPool     *x509.CertPool
	grpcHandler    http.Handler
	gatewayControl *GatewayControlRegistry

	sessionGatewayMu sync.RWMutex
	sessionGateways  map[string]string

	externalPKI   *pki.VaultClient
	externalCAPEM []byte

	enrollLimiterMu sync.Mutex
	enrollLimiter   map[string]*enrollRateEntry

	authLimiterMu sync.Mutex
	authLimiter   map[string]*enrollRateEntry // reuse: per-IP rate limit for login/register

	// Push fan-out: endpoint clients subscribe via SSE to receive
	// push-challenge notifications without polling.
	events *events.Broker

	// metrics holds the Prometheus-compatible exporter and a small set
	// of named counters/gauges populated from the request paths below.
	metrics           *metrics.Registry
	metricRevocations *metrics.Counter
	metricSSESubs     *metrics.Gauge
}

// NewServer creates a new API server.
// Gateway and device endpoints always require mTLS, so the client CA is mandatory.
func NewServer(policyAdmin *pa.PolicyAdministrator, addr, mtlsCAPath string) (*Server, error) {
	if strings.TrimSpace(mtlsCAPath) == "" {
		return nil, fmt.Errorf("strict mTLS requires mtls_ca to be configured on the PDP server")
	}

	s := &Server{
		pa:              policyAdmin,
		mux:             http.NewServeMux(),
		addr:            addr,
		gatewayControl:  NewGatewayControlRegistry(),
		sessionGateways: make(map[string]string),
		enrollLimiter:   make(map[string]*enrollRateEntry),
		authLimiter:     make(map[string]*enrollRateEntry),
		events:          events.NewBroker(64),
	}

	// Metrics exporter (S4.3). Mounted at /metrics below; intentionally
	// public — operational visibility outweighs the trivia exposed.
	s.metrics = metrics.NewRegistry()
	s.metricRevocations = s.metrics.NewCounter("ztna_pdp_revocations_total",
		"Total certificate revocations published")
	s.metricSSESubs = s.metrics.NewGauge("ztna_pdp_sse_subscribers",
		"Currently connected SSE subscribers (gateways + devices)")

	// Wire mfa.PushProvider's create-hook into the broker so that any
	// device-health app subscribed via SSE on the per-device topic
	// receives the challenge immediately. Polling clients are unaffected.
	if policyAdmin != nil && policyAdmin.IdP != nil && policyAdmin.IdP.Push != nil {
		broker := s.events
		policyAdmin.IdP.Push.OnCreate = func(ch *models.PushChallenge) {
			if ch == nil {
				return
			}
			broker.Publish("push.device:"+ch.DeviceID, events.Event{
				Type:    events.TopicPushChallenge,
				Payload: ch,
			})
		}
	}
	if policyAdmin != nil && policyAdmin.Devices != nil {
		policyAdmin.Devices.SetEventPublisher(s)
	}
	if policyAdmin != nil && policyAdmin.Resources != nil {
		policyAdmin.Resources.SetEventPublisher(s)
	}
	s.wireSessionDeleteSink()

	pool, err := loadCertPool(mtlsCAPath)
	if err != nil {
		return nil, err
	}
	s.mtlsCAPool = pool
	log.Printf("[API] mTLS client cert verification enabled (CA: %s)", mtlsCAPath)

	vaultClient, err := pki.NewVaultClient(pki.VaultConfig{
		URL:        policyAdmin.Cfg.PKIURL,
		Token:      policyAdmin.Cfg.PKIToken,
		PKIPath:    policyAdmin.Cfg.PKIPath,
		CAFile:     policyAdmin.Cfg.PKICAFile,
		ServerName: policyAdmin.Cfg.PKIServerName,
		Timeout:    policyAdmin.Cfg.PKITimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Vault PKI client: %w", err)
	}

	caPEM, err := vaultClient.GetCAPEM()
	if err != nil {
		return nil, fmt.Errorf("fetch Vault PKI CA certificate: %w", err)
	}

	s.externalPKI = vaultClient
	s.externalCAPEM = caPEM
	if policyAdmin.Enrollment != nil {
		policyAdmin.Enrollment.SetCertificateAuthority(s.signCSR, s.revokeCertificate, s.deviceRole)
		if policyAdmin.IdP != nil && policyAdmin.IdP.JWT != nil {
			policyAdmin.Enrollment.SetEnrollmentTokenIssuer(policyAdmin.IdP.JWT.GenerateEnrollmentTokenForUserSID)
		}
	}
	if policyAdmin.Gateways != nil {
		policyAdmin.Gateways.SetCertificateAuthority(s.signCSR, s.revokeCertificate)
	}
	if policyAdmin.Resources != nil {
		policyAdmin.Resources.SetCertificateAuthority(s.signCSR)
	}
	log.Printf("[API] PKI provider: vault (url=%s path=%s)", policyAdmin.Cfg.PKIURL, policyAdmin.Cfg.PKIPath)

	s.registerRoutes()
	s.initDeviceCatalogGRPC()
	s.hydrateOIDCClients()
	return s, nil
}

// hydrateOIDCClients registers the native Connect-App OIDC public client.
// Gateways are no longer OIDC clients; they act only as resource servers/PEPs.
func (s *Server) hydrateOIDCClients() {
	if s.pa == nil || s.pa.Store == nil || s.pa.IdP == nil || s.pa.IdP.OIDC == nil {
		return
	}
	s.pa.IdP.OIDC.RegisterNativeConnectAppClient()
	s.pa.IdP.OIDC.RegisterNativeAgentClient()
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
	s.mux.Handle("/metrics", s.metrics)
	s.mux.HandleFunc("/api/ca/cert", s.handleCACert)                    // Public: returns CA certificate PEM
	s.mux.HandleFunc("/api/cert-fingerprint", s.handleCertFingerprint)  // Public: returns server TLS cert SHA-256 fingerprint
	s.mux.HandleFunc("/api/enroll/token", s.handleIssueEnrollmentToken) // Device-bound, short-lived token for service EST simpleenroll

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
	s.mux.HandleFunc("/auth/authorize", s.handleOIDCAuthorize)                   // OIDC Authorization endpoint
	s.mux.HandleFunc("/auth/federated/callback", s.handleFederatedCallback)      // External IdP callback
	s.mux.HandleFunc("/auth/token", s.handleOIDCToken)                           // OIDC Token endpoint
	s.mux.HandleFunc("/auth/userinfo", s.handleOIDCUserInfo)                     // OIDC UserInfo endpoint
	s.mux.HandleFunc("/api/auth/oidc-complete", s.handleOIDCCompleteSession)     // Browser completes OIDC auth
	s.mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)                     // JWKS public key endpoint
	s.mux.HandleFunc("/.well-known/openid-configuration", s.handleOIDCDiscovery) // OIDC discovery doc

	// ─────────────────────────────────────────────
	// Device health endpoint (called directly by device-health-app)
	// The device-health-app sends health reports directly to the PDP.
	// This data is NOT sent via connect-app.
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/device/health-report", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleDirectDeviceHealthReport))))
	s.mux.Handle("/api/device/heartbeat", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleDeviceHeartbeat))))
	s.mux.Handle("/api/device/catalog", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleDeviceCatalog))))
	s.mux.Handle("/api/agent/authorize", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleAgentAuthorize))))

	// ─────────────────────────────────────────────
	// Device push MFA endpoints (called by device-health-app, mTLS required)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/device/push-challenges", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleDevicePushChallenges))))
	s.mux.Handle("/api/device/push-challenges/respond", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleDevicePushRespond))))
	s.mux.Handle("/api/device/push-events", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleDevicePushEvents))))

	// ─────────────────────────────────────────────
	// Gateway endpoints (strict mTLS + enrolled gateway identity)
	// ─────────────────────────────────────────────
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
	s.mux.Handle("/api/admin/tenants", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminTenants)))
	s.mux.Handle("/api/admin/tenants/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminTenantByID)))
	s.mux.Handle("/api/admin/rules", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminRules)))
	s.mux.Handle("/api/admin/rules/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminRuleByID)))
	s.mux.Handle("/api/admin/sessions", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSessions)))
	s.mux.Handle("/api/admin/sessions/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSessionByID)))
	s.mux.Handle("/api/admin/audit", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAudit)))

	// ─────────────────────────────────────────────
	// Device enrollment endpoints
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/api/enroll", s.handleDeviceEnroll)                                                                 // Device submits CSR (no auth — bootstrapping)
	s.mux.HandleFunc("/api/enroll/status", s.handleEnrollmentStatus)                                                      // Device polls enrollment status
	s.mux.Handle("/api/enroll/renew", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleCertRenewal)))) // Device renews short-lived cert (mTLS identity)
	s.mux.HandleFunc("/api/enroll/start-session", s.handleEnrollStartSession)                                             // Device starts browser-based enrollment
	s.mux.HandleFunc("/api/enroll/complete-session", s.handleEnrollCompleteSession)                                       // Browser completes enrollment after OIDC login
	s.mux.HandleFunc("/api/enroll/session-status", s.handleEnrollSessionStatus)                                           // Device polls enrollment session status
	s.mux.HandleFunc("/.well-known/est/ztna/cacerts", s.handleESTCACerts)                                                 // EST CA bundle discovery
	s.mux.HandleFunc("/.well-known/est/ztna/simpleenroll", s.handleESTSimpleEnroll)                                       // EST-style authenticated endpoint enrollment
	s.mux.Handle("/api/admin/enrollments", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminEnrollments)))             // List enrollments
	s.mux.Handle("/api/admin/enrollments/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminEnrollmentAction)))       // Approve/revoke

	// ─────────────────────────────────────────────
	// PDP Admin endpoints (resources, dashboard)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/admin/resources", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminResources)))
	s.mux.Handle("/api/admin/resources/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminResourceByID)))
	s.mux.Handle("/api/admin/device-health", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDeviceHealth)))
	s.mux.Handle("/api/admin/device-health/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDeviceHealthByID)))
	s.mux.Handle("/api/admin/device-posture", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDevicePosture)))
	s.mux.Handle("/api/admin/device-posture/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDevicePostureByID)))
	s.mux.Handle("/api/admin/resources-generate-cert", s.adminAuthMiddleware(http.HandlerFunc(s.handleGenerateCert)))
	s.mux.Handle("/api/admin/resources-regenerate-secret/", s.adminAuthMiddleware(http.HandlerFunc(s.handleRegenerateSecret)))
	s.mux.Handle("/api/admin/dashboard", s.adminAuthMiddleware(http.HandlerFunc(s.handleDashboardStats)))

	// ─────────────────────────────────────────────
	// Gateway enrollment & lifecycle endpoints
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/api/gateway/enroll", s.handleGatewayEnroll)                                                                    // One-time token enrollment (no auth)
	s.mux.Handle("/api/gateway/renew-cert", s.requireClientCert(s.gatewayAuthMiddleware(http.HandlerFunc(s.handleGatewayRenewCert)))) // Cert renewal (mTLS identity)

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
	httpHandler := loggingMiddleware(securityHeadersMiddleware(corsMiddleware(s.pa.Cfg.CORSOrigins)(s.mux)))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.grpcHandler != nil && isGRPCRequest(r) {
			s.grpcHandler.ServeHTTP(w, r)
			return
		}
		httpHandler.ServeHTTP(w, r)
	})
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

// handleCACert returns the active issuer CA certificate (public info, no auth needed).
// Gateways use this to validate certificates issued via the PDP signer path.
func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	caPEM, err := s.getCAPEM()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CA not initialized"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(caPEM)
}

// handleCertFingerprint returns the SHA-256 fingerprint of the PDP server's TLS certificate.
// Operators can use this value to configure pdp_cert_sha256 in gateway/connect/health configs.
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

	// Check Vault issuer CA loaded
	if len(s.externalCAPEM) > 0 {
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
		"service": "ztna-pdp",
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

// handleOIDCDiscovery serves the OpenID Connect Discovery 1.0 metadata document
// at /.well-known/openid-configuration. Allows OIDC clients (including our own
// gateway) to autodetect the authorization, token, userinfo and JWKS endpoints
// from the issuer URL alone, instead of hardcoding them.
func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	base := externalBaseURL(r)
	doc := map[string]interface{}{
		"issuer":                                base,
		"authorization_endpoint":                base + "/auth/authorize",
		"token_endpoint":                        base + "/auth/token",
		"userinfo_endpoint":                     base + "/auth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nbf", "jti", "user_id", "username", "role", "device_id", "mfa_done", "acr", "amr", "nonce"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// externalBaseURL returns the externally-visible base URL for this request,
// honouring X-Forwarded-Proto / X-Forwarded-Host when present (reverse proxy).
func externalBaseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	return scheme + "://" + host
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

	enrollment, ok := deviceEnrollmentFromContext(r)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing client certificate identity"})
		return
	}

	challenges := s.pa.IdP.Push.GetPendingForDevice(enrollment.DeviceID)
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

	enrollment, ok := deviceEnrollmentFromContext(r)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
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
	if ch.DeviceID != enrollment.DeviceID {
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

// handleDirectDeviceHealthReport handles health reports sent directly by the
// device-health-app. Requires a valid client certificate (mTLS). The device_id
// in the report body must match the certificate's CN to prevent spoofing.
//
// Flow: device-health-app → POST /api/device/health-report → PDP stores health
func (s *Server) handleDirectDeviceHealthReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	enrollment, ok := deviceEnrollmentFromContext(r)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing client certificate identity"})
		return
	}
	certCN := enrollment.DeviceID

	var report models.DeviceHealthReport
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&report); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if s == nil || s.pa == nil || s.pa.Devices == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": devices.ErrServiceUnavailable.Error()})
		return
	}
	if _, err := s.pa.Devices.AcceptHealthReport(certCN, report); err != nil {
		writeJSON(w, statusCodeForDeviceTelemetryError(err), map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Device health report received",
	})
}

func statusCodeForDeviceTelemetryError(err error) int {
	switch {
	case errors.Is(err, devices.ErrDeviceIDRequired):
		return http.StatusBadRequest
	case errors.Is(err, devices.ErrDeviceIDMismatch):
		return http.StatusForbidden
	case errors.Is(err, devices.ErrNoPriorHealthReport):
		return http.StatusPreconditionRequired
	case errors.Is(err, devices.ErrNoPriorPosture):
		return http.StatusPreconditionFailed
	case errors.Is(err, devices.ErrServiceUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// handleDeviceHeartbeat is a lightweight liveness ping from the
// device-health-app, intended to be sent every minute. It only updates
// the reported_at timestamp on the existing health record so the policy
// engine's posture-staleness check (see pe/risk) can distinguish
// "device is online and posture has not changed" from "device fell off
// the network 30 minutes ago and may now be compromised".
//
// We deliberately do NOT accept any payload body — heartbeats must be
// cheap. A full health report (POST /api/device/health-report) is sent
// less frequently (only on status change or every ~5 minutes).
func (s *Server) handleDeviceHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	enrollment, ok := deviceEnrollmentFromContext(r)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing client certificate identity"})
		return
	}

	if s == nil || s.pa == nil || s.pa.Devices == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": devices.ErrServiceUnavailable.Error()})
		return
	}
	if _, err := s.pa.Devices.TouchHealthHeartbeat(enrollment.DeviceID); err != nil {
		message := err.Error()
		if errors.Is(err, devices.ErrNoPriorHealthReport) {
			message = "no prior health report on file; submit POST /api/device/health-report first"
		}
		writeJSON(w, statusCodeForDeviceTelemetryError(err), map[string]string{"error": message})
		return
	}
	writeJSON(w, http.StatusOK, models.APIResponse{Success: true})
}

type deviceCatalogRequest struct {
	CurrentVersion string `json:"current_version,omitempty"`
}

func (s *Server) handleDeviceCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	enrollment, ok := deviceEnrollmentFromContext(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device identity not found in request context"})
		return
	}

	claims, statusCode, err := s.authenticateDeviceCatalogUser(r, enrollment.DeviceID)
	if err != nil {
		writeJSON(w, statusCode, map[string]string{"error": err.Error()})
		return
	}

	var req deviceCatalogRequest
	if r.Body != nil {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
	}

	snapshot := s.deviceCatalogSnapshot(claims)
	if strings.TrimSpace(req.CurrentVersion) == snapshot.Version {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) authenticateDeviceCatalogUser(r *http.Request, deviceID string) (*idp.CustomClaims, int, error) {
	token, err := bearerToken(r)
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("authorization bearer token required")
	}
	return s.validateDeviceCatalogToken(token, deviceID)
}

func (s *Server) validateDeviceCatalogToken(token, deviceID string) (*idp.CustomClaims, int, error) {
	if s == nil || s.pa == nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("identity services are not available")
	}
	claims, err := s.pa.ValidateDeviceUserToken(token, deviceID)
	if err != nil {
		return nil, httpStatusForAccessError(err), err
	}
	return claims, 0, nil
}

func (s *Server) deviceCatalogSnapshot(claims *idp.CustomClaims) catalog.Snapshot {
	if claims == nil || s == nil || s.pa == nil || s.pa.Catalog == nil {
		return catalog.EmptySnapshot()
	}
	return s.pa.Catalog.BuildForRole(claims.Role)
}

// handleDevicePushEvents is the device-side equivalent of
// a long-lived SSE stream that delivers push MFA challenges for the calling
// device (identified by mTLS CN) the moment they are created. Replaces
// 3-second polling with sub-second push.
//
// Authn: mTLS client cert; the device subscribes only to its own topic
// (push.device:<deviceID>) so other devices' challenges never fan out
// to it even with a single shared broker.
func (s *Server) handleDevicePushEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	enrollment, ok := deviceEnrollmentFromContext(r)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		http.Error(w, "missing client certificate identity", http.StatusForbidden)
		return
	}
	deviceID := enrollment.DeviceID

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sub := s.events.Subscribe("push.device:" + deviceID)
	defer s.events.Unsubscribe(sub)
	if s.metricSSESubs != nil {
		s.metricSSESubs.Inc()
		defer s.metricSSESubs.Dec()
	}

	if _, err := io.WriteString(w, ": connected\n\n"); err != nil {
		return
	}
	flusher.Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": hb\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case evt, ok := <-sub.C:
			if !ok {
				return
			}
			data, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
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

func (s *Server) handleAdminTenants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tenants := s.pa.Store.ListTenants()
		writeJSON(w, http.StatusOK, models.APIResponse{
			Success: true,
			Data:    tenants,
		})

	case http.MethodPost:
		var tenant models.Tenant
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&tenant); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if tenant.ID == "" {
			tenant.ID, _ = util.GenerateID("tenant")
		}
		tenant.CreatedAt = time.Now()
		tenant.UpdatedAt = time.Now()
		s.pa.Store.SaveTenant(&tenant)
		writeJSON(w, http.StatusCreated, models.APIResponse{
			Success: true,
			Message: "Tenant created",
			Data:    tenant,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminTenantByID(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimPrefix(r.URL.Path, "/api/admin/tenants/")
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant ID required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		tenant, found := s.pa.Store.GetTenant(tenantID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: tenant})

	case http.MethodPut:
		var tenant models.Tenant
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&tenant); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		tenant.ID = tenantID
		tenant.UpdatedAt = time.Now()
		s.pa.Store.SaveTenant(&tenant)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Tenant updated", Data: tenant})

	case http.MethodDelete:
		if !s.pa.Store.DeleteTenant(tenantID) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Tenant deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
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
		s.publishCAEPEvent(events.TopicPolicyUpdated, map[string]string{
			"policy_id": rule.ID,
			"action":    "created",
			"reason":    "policy_rule_created",
		})
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
		s.publishCAEPEvent(events.TopicPolicyUpdated, map[string]string{
			"policy_id": rule.ID,
			"action":    "updated",
			"reason":    "policy_rule_updated",
		})
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Rule updated", Data: rule})

	case http.MethodDelete:
		if err := s.pa.Rules.DeleteRule(ruleID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
			return
		}
		s.publishCAEPEvent(events.TopicPolicyUpdated, map[string]string{
			"policy_id": ruleID,
			"action":    "deleted",
			"reason":    "policy_rule_deleted",
		})
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

func (s *Server) caepPayload(eventType string, fields map[string]string) map[string]string {
	now := time.Now().UTC()
	eventID, err := util.GenerateID("caep")
	if err != nil {
		eventID = fmt.Sprintf("caep_%d", now.UnixNano())
	}
	payload := map[string]string{
		"event_id":   eventID,
		"event_type": eventType,
		"changed_at": now.Format(time.RFC3339Nano),
	}
	for key, value := range fields {
		if strings.TrimSpace(value) != "" {
			payload[key] = value
		}
	}
	return payload
}

func (s *Server) publishCAEPEvent(eventType string, fields map[string]string) {
	if s == nil || s.events == nil {
		return
	}
	now := time.Now().UTC()
	s.events.Publish(eventType, events.Event{
		Type:    eventType,
		Time:    now,
		Payload: s.caepPayload(eventType, fields),
	})
}

func (s *Server) PublishCAEPEvent(eventType string, fields map[string]string) {
	s.publishCAEPEvent(eventType, fields)
}

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

func (s *Server) getCAPEM() ([]byte, error) {
	if len(s.externalCAPEM) > 0 {
		return s.externalCAPEM, nil
	}
	return nil, fmt.Errorf("CA not initialized")
}

func (s *Server) signerReady() bool {
	return s.externalPKI != nil
}

func normalizeEnrollmentComponent(component string) string {
	return paenrollment.NormalizeComponent(component)
}

func (s *Server) deviceRole(_ string) string {
	return s.pa.Cfg.PKIRoleDevice
}

func (s *Server) signCSR(csrPEM []byte, validDays int, vaultRole string) ([]byte, error) {
	if s.externalPKI != nil {
		ttl := fmt.Sprintf("%dh", validDays*24)
		return s.externalPKI.SignCSR(csrPEM, vaultRole, ttl)
	}
	return nil, fmt.Errorf("PKI signer not initialized")
}

func (s *Server) revokeCertificate(serial, certPEM, subjectID string, expiresOn time.Time) {
	if strings.TrimSpace(serial) == "" && strings.TrimSpace(certPEM) == "" {
		return
	}

	if s.externalPKI != nil {
		if err := s.externalPKI.RevokeCertificate(serial, []byte(certPEM)); err != nil {
			log.Printf("[PKI] Failed to revoke certificate in Vault (subject=%s serial=%s): %v", subjectID, serial, err)
		}
	}

	if strings.TrimSpace(serial) != "" {
		s.pa.Store.RevokeCertSerial(serial, subjectID, expiresOn)
		s.publishCAEPEvent(events.TopicRevocation, map[string]string{
			"cert_serial": serial,
			"serial":      serial,
			"subject":     subjectID,
			"reason":      "certificate_revoked",
		})
		if s.metricRevocations != nil {
			s.metricRevocations.Inc()
		}
	}
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
	decision := s.pa.EvaluateAccess(accessReq)

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

func writeResourceAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, paresources.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": resourceClientMessage(err)})
	case errors.Is(err, paresources.ErrResourceNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
	case errors.Is(err, paresources.ErrCredentialIssue):
		log.Printf("[PDP] Resource credential generation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate credentials"})
	case errors.Is(err, paresources.ErrCertificateIssue):
		log.Printf("[PDP] Resource certificate generation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate certificate"})
	default:
		log.Printf("[PDP] Resource operation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to manage resource"})
	}
}

func resourceClientMessage(err error) string {
	message := err.Error()
	for _, prefix := range []string{paresources.ErrInvalidRequest.Error()} {
		if strings.HasPrefix(message, prefix+": ") {
			return strings.TrimPrefix(message, prefix+": ")
		}
	}
	return message
}

func (s *Server) handleAdminResources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resources, err := s.pa.Resources.ListResources()
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resources)

	case http.MethodPost:
		var res models.Resource
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&res); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		created, err := s.pa.Resources.CreateResource(res)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}

		log.Printf("[PDP] Resource created: %s (%s) type=%s host=%s", created.ID, created.Name, created.Type, created.Host)

		writeJSON(w, http.StatusCreated, created)

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
		res, err := s.pa.Resources.GetResource(id)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res)

	case http.MethodPut:
		// Decode into a map to detect which fields were actually sent (PATCH semantics)
		var fields map[string]json.RawMessage
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&fields); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		updated, err := s.pa.Resources.UpdateResource(id, fields)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		log.Printf("[PDP] Resource updated: %s (%s)", updated.ID, updated.Name)
		writeJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		if err := s.pa.Resources.DeleteResource(id); err != nil {
			writeResourceAdminError(w, err)
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

	res, err := s.pa.Resources.RegenerateSecret(id)
	if err != nil {
		if errors.Is(err, paresources.ErrCredentialIssue) {
			log.Printf("[PDP] Resource secret generation failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate secret"})
			return
		}
		writeResourceAdminError(w, err)
		return
	}

	log.Printf("[PDP] Secret regenerated for resource: %s (%s)", res.ID, res.Name)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"client_id":     res.ClientID,
		"client_secret": res.ClientSecret,
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

func (s *Server) handleAdminDevicePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	reports := s.pa.Store.ListDevicePosture()
	if reports == nil {
		reports = []*models.DevicePostureReport{}
	}
	sort.SliceStable(reports, func(i, j int) bool {
		return reports[i].ReportedAt.After(reports[j].ReportedAt)
	})

	writeJSON(w, http.StatusOK, reports)
}

func (s *Server) handleAdminDevicePostureByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	deviceID := strings.TrimPrefix(r.URL.Path, "/api/admin/device-posture/")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device ID required"})
		return
	}

	report, ok := s.pa.Store.GetDevicePosture(deviceID)
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

	var req paresources.GenerateCertificateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	result, err := s.pa.Resources.GenerateCertificate(req)
	if err != nil {
		writeResourceAdminError(w, err)
		return
	}

	log.Printf("[PDP] Certificate generated for resource %s (domain=%s, days=%d)", result.Resource.ID, result.Resource.CertDomain, req.ValidDays)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Certificate generated",
		"cert_info": result.CertInfo,
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
	// Serve from pdp/pa/dashboard/dist/ during development or /app/dashboard/dist in containers.
	distDir := findDashboardDir()
	if distDir == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "dashboard not built - run: cd pdp/pa/dashboard && npm run build"})
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
		"pdp/pa/dashboard/dist",
		"pa/dashboard/dist",
		"../pdp/pa/dashboard/dist",
		"pdp/dashboard/dist",
		"dashboard/dist",
		"../pdp/dashboard/dist",
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
	deviceID := r.URL.Query().Get("device_id")
	hostname := r.URL.Query().Get("hostname")
	acrValues := r.URL.Query().Get("acr_values")

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

	if client.Public || client.RequirePKCE {
		if codeChallenge == "" || codeChallengeMethod != "S256" {
			http.Error(w, "PKCE S256 is required for this client", http.StatusBadRequest)
			return
		}
	}
	if idp.IsNativeEndpointClientID(client.ClientID) && strings.TrimSpace(deviceID) == "" {
		http.Error(w, "device_id is required for endpoint authorization", http.StatusBadRequest)
		return
	}

	// Create an OIDC authorize session
	oidcSession, err := s.pa.IdP.OIDC.CreateAuthorizeSession(clientID, redirectURI, state, scope, codeChallenge, codeChallengeMethod, nonce, deviceID, hostname, acrValues)
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
	if strings.Contains(acrValues, "loa:2") || strings.Contains(acrValues, "mfa") {
		loginURL += "&mfa_step=true"
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// federatedCallbackURL returns the PDP's federated callback URL based on request host.
func (s *Server) federatedCallbackURL() string {
	host := s.pa.Cfg.WebAuthnRPID
	if host == "" {
		host = "localhost" + s.pa.Cfg.ListenAddr
	}
	return fmt.Sprintf("https://%s/auth/federated/callback", host)
}

// handleFederatedCallback receives the authorization code from the external IdP
// after the user authenticates there. It exchanges the code, maps claims,
// provisions the user, issues a PDP JWT, and completes the OIDC session.
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

	oidcSess, ok := s.pa.IdP.OIDC.GetAuthorizeSession(fedSession.OIDCSessionID)
	deviceID := ""
	if ok {
		deviceID = oidcSess.DeviceID
	}

	// Issue PDP JWT with MFADone=false (MFA step-up handled at access time)
	// and bind it to the device asserted by the Connect-App OIDC request.
	authToken, err := s.pa.IdP.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, deviceID, fedSession.Nonce, false)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	// Complete the OIDC authorize session → generate authorization code
	authCode, err := s.pa.IdP.OIDC.CompleteAuthorizeSession(
		fedSession.OIDCSessionID, authToken,
		user.ID, user.Username, user.Role, false,
	)
	if err != nil {
		log.Printf("[FEDERATION] OIDC session completion failed: %v", err)
		http.Error(w, "OIDC session completion failed", http.StatusInternalServerError)
		return
	}

	// Build redirect URL back to the Gateway callback
	redirectURL := authCode.RedirectURI + "?code=" + url.QueryEscape(authCode.Code)
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

	oidcSess, ok := s.pa.IdP.OIDC.GetAuthorizeSession(req.OIDCSession)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "OIDC session not found or expired"})
		return
	}

	// Bind the browser-authenticated user token to the device identity carried
	// by the native Connect-App authorize request. This prevents a token minted
	// in an unbound browser-only flow from being replayed through the gateway.
	boundToken, err := s.pa.IdP.JWT.GenerateAuthToken(
		claims.UserID, claims.Username, role,
		oidcSess.DeviceID, oidcSess.Nonce, claims.MFADone,
	)
	if err != nil {
		log.Printf("[OIDC] Failed to issue device-bound token: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
		return
	}

	// Generate authorization code and complete the OIDC session
	authCode, err := s.pa.IdP.OIDC.CompleteAuthorizeSession(
		req.OIDCSession, boundToken,
		claims.UserID, claims.Username, role, claims.MFADone,
	)
	if err != nil {
		log.Printf("[OIDC] Complete session failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "OIDC session completion failed"})
		return
	}

	// Build redirect URL back to the Gateway callback
	redirectURL := authCode.RedirectURI + "?code=" + url.QueryEscape(authCode.Code)
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

		// Issue a new JWT for this user, preserving device binding and MFA state.
		token, err := s.pa.IdP.JWT.GenerateAuthToken(newRT.UserID, newRT.Username, newRT.Role, newRT.DeviceID, "", newRT.MFADone)
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
			"device_id":     newRT.DeviceID,
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
			authCode.UserID, authCode.Username, authCode.Role, authCode.DeviceID, authCode.Nonce, mfaDone,
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
		"device_id":     authCode.DeviceID,
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

// canonicalCSRPEM accepts PEM, DER, or base64 DER CSR input and returns a
// normalized PEM CSR after verifying its signature.
func canonicalCSRPEM(input string) (string, error) {
	return paenrollment.CanonicalCSRPEM(input)
}

func parseCSR(input string) (*x509.CertificateRequest, []byte, error) {
	return paenrollment.ParseCSR(input)
}

// computeCSRFingerprint extracts the public key from a CSR and returns its SHA-256 hex fingerprint.
// This prevents clients from spoofing the fingerprint field.
func computeCSRFingerprint(csrPEM string) (string, error) {
	return paenrollment.ComputeCSRFingerprint(csrPEM)
}

func shortFingerprint(value string) string {
	return paenrollment.ShortFingerprint(value)
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

	result, err := s.pa.Enrollment.SubmitPendingDeviceEnrollment(req)
	if err != nil {
		s.writePendingEnrollmentError(w, req.DeviceID, err)
		return
	}

	switch result.Action {
	case paenrollment.PendingEnrollmentAlreadyPending:
		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      result.Enrollment.ID,
			Status:  "pending",
			Message: "Enrollment request already pending admin approval",
		})
	case paenrollment.PendingEnrollmentAlreadyApproved:
		writeJSON(w, http.StatusConflict, models.EnrollmentResponse{
			ID:      result.Enrollment.ID,
			Status:  "approved",
			Message: "Device already has a valid certificate for this component",
		})
	default:
		writeJSON(w, http.StatusAccepted, models.EnrollmentResponse{
			ID:      result.Enrollment.ID,
			Status:  "pending",
			Message: "Enrollment request submitted, awaiting admin approval",
		})
	}
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

	resp, err := s.pa.Enrollment.DeviceEnrollmentStatus(enrollmentID)
	if err != nil {
		if errors.Is(err, paenrollment.ErrInvalidRequest) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
			return
		}
		if !errors.Is(err, paenrollment.ErrNotFound) {
			log.Printf("[ENROLL] Failed to load enrollment status for %s: %v", enrollmentID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load enrollment status"})
			return
		}
		writeJSON(w, http.StatusNotFound, models.EnrollmentResponse{Status: "not_found", Message: "No enrollment found"})
		return
	}

	if resp.Status == "approved" {
		if caPEM, err := s.getCAPEM(); err == nil {
			resp.CAPEM = string(caPEM)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) writePendingEnrollmentError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		log.Printf("[ENROLL] Invalid CSR from device %s: %v", deviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, paenrollment.ErrPendingDifferentKey):
		writeJSON(w, http.StatusForbidden, models.EnrollmentResponse{
			Status:  "rejected",
			Message: "Enrollment already pending with a different device key",
		})
	default:
		log.Printf("[ENROLL] Failed to create pending enrollment for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create enrollment request"})
	}
}

func (s *Server) writeBrowserEnrollmentStartError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		log.Printf("[ENROLL] Invalid CSR from device %s: %v", deviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, paenrollment.ErrAlreadyEnrolled):
		writeJSON(w, http.StatusConflict, map[string]string{"error": paenrollment.ErrAlreadyEnrolled.Error()})
	default:
		log.Printf("[ENROLL] Failed to start browser enrollment for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate session ID"})
	}
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

	session, err := s.pa.Enrollment.StartBrowserEnrollSession(req)
	if err != nil {
		s.writeBrowserEnrollmentStartError(w, req.DeviceID, err)
		return
	}

	// Build auth URL — same login page, with enroll_session parameter
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	authURL := fmt.Sprintf("%s://%s/auth/login?enroll_session=%s", scheme, r.Host, session.ID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": session.ID,
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

	if _, err := s.pa.Enrollment.ActiveBrowserEnrollSession(req.SessionID); err != nil {
		writeEnrollSessionLifecycleError(w, err)
		return
	}

	// Validate the auth token. Enrollment binds device identity to a logged-in
	// user, while resource-access MFA remains enforced later by policy.
	claims, err := s.pa.IdP.ParseToken(req.AuthToken)
	if err != nil {
		if _, denyErr := s.pa.Enrollment.DenyBrowserEnrollSession(req.SessionID); denyErr != nil {
			log.Printf("[ENROLL] Failed to mark browser enrollment session denied: session=%s err=%v", req.SessionID, denyErr)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authentication token"})
		return
	}

	var caPEM string
	if loadedCAPEM, err := s.getCAPEM(); err == nil {
		caPEM = string(loadedCAPEM)
	}

	completion, err := s.pa.Enrollment.CompleteBrowserEnrollSession(req.SessionID, req.AuthToken, claims.UserID, claims.Username, caPEM)
	if err != nil {
		if errors.Is(err, paenrollment.ErrNotFound) || errors.Is(err, paenrollment.ErrExpiredSession) || errors.Is(err, paenrollment.ErrInvalidRequest) {
			writeEnrollSessionLifecycleError(w, err)
			return
		}
		log.Printf("[ENROLL] Failed to complete browser enrollment session %s: %v", req.SessionID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
		return
	}

	s.pa.Audit.LogEvent("enrollment_approved", "", claims.Username,
		r.RemoteAddr, "", "", "Device "+completion.Session.DeviceID+" enrolled via OIDC", true)

	log.Printf("[ENROLL] Endpoint certificate ready via OIDC: device=%s user=%s serial=%s reused=%v",
		completion.Session.DeviceID, claims.Username, completion.Enrollment.CertSerial, completion.Reused)

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

	status, err := s.pa.Enrollment.BrowserEnrollSessionStatus(sessionID)
	if err != nil {
		if errors.Is(err, paenrollment.ErrInvalidRequest) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
			return
		}
		if !errors.Is(err, paenrollment.ErrNotFound) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load enrollment session"})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"status":  "expired",
			"message": "Session not found or expired",
		})
		return
	}

	resp := map[string]interface{}{
		"status": status.Status,
	}

	if status.Status == "authenticated" {
		resp["cert_pem"] = status.CertPEM
		resp["ca_pem"] = status.CAPEM
	}
	if status.Message != "" {
		resp["message"] = status.Message
	}

	writeJSON(w, http.StatusOK, resp)
}

func writeEnrollSessionLifecycleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrExpiredSession):
		writeJSON(w, http.StatusGone, map[string]string{"error": "enrollment session expired"})
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
	case errors.Is(err, paenrollment.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrollment session not found or expired"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load enrollment session"})
	}
}

// handleESTCACerts exposes the issuing CA bundle through the standard EST
// discovery path used by endpoint agents before certificate enrollment.
func (s *Server) handleESTCACerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	caPEM, err := s.getCAPEM()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "CA certificate is not available"})
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(caPEM)
}

// handleESTSimpleEnroll performs authenticated EST-style enrollment. It accepts
// a CSR as JSON (csr_pem) or raw PEM/DER/base64 DER and returns the endpoint
// certificate plus CA chain. Authentication is a Cloud JWT bearer token from the
// browser/OIDC login flow; MFA remains conditional at resource access time.
func (s *Server) handleESTSimpleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	claims, err := s.estBearerClaims(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid bearer token"})
		return
	}

	req, err := readESTEnrollmentRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var tokenExpiresAt time.Time
	if claims.ExpiresAt != nil {
		tokenExpiresAt = claims.ExpiresAt.Time
	}
	result, err := s.pa.Enrollment.CompleteESTEnrollment(req, paenrollment.ESTEnrollmentIdentity{
		DeviceID:       claims.DeviceID,
		UserID:         claims.UserID,
		Username:       claims.Username,
		TokenID:        claims.ID,
		TokenExpiresAt: tokenExpiresAt,
	})
	if err != nil {
		s.writeESTEnrollmentError(w, req.DeviceID, err)
		return
	}
	caPEM, err := s.getCAPEM()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "CA certificate is not available"})
		return
	}

	s.pa.Audit.LogEvent("est_enrollment", claims.UserID, claims.Username,
		r.RemoteAddr, "", "", "Endpoint "+result.Enrollment.DeviceID+" enrolled via EST", true)
	log.Printf("[EST] Endpoint certificate ready: device=%s user=%s serial=%s reused=%v",
		result.Enrollment.DeviceID, claims.Username, result.Enrollment.CertSerial, result.Reused)

	writeESTCertificateResponse(w, r, result.Enrollment.ID, result.CertPEM, caPEM, result.Reused)
}

func (s *Server) estBearerClaims(r *http.Request) (*idp.CustomClaims, error) {
	token, err := bearerToken(r)
	if err != nil {
		return nil, err
	}
	claims, err := s.pa.IdP.JWT.ParseEnrollmentToken(token)
	if err != nil {
		return nil, err
	}
	if claims.Nonce != "" && r.Header.Get("X-ZTNA-Enrollment-Nonce") != claims.Nonce {
		return nil, fmt.Errorf("enrollment nonce mismatch")
	}
	return claims, nil
}

func bearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("bearer token required")
	}
	return strings.TrimSpace(parts[1]), nil
}

func validateCSREmailIdentity(csr *x509.CertificateRequest, username string) error {
	return paenrollment.ValidateCSREmailIdentity(csr, username)
}

func (s *Server) writeESTEnrollmentError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidToken), errors.Is(err, paenrollment.ErrTokenAlreadyUsed):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		message := enrollmentClientMessage(err)
		if strings.Contains(message, "CSR common name") || strings.Contains(message, "CSR email") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": message})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	default:
		log.Printf("[EST] Failed to issue endpoint certificate for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
	}
}

func (s *Server) handleIssueEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	token, err := bearerToken(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization header required"})
		return
	}
	claims, err := s.pa.IdP.JWT.ParseAuthTokenForAudience(token, "ztna-gateway")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid parent token"})
		return
	}

	var body struct {
		DeviceID string `json:"device_id"`
		Nonce    string `json:"nonce"`
		UserSID  string `json:"user_sid"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	issuedToken, err := s.pa.Enrollment.IssueEnrollmentToken(paenrollment.EnrollmentTokenParent{
		TokenID:  claims.ID,
		Purpose:  claims.Purpose,
		UserID:   claims.UserID,
		Username: claims.Username,
		Role:     claims.Role,
		DeviceID: claims.DeviceID,
	}, paenrollment.EnrollmentTokenIssueRequest{
		DeviceID: body.DeviceID,
		Nonce:    body.Nonce,
		UserSID:  body.UserSID,
	})
	if err != nil {
		s.writeEnrollmentTokenIssueError(w, err)
		return
	}

	response := map[string]interface{}{
		"enrollment_token": issuedToken.EnrollmentToken,
		"token_type":       issuedToken.TokenType,
		"expires_in":       issuedToken.ExpiresIn,
		"device_id":        issuedToken.DeviceID,
		"nonce":            issuedToken.Nonce,
	}
	if issuedToken.UserSID != "" {
		response["user_sid"] = issuedToken.UserSID
	}
	if issuedToken.UserEmail != "" {
		response["user_email"] = issuedToken.UserEmail
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) writeEnrollmentTokenIssueError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidParentToken):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid parent token"})
	case errors.Is(err, paenrollment.ErrTokenRevoked):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token has been revoked"})
	case errors.Is(err, paenrollment.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrNonceGeneration):
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate nonce"})
	case errors.Is(err, paenrollment.ErrTokenIssue):
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate enrollment token"})
	default:
		log.Printf("[ENROLL] Failed to issue enrollment token: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate enrollment token"})
	}
}

func readESTEnrollmentRequest(r *http.Request) (models.EnrollmentRequest, error) {
	var req models.EnrollmentRequest
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			return req, fmt.Errorf("invalid JSON request body")
		}
	} else {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return req, fmt.Errorf("read CSR body: %w", err)
		}
		req.CSRPEM = string(body)
		req.DeviceID = strings.TrimSpace(r.Header.Get("X-Device-ID"))
		req.Hostname = strings.TrimSpace(r.Header.Get("X-Hostname"))
		req.Component = strings.TrimSpace(r.Header.Get("X-ZTNA-Component"))
	}
	req.Component = normalizeEnrollmentComponent(req.Component)
	if strings.TrimSpace(req.CSRPEM) == "" {
		return req, fmt.Errorf("csr_pem is required")
	}
	return req, nil
}

func writeESTCertificateResponse(w http.ResponseWriter, r *http.Request, id string, certPEM, caPEM []byte, reused bool) {
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") {
		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      id,
			Status:  "approved",
			CertPEM: string(certPEM),
			CAPEM:   string(caPEM),
			Message: fmt.Sprintf("Endpoint certificate ready (reused=%v)", reused),
		})
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("X-Enrollment-ID", id)
	w.Header().Set("X-Certificate-Reused", strconv.FormatBool(reused))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(certPEM)
	if len(caPEM) > 0 {
		if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
			_, _ = w.Write([]byte("\n"))
		}
		_, _ = w.Write(caPEM)
	}
}

func (s *Server) handleAdminEnrollments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	enrollments, err := s.pa.Enrollment.ListDeviceEnrollments()
	if err != nil {
		log.Printf("[ENROLL] Failed to list device enrollments: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list enrollments"})
		return
	}
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

	adminUser := r.Header.Get("X-Username")

	switch action {
	case "approve":
		caPEM, err := s.getCAPEM()
		if err != nil {
			log.Printf("[ENROLL] Failed to get CA PEM for %s: %v", enrollmentID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load CA certificate"})
			return
		}

		enrollment, certPEM, err := s.pa.Enrollment.ApprovePendingEnrollment(enrollmentID, adminUser)
		if err != nil {
			s.writeAdminEnrollmentActionError(w, enrollmentID, action, err)
			return
		}

		s.pa.Audit.LogEvent("enrollment_approved", "", adminUser,
			r.RemoteAddr, "", "", "Approved device "+enrollment.DeviceID, true)

		log.Printf("[ENROLL] Approved: id=%s device=%s by=%s", enrollmentID, enrollment.DeviceID, adminUser)

		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      enrollmentID,
			Status:  "approved",
			CertPEM: string(certPEM),
			CAPEM:   string(caPEM),
			Message: "Certificate issued",
		})

	case "revoke":
		enrollment, err := s.pa.Enrollment.RevokeDeviceEnrollment(enrollmentID)
		if err != nil {
			s.writeAdminEnrollmentActionError(w, enrollmentID, action, err)
			return
		}

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

func (s *Server) writeAdminEnrollmentActionError(w http.ResponseWriter, enrollmentID, action string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrollment not found"})
	case errors.Is(err, paenrollment.ErrInvalidRequest), errors.Is(err, paenrollment.ErrInvalidState):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, paenrollment.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrSigning):
		log.Printf("[ENROLL] Failed to sign CSR for %s: %v", enrollmentID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
	default:
		log.Printf("[ENROLL] Failed admin enrollment action %s for %s: %v", action, enrollmentID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to process enrollment action"})
	}
}

// handleCertRenewal handles POST /api/enroll/renew — device agents renew short-lived certs
func (s *Server) handleCertRenewal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	authenticatedEnrollment, ok := deviceEnrollmentFromContext(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device identity not found in request context"})
		return
	}

	var req models.EnrollmentRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	caPEM, err := s.getCAPEM()
	if err != nil {
		log.Printf("[ENROLL] Renewal: failed to load CA PEM for device %s: %v", req.DeviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load CA certificate"})
		return
	}

	enrollment, certPEM, err := s.pa.Enrollment.RenewDeviceCertificate(req, authenticatedEnrollment)
	if err != nil {
		s.writeEnrollmentRenewalError(w, req.DeviceID, err)
		return
	}

	log.Printf("[ENROLL] Renewed cert for device=%s serial=%s", req.DeviceID, enrollment.CertSerial)

	writeJSON(w, http.StatusOK, models.EnrollmentResponse{
		ID:      enrollment.ID,
		Status:  "approved",
		CertPEM: string(certPEM),
		CAPEM:   string(caPEM),
		Message: "Certificate renewed (24h validity)",
	})
}

func (s *Server) writeEnrollmentRenewalError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		log.Printf("[ENROLL] Invalid CSR in renewal for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, paenrollment.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": enrollmentClientMessage(err)})
	default:
		log.Printf("[ENROLL] Renewal: failed to sign CSR for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
	}
}

func enrollmentClientMessage(err error) string {
	message := err.Error()
	for _, prefix := range []string{
		paenrollment.ErrInvalidRequest.Error(),
		paenrollment.ErrForbidden.Error(),
		paenrollment.ErrNotFound.Error(),
		paenrollment.ErrInvalidState.Error(),
		paenrollment.ErrInvalidCSR.Error(),
	} {
		if strings.HasPrefix(message, prefix+": ") {
			return strings.TrimPrefix(message, prefix+": ")
		}
	}
	return message
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
// The gateway sends a token + CSR; the PDP validates the token, signs the CSR,
// and returns the mTLS cert. User authentication is handled by Connect-App as
// an OIDC public client, so the gateway receives no OIDC client secret.
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

	result, err := s.pa.Gateways.EnrollGateway(req)
	if err != nil {
		s.writeGatewayEnrollmentError(w, err)
		return
	}
	caPEM, err := s.getCAPEM()
	if err != nil {
		log.Printf("[GATEWAY-ENROLL] Failed to load CA PEM for gateway %s: %v", result.Gateway.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load CA certificate"})
		return
	}

	log.Printf("[GATEWAY-ENROLL] Gateway enrolled: id=%s name=%s fqdn=%s (strict PEP)",
		result.Gateway.ID, result.Gateway.Name, result.Gateway.FQDN)

	writeJSON(w, http.StatusOK, models.GatewayEnrollResponse{
		Status:    "enrolled",
		GatewayID: result.Gateway.ID,
		CertPEM:   string(result.CertPEM),
		CAPEM:     string(caPEM),
		Message:   "Gateway enrolled successfully. Certificate valid for 7 days.",
	})
}

func (s *Server) writeGatewayEnrollmentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pagateway.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": gatewayClientMessage(err)})
	case errors.Is(err, pagateway.ErrInvalidEnrollmentToken):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid enrollment token"})
	case errors.Is(err, pagateway.ErrEnrollmentTokenExpired):
		writeJSON(w, http.StatusGone, map[string]string{"error": "enrollment token has expired"})
	case errors.Is(err, pagateway.ErrGatewayAlreadyEnrolled):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "gateway is already enrolled"})
	case errors.Is(err, pagateway.ErrInvalidCSR):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	default:
		log.Printf("[GATEWAY-ENROLL] Gateway enrollment failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to enroll gateway"})
	}
}

// handleGatewayRenewCert handles POST /api/gateway/renew-cert — renew mTLS certificate.
// The gateway identity is derived from the authenticated mTLS certificate (set by
// gatewayAuthMiddleware in the request context). The gateway sends a new CSR;
// the PDP validates that the CSR CN matches the authenticated gateway's FQDN,
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

	result, err := s.pa.Gateways.RenewGatewayCertificate(gw, req.CSRPEM)
	if err != nil {
		s.writeGatewayRenewalError(w, gw.ID, err)
		return
	}
	caPEM, err := s.getCAPEM()
	if err != nil {
		log.Printf("[GATEWAY] Failed to load CA PEM for renewal (gateway=%s): %v", result.Gateway.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load CA certificate"})
		return
	}

	log.Printf("[GATEWAY] Cert renewed for gateway %s (serial=%s)", result.Gateway.ID, result.Gateway.CertSerial)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "renewed",
		"cert_pem": string(result.CertPEM),
		"ca_pem":   string(caPEM),
		"message":  "Certificate renewed (7-day validity)",
	})
}

func (s *Server) writeGatewayRenewalError(w http.ResponseWriter, gatewayID string, err error) {
	switch {
	case errors.Is(err, pagateway.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": gatewayClientMessage(err)})
	case errors.Is(err, pagateway.ErrInvalidCSR):
		message := gatewayClientMessage(err)
		if message == "invalid CSR PEM" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": message})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, pagateway.ErrForbidden):
		log.Printf("[GATEWAY] Cert renewal rejected for gateway %s: %v", gatewayID, err)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": gatewayClientMessage(err)})
	default:
		log.Printf("[GATEWAY] Cert renewal failed for gateway %s: %v", gatewayID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to renew gateway certificate"})
	}
}

func gatewayClientMessage(err error) string {
	message := err.Error()
	for _, prefix := range []string{
		pagateway.ErrInvalidRequest.Error(),
		pagateway.ErrInvalidCSR.Error(),
		pagateway.ErrForbidden.Error(),
	} {
		if strings.HasPrefix(message, prefix+": ") {
			return strings.TrimPrefix(message, prefix+": ")
		}
	}
	return message
}

func (s *Server) writeGatewayAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pagateway.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": gatewayClientMessage(err)})
	case errors.Is(err, pagateway.ErrGatewayNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
	case errors.Is(err, pagateway.ErrGatewayTokenGeneration):
		log.Printf("[ADMIN] Gateway token generation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate gateway token"})
	case errors.Is(err, pagateway.ErrGatewayPersistence):
		log.Printf("[ADMIN] Gateway persistence failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update gateway"})
	default:
		log.Printf("[ADMIN] Gateway operation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to manage gateway"})
	}
}

// handleAdminGateways handles GET/POST /api/admin/gateways — list or create gateways.
func (s *Server) handleAdminGateways(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.pa.Gateways.ListGatewaySummaries()
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, items)

	case http.MethodPost:
		var req pagateway.CreateGatewayRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		result, err := s.pa.Gateways.CreateGateway(req)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}

		log.Printf("[ADMIN] Gateway created: id=%s name=%s auth_mode=%s token_expires=%s", result.Gateway.ID, result.Gateway.Name, result.Gateway.AuthMode, result.Gateway.TokenExpiresAt)

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"id":               result.Gateway.ID,
			"name":             result.Gateway.Name,
			"auth_mode":        result.Gateway.AuthMode,
			"enrollment_token": result.EnrollmentToken,
			"token_expires_at": result.Gateway.TokenExpiresAt,
			"status":           result.Gateway.Status,
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
		gw, err := s.pa.Gateways.GetGatewayForAdmin(id)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, gw)

	case http.MethodPut:
		var req pagateway.UpdateGatewayRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if _, err := s.pa.Gateways.UpdateGateway(id, req); err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		gw, err := s.pa.Gateways.DeleteGateway(id)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}
		if gw.CertSerial != "" {
			log.Printf("[ADMIN] Revoked cert serial %s for gateway %s before deletion", gw.CertSerial, id)
		}
		log.Printf("[ADMIN] Gateway deleted: id=%s", id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	case http.MethodPost:
		// POST with action suffix
		if action == "regenerate-token" {
			result, err := s.pa.Gateways.RegenerateEnrollmentToken(id)
			if err != nil {
				s.writeGatewayAdminError(w, err)
				return
			}

			log.Printf("[ADMIN] Gateway enrollment token regenerated: id=%s", id)

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"enrollment_token": result.EnrollmentToken,
				"token_expires_at": result.TokenExpiresAt,
				"message":          "New enrollment token generated (1-hour expiry).",
			})
		} else if action == "revoke" {
			gw, err := s.pa.Gateways.RevokeGateway(id)
			if err != nil {
				s.writeGatewayAdminError(w, err)
				return
			}

			log.Printf("[ADMIN] Gateway revoked: id=%s name=%s", gw.ID, gw.Name)
			writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		} else if action == "test-federation" {
			// Probe the configured (or supplied) external IdP's discovery doc
			// to validate the issuer is reachable and exposes the required
			// OIDC endpoints. Used by the dashboard "Test connection" button
			// before saving a federation configuration.
			gw, found := s.pa.Store.GetGateway(id)
			if !found {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
				return
			}
			var req struct {
				Issuer string `json:"issuer,omitempty"`
			}
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&req)
			issuer := strings.TrimSpace(req.Issuer)
			if issuer == "" && gw.FederationConfig != nil {
				issuer = gw.FederationConfig.Issuer
			}
			if issuer == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "issuer is required (provide in request body or save federation_config first)"})
				return
			}
			disc, err := s.pa.IdP.Federation.Discover(issuer)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{
					"ok":     false,
					"issuer": issuer,
					"error":  err.Error(),
				})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"ok":                     true,
				"issuer":                 issuer,
				"authorization_endpoint": disc.AuthorizationEndpoint,
				"token_endpoint":         disc.TokenEndpoint,
				"userinfo_endpoint":      disc.UserinfoEndpoint,
				"jwks_uri":               disc.JWKSURI,
			})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action: " + action})
		}

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}
