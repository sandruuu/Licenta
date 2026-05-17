package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"pdp/pa"
	"pdp/pa/events"
	"pdp/pki"
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

	// PA event broker for CAEP-style state-change notifications.
	events *events.Broker
}

// NewServer creates a new API server.
// Gateway and device endpoints always require mTLS, so the client CA is mandatory.
func NewServer(policyAdmin *pa.PolicyAdministrator, addr, mtlsCAPath string) (*Server, error) {
	if strings.TrimSpace(mtlsCAPath) == "" {
		return nil, fmt.Errorf("strict mTLS requires mtls_ca to be configured on the PDP server")
	}
	if policyAdmin.Cfg == nil {
		return nil, fmt.Errorf("PDP config is required")
	}
	policyAdmin.Cfg.ApplyDefaults()

	s := &Server{
		pa:              policyAdmin,
		mux:             http.NewServeMux(),
		addr:            addr,
		gatewayControl:  NewGatewayControlRegistry(),
		sessionGateways: make(map[string]string),
		enrollLimiter:   make(map[string]*enrollRateEntry),
		authLimiter:     make(map[string]*enrollRateEntry),
		events:          events.NewBroker(policyAdmin.Cfg.Runtime.EventBufferSize),
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

	if policyAdmin.Cfg.PKIURL != "" {
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
		log.Printf("[API] PKI provider: vault (url=%s path=%s)", policyAdmin.Cfg.PKIURL, policyAdmin.Cfg.PKIPath)
	} else {
		log.Printf("[API] PKI provider: none (dev mode, no Vault configured)")
	}
	if policyAdmin.Enrollment != nil {
		policyAdmin.Enrollment.SetCertificateAuthority(s.signCSR, s.revokeCertificate, s.deviceRole)
		if policyAdmin.Auth != nil && policyAdmin.Auth.JWT != nil {
			policyAdmin.Enrollment.SetEnrollmentTokenIssuer(policyAdmin.Auth.JWT.GenerateEnrollmentTokenForUserSID)
		}
	}
	if policyAdmin.Gateways != nil {
		policyAdmin.Gateways.SetCertificateAuthority(s.signGatewayCSR, s.revokeCertificate)
	}

	s.registerRoutes()
	s.initDeviceCatalogGRPC()
	s.hydrateOIDCClients()
	return s, nil
}

// hydrateOIDCClients registers the native Connect-App OIDC public client.
// Gateways are no longer OIDC clients; they act only as resource servers/PEPs.
func (s *Server) hydrateOIDCClients() {
	if s.pa == nil || s.pa.Store == nil || s.pa.Auth == nil || s.pa.Auth.OIDC == nil {
		return
	}
	s.pa.Auth.OIDC.RegisterNativeConnectAppClient()
	s.pa.Auth.OIDC.RegisterNativeAgentClient()
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
	s.mux.HandleFunc("/api/config/public", s.handlePublicConfig)
	s.mux.HandleFunc("/health", s.handleHealthCheck)
	s.mux.HandleFunc("/api/ca/cert", s.handleCACert)                    // Public: returns CA certificate PEM
	s.mux.HandleFunc("/api/cert-fingerprint", s.handleCertFingerprint)  // Public: returns server TLS cert SHA-256 fingerprint
	s.mux.HandleFunc("/api/enroll/token", s.handleIssueEnrollmentToken) // Device-bound, short-lived token for service EST simpleenroll

	// ─────────────────────────────────────────────
	// Browser auth flow endpoints (Duo-like)
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/auth/login", s.handleWebLoginPage)                   // Serve React access login page
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

	// SCIM inbound provisioning endpoints (Bearer token per tenant IdP)
	s.mux.HandleFunc("/scim/v2/", s.handleSCIM)

	// ─────────────────────────────────────────────
	// ─────────────────────────────────────────────

	// ─────────────────────────────────────────────
	// ─────────────────────────────────────────────

	// ─────────────────────────────────────────────
	// Gateway endpoints (strict mTLS + enrolled gateway identity)
	// ─────────────────────────────────────────────

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

	// ─────────────────────────────────────────────
	// Admin endpoints (JWT auth + admin role)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/admin/users", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminUsers)))
	s.mux.Handle("/api/admin/tenants", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminTenants)))
	s.mux.Handle("/api/admin/tenants/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminTenantByID)))
	s.mux.Handle("/api/admin/sessions", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSessions)))
	s.mux.Handle("/api/admin/sessions/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSessionByID)))
	s.mux.Handle("/api/admin/audit", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAudit)))
	s.mux.Handle("/api/admin/directory/users", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDirectoryUsers)))
	s.mux.Handle("/api/admin/directory/groups", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDirectoryGroups)))

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
	s.mux.Handle("/api/admin/policies", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminPolicies)))
	s.mux.Handle("/api/admin/policies/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminPolicyByID)))
	s.mux.Handle("/api/admin/policy-assignments", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminPolicyAssignments)))
	s.mux.Handle("/api/admin/policy-assignments/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminPolicyAssignmentByID)))
	s.mux.Handle("/api/admin/device-health", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDeviceHealth)))
	s.mux.Handle("/api/admin/device-health/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDeviceHealthByID)))
	s.mux.Handle("/api/admin/device-posture", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDevicePosture)))
	s.mux.Handle("/api/admin/device-posture/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDevicePostureByID)))
	s.mux.Handle("/api/admin/dashboard", s.adminAuthMiddleware(http.HandlerFunc(s.handleDashboardStats)))

	// ─────────────────────────────────────────────
	// Gateway enrollment & lifecycle endpoints
	// ─────────────────────────────────────────────
	// Admin gateway management
	s.mux.Handle("/api/admin/gateways", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminGateways)))
	s.mux.Handle("/api/admin/gateways/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminGatewayByID)))

	// ─────────────────────────────────────────────
	// Admin Identity Provider management (per Tenant)
	// ─────────────────────────────────────────────
	s.mux.Handle("/api/admin/tenants/idps/discover", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminIdPDiscover)))
	s.mux.Handle("/api/admin/tenants/idps", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminIdentityProviders)))
	s.mux.Handle("/api/admin/tenants/idps/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminIdentityProviderByID)))

	// ─────────────────────────────────────────────
	// Dashboard SPA (serve React build)
	// ─────────────────────────────────────────────
	s.mux.HandleFunc("/dashboard/", s.handleDashboardSPA)
	s.mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
	})
}

// StartTLS begins listening for HTTPS requests using an in-memory certificate provider.
func (s *Server) StartTLS(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) error {
	appCfg := s.appConfig()
	httpHandler := loggingMiddleware(securityHeadersMiddleware(appCfg.Public.DeviceHealthAgentURL)(corsMiddleware(appCfg.CORSOrigins)(s.mux)))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.grpcHandler != nil && isGRPCRequest(r) {
			s.grpcHandler.ServeHTTP(w, r)
			return
		}
		httpHandler.ServeHTTP(w, r)
	})
	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: getCertificate,
	}
	tlsConfig.ClientCAs = s.mtlsCAPool
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	server := &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       appCfg.Runtime.HTTPReadTimeout,
		ReadHeaderTimeout: appCfg.Runtime.HTTPReadHeaderTimeout,
		WriteTimeout:      appCfg.Runtime.HTTPWriteTimeout,
		IdleTimeout:       appCfg.Runtime.HTTPIdleTimeout,
	}
	log.Printf("[API] Server starting on %s (TLS)", s.addr)
	return server.ListenAndServeTLS("", "")
}
