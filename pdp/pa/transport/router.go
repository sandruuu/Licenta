package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"pdp/pa"
	"pdp/pa/enforcement"
	"pdp/pa/events"
	"pdp/pki"
)

// Server is the HTTP API server for the TrustCloud component.
type Server struct {
	pa             *pa.PolicyAdministrator
	mux            *http.ServeMux
	addr           string
	mtlsCAPool     *x509.CertPool
	grpcHandler    http.Handler
	gatewayControl *GatewayControlRegistry
	draining       atomic.Bool

	externalPKI   *pki.VaultClient
	externalCAPEM []byte

	agentSessions        *agentSessionStore
	adminSessions        *adminSessionStore
	stepUpAuth           *stepUpBrowserAuthStore
	adminMFA             *adminMFAStore
	adminPasswordChanges *adminPasswordChangeStore

	// PA event broker for CAEP-style state-change notifications.
	events *events.Broker
}

// NewServer creates a new API server.
// Gateway and device endpoints always require mTLS, so the client CA is mandatory.
func NewServer(policyAdmin *pa.PolicyAdministrator, addr, mtlsCAPath string) (*Server, error) {
	if strings.TrimSpace(mtlsCAPath) == "" {
		return nil, fmt.Errorf("strict mTLS requires mtls_ca to be configured on the PDP server")
	}
	if policyAdmin == nil {
		return nil, fmt.Errorf("PDP policy administrator is required")
	}
	if policyAdmin.Cfg == nil {
		return nil, fmt.Errorf("PDP config is required")
	}
	policyAdmin.Cfg.ApplyDefaults()

	s := &Server{
		pa:                   policyAdmin,
		mux:                  http.NewServeMux(),
		addr:                 addr,
		gatewayControl:       NewGatewayControlRegistry(policyAdmin.Runtime),
		agentSessions:        newAgentSessionStore(policyAdmin.Runtime),
		adminSessions:        newAdminSessionStore(policyAdmin.Runtime, policyAdmin.Cfg.Runtime.AdminAccessTokenTTL, policyAdmin.Cfg.Runtime.AdminSessionIdleTTL, policyAdmin.Cfg.Runtime.AdminSessionAbsoluteTTL),
		stepUpAuth:           newStepUpBrowserAuthStore(policyAdmin.Runtime, policyAdmin.Cfg.Runtime.BrowserAuthSessionTTL),
		adminMFA:             newAdminMFAStore(policyAdmin.Runtime),
		adminPasswordChanges: newAdminPasswordChangeStore(policyAdmin.Runtime),
		events:               events.NewBroker(policyAdmin.Runtime, policyAdmin.Cfg.Runtime.EventBufferSize),
	}

	if policyAdmin.Devices != nil {
		policyAdmin.Devices.SetEventPublisher(s)
	}
	if policyAdmin.Resources != nil {
		policyAdmin.Resources.SetEventPublisher(s)
	}
	if policyAdmin.Enrollment != nil {
		policyAdmin.Enrollment.SetEventPublisher(s)
	}
	if policyAdmin.Gateways != nil {
		policyAdmin.Gateways.SetEventPublisher(s)
	}
	s.wireSessionDeleteSink()
	enforcement.NewService(policyAdmin, s.events).Start(context.Background())

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
		log.Printf("[API] PKI provider: none (no Vault configured)")
	}
	if policyAdmin.Enrollment != nil {
		policyAdmin.Enrollment.SetCertificateAuthority(s.signCSR, s.revokeCertificate, s.deviceRole)
		policyAdmin.Enrollment.SetInteractiveDeviceCertificateIssuer(s.signDeviceEnrollmentCSR)
		if policyAdmin.Auth != nil && policyAdmin.Auth.JWT != nil {
			policyAdmin.Enrollment.SetEnrollmentTokenIssuer(policyAdmin.Auth.JWT.GenerateEnrollmentTokenForUserSID)
		}
	}
	if policyAdmin.Gateways != nil {
		policyAdmin.Gateways.SetCertificateAuthority(s.signGatewayCSR, s.revokeCertificate)
	}

	s.registerRoutes()
	s.initDeviceCatalogGRPC()
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
	// Public endpoints (no auth required)
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/password/change-initial", s.handleInitialPasswordChange)
	s.mux.HandleFunc("/api/auth/mfa/verify", s.handleMFAVerify)
	s.mux.HandleFunc("/api/auth/mfa/recovery", s.handleMFARecovery)
	s.mux.HandleFunc("/api/auth/passkey/login/begin", s.handleAdminPasskeyLoginBegin)
	s.mux.HandleFunc("/api/auth/passkey/login/finish", s.handleAdminPasskeyLoginFinish)
	s.mux.HandleFunc("/api/auth/passkey/register/begin", s.handleAdminPasskeyRegisterBegin)
	s.mux.HandleFunc("/api/auth/passkey/register/finish", s.handleAdminPasskeyRegisterFinish)
	s.mux.HandleFunc("/api/auth/session/refresh", s.handleAdminSessionRefresh)
	s.mux.HandleFunc("/api/auth/logout", s.handleAdminLogout)
	s.mux.HandleFunc("/api/config/public", s.handlePublicConfig)
	s.mux.HandleFunc("/live", s.handleLiveCheck)
	s.mux.HandleFunc("/ready", s.handleReadyCheck)
	s.mux.HandleFunc("/health", s.handleHealthCheck)
	s.mux.HandleFunc("/api/ca/cert", s.handleCACert)                   // Public: returns CA certificate PEM
	s.mux.HandleFunc("/api/cert-fingerprint", s.handleCertFingerprint) // Public: returns server TLS cert SHA-256 fingerprint

	// Public agent identity flow endpoints
	s.mux.HandleFunc("/auth/login", s.handleWebLoginPage) // Serve React access login page
	s.mux.HandleFunc(publicEnrollPathPrefix, s.handleBrowserEnroll)
	s.mux.HandleFunc(publicSignInPathPrefix, s.handleBrowserAgentSession)
	s.mux.HandleFunc(publicStepUpAssetPath, s.handleStepUpBrowserAsset)
	s.mux.HandleFunc(publicStepUpPathPrefix, s.handleBrowserStepUp)

	s.mux.HandleFunc("/auth/federated/callback", s.handleFederatedCallback)

	// SCIM inbound provisioning endpoints (Bearer token per organization IdP)
	s.mux.HandleFunc("/scim/v2/", s.handleSCIM)

	// Authenticated user endpoints (JWT auth)
	s.mux.Handle("/api/auth/revoke-token", s.adminAuthMiddleware(http.HandlerFunc(s.handleRevokeToken)))

	// WebAuthn / Passkey endpoints
	s.mux.HandleFunc("/api/step-up/recovery-codes", s.handleStepUpRecoveryCodesRegenerate)
	s.mux.HandleFunc("/api/step-up/webauthn/begin", s.handleStepUpWebAuthnBegin)
	s.mux.HandleFunc("/api/step-up/webauthn/finish", s.handleStepUpWebAuthnFinish)
	s.mux.HandleFunc("/api/step-up/webauthn/register/begin", s.handleStepUpWebAuthnRegisterBegin)
	s.mux.HandleFunc("/api/step-up/webauthn/register/finish", s.handleStepUpWebAuthnRegisterFinish)

	// Admin endpoints (JWT auth + admin role)
	s.mux.Handle("/api/admin/session", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSession)))
	s.mux.Handle("/api/admin/account", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAccount)))
	s.mux.Handle("/api/admin/account/password", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAccountPassword)))
	s.mux.Handle("/api/admin/account/recovery-codes", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAccountRecoveryCodes)))
	s.mux.Handle("/api/admin/account/passkeys", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAccountPasskeys)))
	s.mux.Handle("/api/admin/account/passkeys/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAccountPasskeyAction)))
	s.mux.Handle("/api/admin/users", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminUsers)))
	s.mux.Handle("/api/admin/organizations", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminOrganizations)))
	s.mux.Handle("/api/admin/organizations/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminOrganizationByID)))
	s.mux.Handle("/api/admin/sessions", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSessions)))
	s.mux.Handle("/api/admin/sessions/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminSessionByID)))
	s.mux.Handle("/api/admin/audit", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminAudit)))
	s.mux.Handle("/api/admin/directory/users", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDirectoryUsers)))
	s.mux.Handle("/api/admin/directory/groups", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDirectoryGroups)))

	// Device enrollment lifecycle endpoints
	s.mux.Handle("/api/enroll/renew", s.requireClientCert(s.deviceAuthMiddleware(http.HandlerFunc(s.handleCertRenewal)))) // Device renews short-lived cert (mTLS identity)
	s.mux.Handle("/api/admin/enrollments", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminEnrollments)))             // List enrollments
	s.mux.Handle("/api/admin/enrollments/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminEnrollmentAction)))       // Approve/revoke

	// PDP Admin endpoints (resources, dashboard)
	s.mux.Handle("/api/admin/resources", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminResources)))
	s.mux.Handle("/api/admin/resources/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminResourceByID)))
	s.mux.Handle("/api/admin/policies", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminPolicies)))
	s.mux.Handle("/api/admin/policies/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminPolicyByID)))
	s.mux.Handle("/api/admin/policy-assignments", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminPolicyAssignments)))
	s.mux.Handle("/api/admin/policy-assignments/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminPolicyAssignmentByID)))
	s.mux.Handle("/api/admin/device-data", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDeviceData)))
	s.mux.Handle("/api/admin/device-data/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminDeviceDataByID)))
	s.mux.Handle("/api/admin/dashboard", s.adminAuthMiddleware(http.HandlerFunc(s.handleDashboardStats)))

	// Gateway enrollment & lifecycle endpoints
	// Admin gateway management
	s.mux.Handle("/api/admin/gateways", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminGateways)))
	s.mux.Handle("/api/admin/gateways/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminGatewayByID)))

	// Admin Identity Provider management (per Organization)
	s.mux.Handle("/api/admin/organizations/idps/discover", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminIdPDiscover)))
	s.mux.Handle("/api/admin/organizations/idps", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminIdentityProviders)))
	s.mux.Handle("/api/admin/organizations/idps/", s.adminAuthMiddleware(http.HandlerFunc(s.handleAdminIdentityProviderByID)))

	// Dashboard SPA (serve React build)
	s.mux.HandleFunc("/", s.handleDashboardSPA)
}

// StartTLS begins listening for HTTPS requests using the active dynamic certificate provider.
func (s *Server) StartTLS(ctx context.Context, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	appCfg := s.appConfig()
	httpHandler := loggingMiddleware(securityHeadersMiddleware()(corsMiddleware(appCfg.CORSOrigins)(s.mux)))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.grpcHandler != nil && isGRPCRequest(r) {
			s.grpcHandler.ServeHTTP(w, r)
			return
		}
		httpHandler.ServeHTTP(w, r)
	})
	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
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
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		s.BeginDrain()
		if appCfg.Runtime.ReadinessDrainDelay > 0 {
			time.Sleep(appCfg.Runtime.ReadinessDrainDelay)
		}
		timeout := appCfg.Runtime.HTTPShutdownTimeout
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) BeginDrain() {
	if s != nil {
		s.draining.Store(true)
	}
}

func (s *Server) IsDraining() bool {
	return s != nil && s.draining.Load()
}
