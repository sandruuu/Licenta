package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"pdp/config"
	"pdp/internal/testdb"
	"pdp/internal/testredis"
	"pdp/mfa"
	"pdp/models"
	"pdp/pa"
	"pdp/pa/audit"
	"pdp/pa/auth"
	"pdp/pa/catalog"
	"pdp/pa/devices"
	"pdp/pa/enrollment"
	"pdp/pa/gateway"
	"pdp/pa/policies"
	"pdp/pa/resources"
	"pdp/pa/sessions"
	"pdp/pe/evaluation"
	"pdp/runtime/redisstate"
	"pdp/store"
)

func newDeviceCatalogAccessToken(t *testing.T, server *Server, dataStore *store.Store, deviceID, role, certificateThumbprint string) string {
	t.Helper()
	dataStore.SaveUser(&models.User{
		ID:             "user-1",
		OrganizationID: transportTestOrganizationID,
		Username:       "alice@example.test",
		Email:          "alice@example.test",
		Role:           role,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	})
	token, _, err := server.pa.Auth.JWT.GenerateAgentSessionToken(auth.AgentSessionTokenRequest{
		SessionID:                   "sess-test",
		UserID:                      "user-1",
		Username:                    "alice@example.test",
		Role:                        role,
		OrganizationID:              transportTestOrganizationID,
		DeviceID:                    deviceID,
		CertificateThumbprintSHA256: certificateThumbprint,
		LocalUserSIDHash:            "sid-hash",
		WindowsLogonSessionID:       "logon-session",
		WindowsSessionID:            "1",
		PolicyEpoch:                 1,
	})
	if err != nil {
		t.Fatalf("GenerateAgentSessionToken returned error: %v", err)
	}
	return token
}

func newDeviceAPITestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dataStore := testdb.NewStore(t)
	runtimeState := testredis.NewClient(t)
	dataStore.SaveOrganization(&models.Organization{
		ID:        transportTestOrganizationID,
		Name:      "Test Organization",
		Domain:    "example.test",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	dataDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:          ":8443",
		PDPFQDN:             "pdp.test.local",
		TLSCert:             dataDir + "/pdp-server-tls-cert.pem",
		MTLSCA:              dataDir + "/vault-pki-ca-cert.pem",
		PKIPath:             "pki_int",
		PKIRolePDP:          "trustcloud",
		PKIRoleDevice:       "trustagent",
		PKIRoleGateway:      "trustgateway",
		PKITransitKey:       "trustcloud-key",
		PKITimeout:          10 * time.Second,
		JWTTransitKey:       "trustcloud-key",
		JWTKeyEncryptedPath: dataDir + "/jwt_signing_key.enc",
		TOTPIssuer:          "TrustCloud",
		SessionExpiry:       time.Hour,
		MaxSessions:         5,
		MaxLoginAttempts:    5,
		LockoutDuration:     15 * time.Minute,
		DataDir:             dataDir,
		DatabaseURL:         testdb.DatabaseURL(t),
		RedisURL:            "redis://test-redis",
		PDPKeyEncryptedPath: dataDir + "/pdp_key.enc",
		CORSOrigins:         []string{},
		Runtime: config.RuntimeConfig{
			StoreAutoSaveInterval:   time.Minute,
			SessionCleanupInterval:  time.Minute,
			CertificateRenewBefore:  time.Hour,
			HTTPReadTimeout:         30 * time.Second,
			HTTPReadHeaderTimeout:   10 * time.Second,
			HTTPWriteTimeout:        60 * time.Second,
			HTTPIdleTimeout:         120 * time.Second,
			EventBufferSize:         64,
			AuthRateLimitWindow:     time.Minute,
			AuthRateLimitMax:        10,
			AdminAccessTokenTTL:     5 * time.Minute,
			AdminSessionIdleTTL:     30 * time.Minute,
			AdminSessionAbsoluteTTL: 8 * time.Hour,
		},
		Public: config.PublicDashboardConfig{
			FederatedCallbackURL: "https://localhost:8443/auth/federated/callback",
			OIDCDefaultScopes:    "openid profile email",
			OIDCDefaultClaimMapping: map[string]string{
				"username": "preferred_username",
				"email":    "email",
				"groups":   "groups",
			},
			ResourceDefaultPorts: map[string]int{
				"web": 443,
				"ssh": 22,
				"rdp": 3389,
			},
		},
	}
	policyAdmin := newTestPolicyAdministrator(t, cfg, dataStore, runtimeState)
	now := time.Now()
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:        "test_allow_admin_access",
		Name:      "Allow admin access in transport tests",
		Enabled:   true,
		Action:    "allow",
		CreatedAt: now,
		UpdatedAt: now,
		Conditions: models.RuleConditions{
			AllowedRoles: []string{"admin"},
		},
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:             "assign_test_allow_admin_access",
		PolicyID:       "test_allow_admin_access",
		OrganizationID: transportTestOrganizationID,
		Level:          "organization",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	server := &Server{
		pa:                   policyAdmin,
		mtlsCAPool:           x509.NewCertPool(),
		stepUpAuth:           newStepUpBrowserAuthStore(runtimeState, cfg.Runtime.BrowserAuthSessionTTL),
		adminSessions:        newAdminSessionStore(runtimeState, cfg.Runtime.AdminAccessTokenTTL, cfg.Runtime.AdminSessionIdleTTL, cfg.Runtime.AdminSessionAbsoluteTTL),
		adminMFA:             newAdminMFAStore(runtimeState),
		adminPasswordChanges: newAdminPasswordChangeStore(runtimeState),
		agentSessions:        newAgentSessionStore(runtimeState),
	}
	server.wireSessionDeleteSink()
	return server, dataStore
}

func newTestPolicyAdministrator(t *testing.T, cfg *config.Config, dataStore *store.Store, runtimeState *redisstate.Client) *pa.PolicyAdministrator {
	t.Helper()
	jwtKey, err := auth.GenerateJWTSigningKey()
	if err != nil {
		t.Fatalf("GenerateJWTSigningKey() error = %v", err)
	}
	jwtMgr, err := auth.NewJWTManager(jwtKey, cfg.Runtime.AdminAccessTokenTTL, cfg.Runtime.OIDCEnrollmentTokenTTL)
	if err != nil {
		t.Fatalf("NewJWTManager() error = %v", err)
	}
	auditLogger := audit.NewAuditLogger(dataStore)
	authService := &auth.Service{
		Users:      auth.NewUserManager(dataStore),
		JWT:        jwtMgr,
		WebAuthn:   mfa.NewWebAuthnProvider(cfg, runtimeState),
		Federation: auth.NewFederationProvider(runtimeState, cfg.Public.OIDCDefaultScopes, cfg.Public.OIDCDefaultClaimMapping, cfg.Runtime.FederationCacheTTL, cfg.Runtime.FederationHTTPTimeout),
		Store:      dataStore,
		Runtime:    runtimeState,
		Cfg:        cfg,
	}
	return &pa.PolicyAdministrator{
		Auth:       authService,
		Engine:     evaluation.NewEngine(),
		Geo:        policies.NewGeoLocator(dataStore, runtimeState, cfg.Geo),
		Catalog:    catalog.NewService(dataStore, cfg.Runtime.CatalogTTLSeconds),
		Devices:    devices.NewService(dataStore, auditLogger),
		Enrollment: enrollment.NewService(dataStore, runtimeState, enrollment.Config{CertificateValidityDays: cfg.Enrollment.CertificateValidityDays, BrowserSessionTTL: cfg.Enrollment.BrowserSessionTTL}),
		Gateways:   gateway.NewService(dataStore, cfg.PKIRoleGateway, gateway.Config{CertificateValidityDays: cfg.Gateway.CertificateValidityDays, EnrollmentTokenTTL: cfg.Gateway.EnrollmentTokenTTL}),
		Resources:  resources.NewService(dataStore),
		Sessions:   sessions.NewSessionManager(dataStore, cfg.SessionExpiry, cfg.MaxSessions),
		StepUps:    pa.NewStepUpManager(runtimeState),
		Audit:      auditLogger,
		Store:      dataStore,
		Runtime:    runtimeState,
		Cfg:        cfg,
	}
}

const transportTestOrganizationID = "organization-1"

func newDeviceAPICertificate(t *testing.T, commonName string, notAfter time.Time) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, cert
}
