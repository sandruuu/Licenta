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
	"pdp/models"
	"pdp/pa"
	"pdp/pa/auth"
	"pdp/store"
)

func newDeviceCatalogAccessToken(t *testing.T, server *Server, dataStore *store.Store, deviceID, role, certificateThumbprint string) string {
	t.Helper()
	dataStore.SaveUser(&models.User{
		ID:        "user-1",
		TenantID:  transportTestTenantID,
		Username:  "alice@example.test",
		Email:     "alice@example.test",
		Role:      role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	token, _, err := server.pa.Auth.JWT.GenerateAgentSessionToken(auth.AgentSessionTokenRequest{
		SessionID:                   "sess-test",
		UserID:                      "user-1",
		Username:                    "alice@example.test",
		Role:                        role,
		TenantID:                    transportTestTenantID,
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
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	dataStore.SaveTenant(&models.Tenant{
		ID:        transportTestTenantID,
		Name:      "Test Tenant",
		Domain:    "example.test",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	t.Cleanup(func() { _ = dataStore.Close() })
	dataDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:          ":8443",
		PDPFQDN:             "pdp.test.local",
		TLSCert:             dataDir + "/pdp-server-tls-cert.pem",
		MTLSCA:              dataDir + "/vault-pki-ca-cert.pem",
		PKIPath:             "pki_int",
		PKIRolePDP:          "trustcloud",
		PKIRoleDevice:       "trustagent-device",
		PKIRoleGateway:      "trustgateway",
		PKITransitKey:       "trustcloud-pdp-key",
		PKITimeout:          10 * time.Second,
		JWTExpiry:           time.Hour,
		MFATokenExpiry:      5 * time.Minute,
		JWTTransitKey:       "trustcloud-pdp-key",
		JWTKeyEncryptedPath: dataDir + "/jwt_signing_key.enc",
		TOTPIssuer:          "TrustCloud-PDP",
		SessionExpiry:       time.Hour,
		MaxSessions:         5,
		MaxLoginAttempts:    5,
		LockoutDuration:     15 * time.Minute,
		DataDir:             dataDir,
		DatabasePath:        dataDir + "/trustcloud.db",
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
			OIDCAuthorizeSessionTTL: 5 * time.Minute,
			OIDCAuthCodeTTL:         time.Minute,
			OIDCRefreshTokenTTL:     time.Hour,
			OIDCCleanupInterval:     time.Minute,
		},
		Public: config.PublicDashboardConfig{
			DeviceHealthAgentURL:  "http://127.0.0.1:12080",
			DeviceHealthTimeoutMS: 3000,
			DeviceHealthRetryMS:   5000,
			FederatedCallbackURL:  "https://localhost:8443/auth/federated/callback",
			OIDCDefaultScopes:     "openid profile email",
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
	policyAdmin := pa.NewPolicyAdministrator(cfg, dataStore)
	now := time.Now()
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:        "test_allow_admin_access",
		Name:      "Allow admin access in transport tests",
		Priority:  1,
		Enabled:   true,
		Action:    "allow",
		CreatedAt: now,
		UpdatedAt: now,
		Conditions: models.RuleConditions{
			AllowedRoles: []string{"admin"},
		},
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:        "assign_test_allow_admin_access",
		PolicyID:  "test_allow_admin_access",
		TenantID:  transportTestTenantID,
		Level:     "organization",
		Priority:  1,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	server := &Server{pa: policyAdmin, mtlsCAPool: x509.NewCertPool(), sessionGateways: make(map[string]string)}
	server.wireSessionDeleteSink()
	return server, dataStore
}

const transportTestTenantID = "tenant-1"

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
