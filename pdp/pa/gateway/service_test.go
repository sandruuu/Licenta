package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"pdp/models"
	"pdp/store"
)

// gatewayTokenHash returns the SHA-256 hex hash of a token, matching the
// production encoding used by CreateGateway/GetGatewayByToken.
func gatewayTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func TestServiceEnrollGatewayConsumesTokenAndPersistsCertificate(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	ca := newGatewayTestCA(t)
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore, "gateway-role")
	service.SetCertificateAuthority(ca.sign, nil)
	service.now = func() time.Time { return fixedNow }

	dataStore.SaveGateway(&models.Gateway{
		ID:              "gw-1",
		TenantID:        gatewayTestTenantID,
		TenantIDs:       []string{gatewayTestTenantID},
		Name:            "Old Gateway",
		FQDN:            "old.example.test",
		EnrollmentToken: gatewayTokenHash("token-1"),
		TokenExpiresAt:  fixedNow.Add(time.Hour).Format(time.RFC3339),
		Status:          "pending",
		CreatedAt:       fixedNow.Add(-time.Hour),
		UpdatedAt:       fixedNow.Add(-time.Hour),
	})

	result, err := service.EnrollGateway(models.GatewayEnrollRequest{
		Token:     "token-1",
		CSRPEM:    newGatewayCSR(t, gatewayTestTenantID, "gw-1", "edge.example.test"),
		Name:      "Edge Gateway",
		FQDN:      "edge.example.test",
		GatewayID: "gw-1",
		TenantID:  gatewayTestTenantID,
	})
	if err != nil {
		t.Fatalf("EnrollGateway returned error: %v", err)
	}
	if result.Gateway.Status != "enrolled" {
		t.Fatalf("gateway status = %q, want enrolled", result.Gateway.Status)
	}
	if result.Gateway.EnrollmentToken != "" || result.Gateway.TokenExpiresAt != "" {
		t.Fatalf("enrollment token was not consumed: token=%q expires=%q", result.Gateway.EnrollmentToken, result.Gateway.TokenExpiresAt)
	}
	if result.Gateway.CertPEM == "" || result.Gateway.CertFingerprint == "" || result.Gateway.CertSerial == "" {
		t.Fatalf("gateway certificate metadata was not populated: %+v", result.Gateway)
	}
	if result.Gateway.Name != "Edge Gateway" || result.Gateway.FQDN != "edge.example.test" {
		t.Fatalf("gateway identity was not updated: name=%q fqdn=%q", result.Gateway.Name, result.Gateway.FQDN)
	}
	if ca.lastRole() != "gateway-role" {
		t.Fatalf("signer role = %q, want gateway-role", ca.lastRole())
	}
	if string(result.CertPEM) != result.Gateway.CertPEM {
		t.Fatalf("result cert does not match persisted gateway cert")
	}
	if _, found := dataStore.GetGatewayByToken("token-1"); found {
		t.Fatalf("consumed enrollment token still resolves a gateway")
	}
	saved, found := dataStore.GetGateway("gw-1")
	if !found {
		t.Fatalf("gateway was not persisted")
	}
	if saved.CertSerial != result.Gateway.CertSerial || saved.Status != "enrolled" {
		t.Fatalf("saved gateway mismatch: got serial=%q status=%q", saved.CertSerial, saved.Status)
	}
}

func TestServiceEnrollGatewayRejectsInvalidExpiredAndEnrolledTokens(t *testing.T) {
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

	t.Run("invalid token", func(t *testing.T) {
		dataStore := newGatewayTestStore(t)
		service := newGatewayTestService(t, dataStore, fixedNow)
		_, err := service.EnrollGateway(models.GatewayEnrollRequest{Token: "missing", CSRPEM: newGatewayCSR(t, gatewayTestTenantID, "gw-1", "gw.example.test")})
		if !errors.Is(err, ErrInvalidEnrollmentToken) {
			t.Fatalf("error = %v, want ErrInvalidEnrollmentToken", err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		dataStore := newGatewayTestStore(t)
		service := newGatewayTestService(t, dataStore, fixedNow)
		dataStore.SaveGateway(&models.Gateway{ID: "gw-expired", TenantID: gatewayTestTenantID, EnrollmentToken: gatewayTokenHash("expired"), TokenExpiresAt: fixedNow.Add(-time.Minute).Format(time.RFC3339), Status: "pending"})
		_, err := service.EnrollGateway(models.GatewayEnrollRequest{Token: "expired", CSRPEM: newGatewayCSR(t, gatewayTestTenantID, "gw-expired", "gw.example.test")})
		if !errors.Is(err, ErrEnrollmentTokenExpired) {
			t.Fatalf("error = %v, want ErrEnrollmentTokenExpired", err)
		}
	})

	t.Run("already enrolled", func(t *testing.T) {
		dataStore := newGatewayTestStore(t)
		service := newGatewayTestService(t, dataStore, fixedNow)
		dataStore.SaveGateway(&models.Gateway{ID: "gw-enrolled", TenantID: gatewayTestTenantID, EnrollmentToken: gatewayTokenHash("enrolled"), TokenExpiresAt: fixedNow.Add(time.Hour).Format(time.RFC3339), Status: "enrolled"})
		_, err := service.EnrollGateway(models.GatewayEnrollRequest{Token: "enrolled", CSRPEM: newGatewayCSR(t, gatewayTestTenantID, "gw-enrolled", "gw.example.test")})
		if !errors.Is(err, ErrGatewayAlreadyEnrolled) {
			t.Fatalf("error = %v, want ErrGatewayAlreadyEnrolled", err)
		}
	})
}

func TestServiceRenewGatewayCertificateUpdatesCertificateAndRevokesOldSerial(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	ca := newGatewayTestCA(t)
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	var revokedSerial, revokedSubject string
	service := NewService(dataStore, "gateway-role")
	service.SetCertificateAuthority(ca.sign, func(serial, certPEM, subjectID string, expiresOn time.Time) {
		revokedSerial = serial
		revokedSubject = subjectID
	})
	service.now = func() time.Time { return fixedNow }

	oldCertPEM, err := ca.sign([]byte(newGatewayCSR(t, gatewayTestTenantID, "gw-1", "edge.example.test")), 7, "gateway-role")
	if err != nil {
		t.Fatalf("sign old certificate: %v", err)
	}
	_, oldSerial := certificateIdentity(oldCertPEM)
	gateway := &models.Gateway{
		ID:            "gw-1",
		TenantID:      gatewayTestTenantID,
		TenantIDs:     []string{gatewayTestTenantID},
		Name:          "Edge Gateway",
		FQDN:          "edge.example.test",
		Status:        "enrolled",
		CertPEM:       string(oldCertPEM),
		CertSerial:    oldSerial,
		CertExpiresAt: fixedNow.Add(2 * time.Hour).Format(time.RFC3339),
		CreatedAt:     fixedNow.Add(-time.Hour),
		UpdatedAt:     fixedNow.Add(-time.Hour),
	}
	dataStore.SaveGateway(gateway)

	result, err := service.RenewGatewayCertificate(gateway, newGatewayCSR(t, gatewayTestTenantID, "gw-1", "edge.example.test"))
	if err != nil {
		t.Fatalf("RenewGatewayCertificate returned error: %v", err)
	}
	if result.Gateway.CertSerial == "" || result.Gateway.CertSerial == oldSerial {
		t.Fatalf("certificate serial was not renewed: old=%q new=%q", oldSerial, result.Gateway.CertSerial)
	}
	if revokedSerial != oldSerial || revokedSubject != "gateway:gw-1" {
		t.Fatalf("old serial was not revoked correctly: serial=%q subject=%q", revokedSerial, revokedSubject)
	}
	saved, found := dataStore.GetGateway("gw-1")
	if !found {
		t.Fatalf("gateway was not persisted")
	}
	if saved.CertSerial != result.Gateway.CertSerial || saved.CertPEM != string(result.CertPEM) {
		t.Fatalf("saved renewal mismatch: saved serial=%q result serial=%q", saved.CertSerial, result.Gateway.CertSerial)
	}
}

func TestServiceRenewGatewayCertificateValidatesCSRIdentity(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := newGatewayTestService(t, dataStore, fixedNow)
	gateway := &models.Gateway{ID: "gw-1", TenantID: gatewayTestTenantID, FQDN: "edge.example.test", Status: "enrolled"}

	_, err := service.RenewGatewayCertificate(gateway, newGatewayCSR(t, gatewayTestTenantID, "gw-other", "edge.example.test"))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("error = %v, want ErrForbidden", err)
	}

	_, err = service.RenewGatewayCertificate(gateway, "not a csr")
	if !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("error = %v, want ErrInvalidCSR", err)
	}
}

func TestServiceCreateListAndGetGatewayForAdmin(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	seedGatewayTenant(dataStore)
	dataStore.SaveResource(&models.Resource{ID: "res-1", TenantID: gatewayTestTenantID, Name: "SSH", Type: "ssh", Enabled: true})
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore, "gateway-role")
	service.now = func() time.Time { return fixedNow }

	result, err := service.CreateGateway(CreateGatewayRequest{
		TenantID:          gatewayTestTenantID,
		Name:              "Edge Gateway",
		FQDN:              "edge.example.test",
		AssignedResources: []string{"res-1"},
		AuthMode:          "federated",
		FederationConfig: &models.FederationConfig{
			Issuer:       " https://idp.example.test ",
			ClientID:     " client-1 ",
			ClientSecret: "secret-1",
		},
	})
	if err != nil {
		t.Fatalf("CreateGateway returned error: %v", err)
	}
	if result.Gateway.ID == "" || len(result.EnrollmentToken) != gatewayEnrollmentTokenBytes*2 {
		t.Fatalf("gateway credentials were not generated: id=%q token=%q", result.Gateway.ID, result.EnrollmentToken)
	}
	if result.Gateway.AuthMode != "federated" || result.Gateway.FederationConfig.Scopes != "openid profile email" {
		t.Fatalf("federation defaults not applied: %+v", result.Gateway.FederationConfig)
	}

	items, err := service.ListGatewaySummaries()
	if err != nil {
		t.Fatalf("ListGatewaySummaries returned error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("list length = %d, want 1", len(items))
	}
	if items[0].FederationConfig == nil || items[0].FederationConfig.ClientSecret != "" {
		t.Fatalf("list did not strip federation secret: %+v", items[0].FederationConfig)
	}
	// EnrollmentToken is intentionally zeroed in gatewayListItem for defense-in-depth.
	// The plaintext token is only returned at creation time (CreateGatewayResult).
	if items[0].EnrollmentToken != "" {
		t.Fatalf("list enrollment token should be empty (sanitized), got %q", items[0].EnrollmentToken)
	}

	result.Gateway.CertPEM = "cert-pem"
	result.Gateway.OIDCClientSecret = "oidc-secret"
	dataStore.SaveGateway(result.Gateway)
	detail, err := service.GetGatewayForAdmin(result.Gateway.ID)
	if err != nil {
		t.Fatalf("GetGatewayForAdmin returned error: %v", err)
	}
	if detail.CertPEM != "" || detail.OIDCClientSecret != "" || detail.FederationConfig.ClientSecret != "" {
		t.Fatalf("admin detail was not sanitized: cert=%q oidc=%q federation=%+v", detail.CertPEM, detail.OIDCClientSecret, detail.FederationConfig)
	}
}

func TestServiceCreateGatewayValidatesAdminRequest(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	seedGatewayTenant(dataStore)
	service := NewService(dataStore, "gateway-role")

	_, err := service.CreateGateway(CreateGatewayRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty request error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateGateway(CreateGatewayRequest{Name: "Edge", TenantID: gatewayTestTenantID, AuthMode: "unknown"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid auth mode error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateGateway(CreateGatewayRequest{Name: "Edge", TenantID: gatewayTestTenantID, AuthMode: "federated"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing federation config error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateGateway(CreateGatewayRequest{Name: "Edge"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing tenant error = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceUpdateGatewayPreservesFederationSecretAndCanClearFederation(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	seedGatewayTenant(dataStore)
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore, "gateway-role")
	service.now = func() time.Time { return fixedNow }
	dataStore.SaveResource(&models.Resource{ID: "res-1", TenantID: gatewayTestTenantID, Name: "SSH", Type: "ssh", Enabled: true})
	dataStore.SaveResource(&models.Resource{ID: "res-2", TenantID: gatewayTestTenantID, Name: "RDP", Type: "rdp", Enabled: true})
	dataStore.SaveGateway(&models.Gateway{
		ID:        "gw-1",
		TenantID:  gatewayTestTenantID,
		TenantIDs: []string{gatewayTestTenantID},
		Name:      "Old Gateway",
		FQDN:      "old.example.test",
		Status:    "pending",
		AuthMode:  "federated",
		FederationConfig: &models.FederationConfig{
			Issuer:       "https://old-idp.example.test",
			ClientID:     "old-client",
			ClientSecret: "secret-1",
		},
		CreatedAt: fixedNow.Add(-time.Hour),
		UpdatedAt: fixedNow.Add(-time.Hour),
	})

	updated, err := service.UpdateGateway("gw-1", UpdateGatewayRequest{
		Name:              "New Gateway",
		FQDN:              "new.example.test",
		AssignedResources: []string{"res-1", "res-2"},
		FederationConfig: &models.FederationConfig{
			Issuer:   "https://new-idp.example.test",
			ClientID: "new-client",
		},
	})
	if err != nil {
		t.Fatalf("UpdateGateway returned error: %v", err)
	}
	if updated.Name != "New Gateway" || updated.FQDN != "new.example.test" || len(updated.AssignedResources) != 2 {
		t.Fatalf("gateway fields not updated: %+v", updated)
	}
	if updated.FederationConfig == nil || updated.FederationConfig.ClientSecret != "secret-1" {
		t.Fatalf("federation secret was not preserved: %+v", updated.FederationConfig)
	}

	updated, err = service.UpdateGateway("gw-1", UpdateGatewayRequest{AuthMode: "builtin"})
	if err != nil {
		t.Fatalf("UpdateGateway builtin returned error: %v", err)
	}
	if updated.AuthMode != "builtin" || updated.FederationConfig != nil {
		t.Fatalf("builtin update did not clear federation config: auth=%q federation=%+v", updated.AuthMode, updated.FederationConfig)
	}
}

func TestServiceRegenerateRevokeAndDeleteGateway(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	var revoked []string
	service := NewService(dataStore, "gateway-role")
	service.SetCertificateAuthority(nil, func(serial, certPEM, subjectID string, expiresOn time.Time) {
		revoked = append(revoked, serial+":"+subjectID)
	})
	service.now = func() time.Time { return fixedNow }

	dataStore.SaveGateway(&models.Gateway{ID: "gw-1", Name: "Gateway", EnrollmentToken: gatewayTokenHash("old-token"), Status: "enrolled", CertSerial: "serial-1", CertPEM: "cert-1"})
	dataStore.SaveGateway(&models.Gateway{ID: "gw-2", Name: "Delete Gateway", Status: "enrolled", CertSerial: "serial-2", CertPEM: "cert-2"})

	regenerated, err := service.RegenerateEnrollmentToken("gw-1")
	if err != nil {
		t.Fatalf("RegenerateEnrollmentToken returned error: %v", err)
	}
	if len(regenerated.EnrollmentToken) != gatewayEnrollmentTokenBytes*2 || regenerated.Gateway.Status != "pending" {
		t.Fatalf("token was not regenerated correctly: %+v", regenerated)
	}

	revokedGateway, err := service.RevokeGateway("gw-1")
	if err != nil {
		t.Fatalf("RevokeGateway returned error: %v", err)
	}
	if revokedGateway.Status != "revoked" || revokedGateway.EnrollmentToken != "" {
		t.Fatalf("gateway was not revoked: %+v", revokedGateway)
	}
	if len(revoked) != 1 || revoked[0] != "serial-1:gateway:gw-1" {
		t.Fatalf("revocation callback mismatch after revoke: %v", revoked)
	}

	deletedGateway, err := service.DeleteGateway("gw-2")
	if err != nil {
		t.Fatalf("DeleteGateway returned error: %v", err)
	}
	if deletedGateway.ID != "gw-2" {
		t.Fatalf("deleted gateway = %q, want gw-2", deletedGateway.ID)
	}
	if _, found := dataStore.GetGateway("gw-2"); found {
		t.Fatalf("deleted gateway still exists in store")
	}
	if len(revoked) != 2 || revoked[1] != "serial-2:gateway:gw-2" {
		t.Fatalf("revocation callback mismatch after delete: %v", revoked)
	}
}

func newGatewayTestStore(t *testing.T) *store.Store {
	t.Helper()
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = dataStore.Close() })
	return dataStore
}

const gatewayTestTenantID = "tenant-1"

func seedGatewayTenant(dataStore *store.Store) {
	now := time.Now()
	dataStore.SaveTenant(&models.Tenant{
		ID:        gatewayTestTenantID,
		Name:      "Test Tenant",
		Domain:    "example.test",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
}

func newGatewayTestService(t *testing.T, dataStore *store.Store, now time.Time) *Service {
	t.Helper()
	ca := newGatewayTestCA(t)
	service := NewService(dataStore, "gateway-role")
	service.SetCertificateAuthority(ca.sign, nil)
	service.now = func() time.Time { return now }
	return service
}

type gatewayTestCA struct {
	key    *rsa.PrivateKey
	cert   *x509.Certificate
	mu     sync.Mutex
	serial int64
	role   string
}

func newGatewayTestCA(t *testing.T) *gatewayTestCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Gateway CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &gatewayTestCA{key: key, cert: cert, serial: 100}
}

func (ca *gatewayTestCA) sign(csrPEM []byte, validDays int, role string) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	ca.mu.Lock()
	ca.serial++
	serial := ca.serial
	ca.role = role
	ca.mu.Unlock()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		URIs:         csr.URIs,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (ca *gatewayTestCA) lastRole() string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.role
}

func newGatewayCSR(t *testing.T, tenantID, gatewayID, fqdn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	identityURI, err := url.Parse(GatewayIdentityURI(tenantID, gatewayID))
	if err != nil {
		t.Fatalf("parse gateway identity URI: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: gatewayID},
		DNSNames: []string{fqdn},
		URIs:     []*url.URL{identityURI},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
