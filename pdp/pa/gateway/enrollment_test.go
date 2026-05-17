package gateway

import (
	"errors"
	"testing"
	"time"

	"pdp/models"
)

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
		Name:            "Edge Gateway",
		FQDN:            "edge.example.test",
		EnrollmentToken: gatewayTokenHash("token-1"),
		TokenExpiresAt:  fixedNow.Add(time.Hour).Format(time.RFC3339),
		Status:          "pending",
		CreatedAt:       fixedNow.Add(-time.Hour),
		UpdatedAt:       fixedNow.Add(-time.Hour),
	})

	result, err := service.EnrollGateway(models.GatewayEnrollRequest{
		Token:  "token-1",
		CSRPEM: newBareGatewayCSR(t),
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
	cert := parseGatewayTestCertificate(t, []byte(result.Gateway.CertPEM))
	organizationID, gatewayID, ok := GatewayCertificateIdentity(cert)
	if !ok {
		t.Fatal("issued gateway certificate does not contain gateway identity")
	}
	if organizationID != gatewayTestTenantID || gatewayID != "gw-1" {
		t.Fatalf("issued identity = organization=%q gateway=%q", organizationID, gatewayID)
	}
	if !stringSliceContainsFold(cert.DNSNames, "edge.example.test") {
		t.Fatalf("issued DNS SANs = %v, want edge.example.test", cert.DNSNames)
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

func TestServiceEnrollGatewayRejectsCSRRequestedIdentityMismatch(t *testing.T) {
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	dataStore := newGatewayTestStore(t)
	service := newGatewayTestService(t, dataStore, fixedNow)
	dataStore.SaveGateway(&models.Gateway{
		ID:              "gw-1",
		TenantID:        gatewayTestTenantID,
		FQDN:            "edge.example.test",
		EnrollmentToken: gatewayTokenHash("token-1"),
		TokenExpiresAt:  fixedNow.Add(time.Hour).Format(time.RFC3339),
		Status:          "pending",
	})

	_, err := service.EnrollGateway(models.GatewayEnrollRequest{
		Token:  "token-1",
		CSRPEM: newGatewayCSR(t, gatewayTestTenantID, "gw-1", "attacker.example.test"),
	})
	if !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("error = %v, want ErrInvalidCSR", err)
	}
}

func TestServiceEnrollGatewayKeepsTokenWhenSigningFails(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore, "gateway-role")
	service.SetCertificateAuthority(func([]byte, int, string, CertificateProfile) ([]byte, error) {
		return nil, errors.New("sign failed")
	}, nil)
	service.now = func() time.Time { return fixedNow }

	dataStore.SaveGateway(&models.Gateway{
		ID:              "gw-1",
		TenantID:        gatewayTestTenantID,
		TenantIDs:       []string{gatewayTestTenantID},
		Name:            "Edge Gateway",
		FQDN:            "edge.example.test",
		EnrollmentToken: gatewayTokenHash("token-1"),
		TokenExpiresAt:  fixedNow.Add(time.Hour).Format(time.RFC3339),
		Status:          "pending",
		CreatedAt:       fixedNow.Add(-time.Hour),
		UpdatedAt:       fixedNow.Add(-time.Hour),
	})

	_, err := service.EnrollGateway(models.GatewayEnrollRequest{
		Token:  "token-1",
		CSRPEM: newBareGatewayCSR(t),
	})
	if !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("error = %v, want ErrInvalidCSR", err)
	}
	if _, found := dataStore.GetGatewayByToken("token-1"); !found {
		t.Fatal("enrollment token was consumed even though signing failed")
	}
	saved, found := dataStore.GetGateway("gw-1")
	if !found {
		t.Fatal("gateway was not persisted")
	}
	if saved.Status != "pending" {
		t.Fatalf("gateway status = %q, want pending", saved.Status)
	}
}
