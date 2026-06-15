package gateway

import (
	"errors"
	"testing"
	"time"

	"pdp/models"
)

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

	oldCertPEM, err := ca.sign([]byte(newGatewayCSR(t, gatewayTestOrganizationID, "gw-1", "edge.example.test")), 7, "gateway-role", CertificateProfile{
		CommonName: "edge.example.test",
		DNSNames:   []string{"edge.example.test"},
		URISANs:    []string{GatewayIdentityURI(gatewayTestOrganizationID, "gw-1")},
	})
	if err != nil {
		t.Fatalf("sign old certificate: %v", err)
	}
	_, oldSerial := certificateIdentity(oldCertPEM)
	gateway := &models.Gateway{
		ID:              "gw-1",
		OrganizationID:  gatewayTestOrganizationID,
		OrganizationIDs: []string{gatewayTestOrganizationID},
		Name:            "Edge Gateway",
		FQDN:            "edge.example.test",
		Status:          "enrolled",
		CertPEM:         string(oldCertPEM),
		CertSerial:      oldSerial,
		CertExpiresAt:   fixedNow.Add(2 * time.Hour).Format(time.RFC3339),
		CreatedAt:       fixedNow.Add(-time.Hour),
		UpdatedAt:       fixedNow.Add(-time.Hour),
	}
	dataStore.SaveGateway(gateway)

	result, err := service.RenewGatewayCertificate(gateway, newGatewayCSR(t, gatewayTestOrganizationID, "gw-1", "edge.example.test"))
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
	gateway := &models.Gateway{ID: "gw-1", OrganizationID: gatewayTestOrganizationID, FQDN: "edge.example.test", Status: "enrolled"}

	_, err := service.RenewGatewayCertificate(gateway, newGatewayCSR(t, gatewayTestOrganizationID, "gw-other", "edge.example.test"))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("error = %v, want ErrForbidden", err)
	}

	_, err = service.RenewGatewayCertificate(gateway, "not a csr")
	if !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("error = %v, want ErrInvalidCSR", err)
	}
}
