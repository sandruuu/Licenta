package gateway

import (
	"errors"
	"testing"
	"time"

	"pdp/models"
)

func TestServiceCreateListAndGetGatewayForAdmin(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	seedGatewayOrganization(dataStore)
	dataStore.SaveResource(&models.Resource{ID: "res-1", OrganizationID: gatewayTestOrganizationID, Name: "SSH", Type: "ssh", ExternalPort: 22, InternalPort: 22, Enabled: true})
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore, "gateway-role")
	service.now = func() time.Time { return fixedNow }

	result, err := service.CreateGateway(CreateGatewayRequest{
		OrganizationID:    gatewayTestOrganizationID,
		Name:              "Edge Gateway",
		FQDN:              "edge.example.test",
		AssignedResources: []string{"res-1"},
	})
	if err != nil {
		t.Fatalf("CreateGateway returned error: %v", err)
	}
	if result.Gateway.ID == "" || len(result.EnrollmentToken) != gatewayEnrollmentTokenBytes*2 {
		t.Fatalf("gateway credentials were not generated: id=%q token=%q", result.Gateway.ID, result.EnrollmentToken)
	}

	items, err := service.ListGatewaySummaries()
	if err != nil {
		t.Fatalf("ListGatewaySummaries returned error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("list length = %d, want 1", len(items))
	}
	// EnrollmentToken is intentionally zeroed in gatewayListItem for defense-in-depth.
	// The plaintext token is only returned at creation time (CreateGatewayResult).
	if items[0].EnrollmentToken != "" {
		t.Fatalf("list enrollment token should be empty (sanitized), got %q", items[0].EnrollmentToken)
	}

	result.Gateway.CertPEM = "cert-pem"
	dataStore.SaveGateway(result.Gateway)
	detail, err := service.GetGatewayForAdmin(result.Gateway.ID)
	if err != nil {
		t.Fatalf("GetGatewayForAdmin returned error: %v", err)
	}
	if detail.CertPEM != "" {
		t.Fatalf("admin detail was not sanitized: cert=%q", detail.CertPEM)
	}
}

func TestServiceCreateGatewayValidatesAdminRequest(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	seedGatewayOrganization(dataStore)
	service := NewService(dataStore, "gateway-role")

	_, err := service.CreateGateway(CreateGatewayRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty request error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateGateway(CreateGatewayRequest{Name: "Edge"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing organization error = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceUpdateGatewayPatchesFields(t *testing.T) {
	dataStore := newGatewayTestStore(t)
	seedGatewayOrganization(dataStore)
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore, "gateway-role")
	service.now = func() time.Time { return fixedNow }
	dataStore.SaveResource(&models.Resource{ID: "res-1", OrganizationID: gatewayTestOrganizationID, Name: "SSH", Type: "ssh", ExternalPort: 22, InternalPort: 22, Enabled: true})
	dataStore.SaveResource(&models.Resource{ID: "res-2", OrganizationID: gatewayTestOrganizationID, Name: "RDP", Type: "rdp", ExternalPort: 3389, InternalPort: 3389, Enabled: true})
	dataStore.SaveGateway(&models.Gateway{
		ID:              "gw-1",
		OrganizationID:  gatewayTestOrganizationID,
		OrganizationIDs: []string{gatewayTestOrganizationID},
		Name:            "Old Gateway",
		FQDN:            "old.example.test",
		Status:          "pending",
		CreatedAt:       fixedNow.Add(-time.Hour),
		UpdatedAt:       fixedNow.Add(-time.Hour),
	})

	updated, err := service.UpdateGateway("gw-1", UpdateGatewayRequest{
		Name:              "New Gateway",
		FQDN:              "new.example.test",
		AssignedResources: []string{"res-1", "res-2"},
	})
	if err != nil {
		t.Fatalf("UpdateGateway returned error: %v", err)
	}
	if updated.Name != "New Gateway" || updated.FQDN != "new.example.test" || len(updated.AssignedResources) != 2 {
		t.Fatalf("gateway fields not updated: %+v", updated)
	}

	detail, err := service.GetGatewayForAdmin("gw-1")
	if err != nil {
		t.Fatalf("GetGatewayForAdmin returned error: %v", err)
	}
	if detail.CertPEM != "" {
		t.Fatalf("admin view should hide certificate PEM")
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

	dataStore.SaveGateway(&models.Gateway{
		ID: "gw-1", Name: "Gateway", EnrollmentToken: gatewayTokenHash("old-token"), TokenExpiresAt: "2025-01-02T04:04:05Z",
		Status: "enrolled", CertSerial: "serial-1", CertPEM: "cert-1", CertFingerprint: "fingerprint-1", CertExpiresAt: "2025-01-09T03:04:05Z",
	})
	dataStore.SaveGateway(&models.Gateway{ID: "gw-2", Name: "Delete Gateway", Status: "enrolled", CertSerial: "serial-2", CertPEM: "cert-2"})
	dataStore.SaveGateway(&models.Gateway{ID: "gw-3", Name: "Pending Gateway", Status: "pending", EnrollmentToken: gatewayTokenHash("old-pending-token"), TokenExpiresAt: "2025-01-02T04:04:05Z"})

	if _, err := service.RegenerateEnrollmentToken("gw-1"); !errors.Is(err, ErrGatewayAlreadyEnrolled) {
		t.Fatalf("RegenerateEnrollmentToken enrolled gateway error = %v, want ErrGatewayAlreadyEnrolled", err)
	}

	regenerated, err := service.RegenerateEnrollmentToken("gw-3")
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
	if revokedGateway.Status != "revoked" || revokedGateway.EnrollmentToken != "" || revokedGateway.TokenExpiresAt != "" {
		t.Fatalf("gateway was not revoked: %+v", revokedGateway)
	}
	if revokedGateway.CertSerial != "" || revokedGateway.CertPEM != "" || revokedGateway.CertFingerprint != "" || revokedGateway.CertExpiresAt != "" {
		t.Fatalf("gateway certificate metadata was not invalidated: %+v", revokedGateway)
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
