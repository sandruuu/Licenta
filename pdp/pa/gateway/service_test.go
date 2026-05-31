package gateway

import (
	"errors"
	"testing"
	"time"

	"pdp/models"
)

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
	})
	if err != nil {
		t.Fatalf("CreateGateway returned error: %v", err)
	}
	if result.Gateway.ID == "" || len(result.EnrollmentToken) != gatewayEnrollmentTokenBytes*2 {
		t.Fatalf("gateway credentials were not generated: id=%q token=%q", result.Gateway.ID, result.EnrollmentToken)
	}
	if result.Gateway.AuthMode != "builtin" || result.Gateway.FederationConfig != nil {
		t.Fatalf("gateway should use tenant-level IdP configuration only: auth=%q federation=%+v", result.Gateway.AuthMode, result.Gateway.FederationConfig)
	}

	items, err := service.ListGatewaySummaries()
	if err != nil {
		t.Fatalf("ListGatewaySummaries returned error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("list length = %d, want 1", len(items))
	}
	if items[0].AuthMode != "builtin" || items[0].FederationConfig != nil {
		t.Fatalf("list should not expose gateway federation config: auth=%q federation=%+v", items[0].AuthMode, items[0].FederationConfig)
	}
	// EnrollmentToken is intentionally zeroed in gatewayListItem for defense-in-depth.
	// The plaintext token is only returned at creation time (CreateGatewayResult).
	if items[0].EnrollmentToken != "" {
		t.Fatalf("list enrollment token should be empty (sanitized), got %q", items[0].EnrollmentToken)
	}

	result.Gateway.CertPEM = "cert-pem"
	result.Gateway.OIDCClientSecret = "oidc-secret"
	result.Gateway.FederationConfig = &models.FederationConfig{Issuer: "https://legacy-idp.example.test", ClientID: "legacy", ClientSecret: "secret"}
	dataStore.SaveGateway(result.Gateway)
	detail, err := service.GetGatewayForAdmin(result.Gateway.ID)
	if err != nil {
		t.Fatalf("GetGatewayForAdmin returned error: %v", err)
	}
	if detail.CertPEM != "" || detail.OIDCClientSecret != "" || detail.FederationConfig != nil || detail.AuthMode != "builtin" {
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
		t.Fatalf("federated auth mode error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateGateway(CreateGatewayRequest{
		Name:     "Edge",
		TenantID: gatewayTestTenantID,
		FederationConfig: &models.FederationConfig{
			Issuer:   "https://idp.example.test",
			ClientID: "client-1",
		},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("gateway federation config error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateGateway(CreateGatewayRequest{Name: "Edge"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing tenant error = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceUpdateGatewayRejectsFederationConfigAndCanClearLegacyFederation(t *testing.T) {
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

	_, err := service.UpdateGateway("gw-1", UpdateGatewayRequest{
		FederationConfig: &models.FederationConfig{
			Issuer:   "https://new-idp.example.test",
			ClientID: "new-client",
		},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("gateway federation config update error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.UpdateGateway("gw-1", UpdateGatewayRequest{AuthMode: "federated"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("gateway federated auth update error = %v, want ErrInvalidRequest", err)
	}

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
	if updated.FederationConfig == nil || updated.FederationConfig.ClientSecret != "secret-1" {
		t.Fatalf("legacy federation config should be preserved on unrelated updates: %+v", updated.FederationConfig)
	}

	detail, err := service.GetGatewayForAdmin("gw-1")
	if err != nil {
		t.Fatalf("GetGatewayForAdmin returned error: %v", err)
	}
	if detail.AuthMode != "builtin" || detail.FederationConfig != nil {
		t.Fatalf("admin view should hide legacy federation config: auth=%q federation=%+v", detail.AuthMode, detail.FederationConfig)
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

	dataStore.SaveGateway(&models.Gateway{
		ID: "gw-1", Name: "Gateway", EnrollmentToken: gatewayTokenHash("old-token"), TokenExpiresAt: "2025-01-02T04:04:05Z",
		Status: "enrolled", CertSerial: "serial-1", CertPEM: "cert-1", CertFingerprint: "fingerprint-1", CertExpiresAt: "2025-01-09T03:04:05Z",
	})
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
