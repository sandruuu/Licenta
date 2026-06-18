package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pdp/models"
)

func TestHRDRequiresExplicitDomainOrOrganizationContext(t *testing.T) {
	server := newHRDResolutionTestServer(t, "demo.trustcloud.test", []string{"demo.trustcloud.test"})

	request := httptest.NewRequest(http.MethodGet, "/auth/authorize?login_hint=user@unknown.test", nil)
	if _, _, err := server.resolveIdentityProvider(request, "trustagent-endpoint"); err == nil {
		t.Fatalf("expected unknown login_hint domain to be rejected")
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
	idpCfg, organization, err := server.resolveIdentityProvider(request, "trustagent-endpoint")
	if err != nil {
		t.Fatalf("resolveIdentityProvider without login_hint returned error: %v", err)
	}
	if idpCfg != nil || organization != nil {
		t.Fatalf("implicit HRD resolution should not select an IdP: idp=%+v organization=%+v", idpCfg, organization)
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize?organization_id=organization-1", nil)
	idpCfg, organization, err = server.resolveIdentityProvider(request, "trustagent-endpoint")
	if err != nil {
		t.Fatalf("resolveIdentityProvider with organization_id returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-1" || organization == nil || organization.ID != "organization-1" {
		t.Fatalf("organization HRD mismatch: idp=%+v organization=%+v", idpCfg, organization)
	}
}

func TestEnrollmentHRDRequiresEmailDomain(t *testing.T) {
	server := newHRDResolutionTestServer(t, "demo.trustcloud.test", []string{"demo.trustcloud.test"})

	if idpCfg, organization, ok := server.resolveEnrollmentIdentityProvider("user@unknown.test"); ok {
		t.Fatalf("unknown enrollment email resolved unexpectedly: idp=%+v organization=%+v", idpCfg, organization)
	}

	if idpCfg, organization, ok := server.resolveEnrollmentIdentityProvider(""); ok {
		t.Fatalf("empty enrollment email resolved unexpectedly: idp=%+v organization=%+v", idpCfg, organization)
	}

	idpCfg, organization, ok := server.resolveEnrollmentIdentityProvider("user@demo.trustcloud.test")
	if !ok || idpCfg == nil || idpCfg.ID != "idp-1" || organization == nil || organization.ID != "organization-1" {
		t.Fatalf("domain enrollment HRD mismatch: ok=%v idp=%+v organization=%+v", ok, idpCfg, organization)
	}
}

func TestAgentSessionHRDUsesDeviceOrganizationContext(t *testing.T) {
	server := newHRDResolutionTestServer(t, "demo.trustcloud.test", nil)

	if idpCfg, ok := server.resolveAgentSessionIdentityProvider("organization-1", "user@unknown.test"); ok {
		t.Fatalf("unknown agent-session email resolved unexpectedly: idp=%+v", idpCfg)
	}

	idpCfg, ok := server.resolveAgentSessionIdentityProvider("organization-1", "user@demo.trustcloud.test")
	if !ok || idpCfg == nil || idpCfg.ID != "idp-1" {
		t.Fatalf("organization-domain agent-session HRD mismatch: ok=%v idp=%+v", ok, idpCfg)
	}
}

func newHRDResolutionTestServer(t *testing.T, organizationDomain string, idpDomains []string) *Server {
	t.Helper()
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveOrganization(&models.Organization{
		ID:           "organization-1",
		Name:         "Organization 1",
		Domain:       organizationDomain,
		Enabled:      true,
		DefaultIdPID: "idp-1",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:             "idp-1",
		OrganizationID: "organization-1",
		Name:           "Organization 1 IdP",
		Type:           "oidc",
		Enabled:        true,
		Domains:        idpDomains,
		Issuer:         "https://idp1.example.test",
		ClientID:       "client-1",
		Scopes:         "openid profile email",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	return newIdentityProviderTestServer(dataStore)
}
