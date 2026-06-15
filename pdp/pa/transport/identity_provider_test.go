package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pdp/config"
	"pdp/internal/testdb"
	"pdp/models"
	"pdp/pa"
	"pdp/store"
)

func TestResolveIdentityProviderUsesOrganizationLevelConfig(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveOrganization(&models.Organization{ID: "organization-1", Name: "Organization 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveOrganization(&models.Organization{ID: "organization-2", Name: "Organization 2", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:             "idp-1",
		OrganizationID: "organization-1",
		Name:           "Organization 1 IdP",
		Type:           "oidc",
		Enabled:        true,
		Domains:        []string{"example.test"},
		Issuer:         "https://idp1.example.test",
		ClientID:       "client-1",
		Scopes:         "openid profile email",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:             "idp-2",
		OrganizationID: "organization-2",
		Name:           "Organization 2 IdP",
		Type:           "oidc",
		Enabled:        true,
		Issuer:         "https://idp2.example.test",
		ClientID:       "client-2",
		Scopes:         "openid profile email",
		CreatedAt:      now.Add(time.Second),
		UpdatedAt:      now.Add(time.Second),
	})
	organization1, _ := dataStore.GetOrganization("organization-1")
	organization1.DefaultIdPID = "idp-1"
	dataStore.SaveOrganization(organization1)
	organization2, _ := dataStore.GetOrganization("organization-2")
	organization2.DefaultIdPID = "idp-2"
	dataStore.SaveOrganization(organization2)

	server := newIdentityProviderTestServer(dataStore)

	request := httptest.NewRequest(http.MethodGet, "/auth/authorize?organization_id=organization-2", nil)
	idpCfg, organization, err := server.resolveIdentityProvider(request, "trustagent-endpoint")
	if err != nil {
		t.Fatalf("resolveIdentityProvider returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-2" || organization == nil || organization.ID != "organization-2" {
		t.Fatalf("organization default IdP mismatch: idp=%+v organization=%+v", idpCfg, organization)
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize?login_hint=alice@example.test", nil)
	idpCfg, organization, err = server.resolveIdentityProvider(request, "trustagent-endpoint")
	if err != nil {
		t.Fatalf("resolveIdentityProvider domain returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-1" || organization == nil || organization.ID != "organization-1" {
		t.Fatalf("domain IdP mismatch: idp=%+v organization=%+v", idpCfg, organization)
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize?organization_id=organization-2&login_hint=alice@example.test", nil)
	if _, _, err = server.resolveIdentityProvider(request, "trustagent-endpoint"); err == nil {
		t.Fatalf("expected organization/login_hint mismatch to be rejected")
	}
}

func TestResolveIdentityProviderUsesOrganizationDomainForDefaultIdP(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveOrganization(&models.Organization{
		ID:        "organization-1",
		Name:      "Organization 1",
		Domain:    "company-a.test",
		Domains:   []string{"branch.company-a.test"},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:             "idp-1",
		OrganizationID: "organization-1",
		Name:           "Organization 1 IdP",
		Type:           "oidc",
		Enabled:        true,
		Issuer:         "https://idp1.example.test",
		ClientID:       "client-1",
		Scopes:         "openid profile email",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	organization, _ := dataStore.GetOrganization("organization-1")
	organization.DefaultIdPID = "idp-1"
	dataStore.SaveOrganization(organization)

	server := newIdentityProviderTestServer(dataStore)

	request := httptest.NewRequest(http.MethodGet, "/auth/authorize?login_hint=alice@company-a.test", nil)
	idpCfg, resolvedOrganization, err := server.resolveIdentityProvider(request, "trustagent-endpoint")
	if err != nil {
		t.Fatalf("resolveIdentityProvider primary domain returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-1" || resolvedOrganization == nil || resolvedOrganization.ID != "organization-1" {
		t.Fatalf("organization primary domain mismatch: idp=%+v organization=%+v", idpCfg, resolvedOrganization)
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize?login_hint=bob@branch.company-a.test", nil)
	idpCfg, resolvedOrganization, err = server.resolveIdentityProvider(request, "trustagent-endpoint")
	if err != nil {
		t.Fatalf("resolveIdentityProvider domain alias returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-1" || resolvedOrganization == nil || resolvedOrganization.ID != "organization-1" {
		t.Fatalf("organization alias domain mismatch: idp=%+v organization=%+v", idpCfg, resolvedOrganization)
	}
}

func TestAdminIdentityProvidersAllowOnePerOrganization(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveOrganization(&models.Organization{ID: "organization-1", Name: "Organization 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveOrganization(&models.Organization{ID: "organization-2", Name: "Organization 2", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveOrganizationMembership(&models.OrganizationMembership{UserID: "admin-1", OrganizationID: "organization-1", Role: "platform_admin", CreatedAt: now})
	dataStore.SaveOrganizationMembership(&models.OrganizationMembership{UserID: "admin-1", OrganizationID: "organization-2", Role: "platform_admin", CreatedAt: now})
	server := newIdentityProviderTestServer(dataStore)

	body := `{"id":"idp-1","name":"IdP 1","issuer":"https://idp1.example.test","client_id":"client-1"}`
	recorder := httptest.NewRecorder()
	request := authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=organization-1", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("first IdP status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	body = `{"id":"idp-2","name":"IdP 2","issuer":"https://idp2.example.test","client_id":"client-2","is_default":true}`
	recorder = httptest.NewRecorder()
	request = authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=organization-1", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("second IdP status = %d, want %d, body=%s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}

	cfgs := dataStore.ListIdentityProviderConfigsForOrganization("organization-1")
	if len(cfgs) != 1 {
		t.Fatalf("IdP count = %d, want 1", len(cfgs))
	}
	organization, _ := dataStore.GetOrganization("organization-1")
	if organization.DefaultIdPID != "idp-1" {
		t.Fatalf("default IdP = %q, want idp-1", organization.DefaultIdPID)
	}

	body = `{"id":"idp-2","name":"IdP 2","issuer":"https://idp2.example.test","client_id":"client-2"}`
	recorder = httptest.NewRecorder()
	request = authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=organization-2", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("second organization IdP status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func authorizedIdentityProviderRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("X-User-ID", "admin-1")
	request.Header.Set("X-Username", "admin@example.test")
	request.Header.Set("X-User-Role", "platform_admin")
	return request
}

func newIdentityProviderTestStore(t *testing.T) *store.Store {
	t.Helper()
	return testdb.NewStore(t)
}

func newIdentityProviderTestServer(dataStore *store.Store) *Server {
	return &Server{
		pa: &pa.PolicyAdministrator{
			Store: dataStore,
			Cfg: &config.Config{
				Public: config.PublicDashboardConfig{
					OIDCDefaultScopes: "openid profile email",
					OIDCDefaultClaimMapping: map[string]string{
						"username": "preferred_username",
						"email":    "email",
						"groups":   "groups",
					},
				},
			},
		},
	}
}
