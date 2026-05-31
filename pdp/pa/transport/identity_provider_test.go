package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pdp/config"
	"pdp/models"
	"pdp/pa"
	"pdp/store"
)

func TestResolveIdentityProviderUsesTenantLevelConfig(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveTenant(&models.Tenant{ID: "tenant-1", Name: "Tenant 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveTenant(&models.Tenant{ID: "tenant-2", Name: "Tenant 2", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:        "idp-1",
		TenantID:  "tenant-1",
		Name:      "Tenant 1 IdP",
		Type:      "oidc",
		Enabled:   true,
		Domains:   []string{"example.test"},
		Issuer:    "https://idp1.example.test",
		ClientID:  "client-1",
		Scopes:    "openid profile email",
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:        "idp-2",
		TenantID:  "tenant-2",
		Name:      "Tenant 2 IdP",
		Type:      "oidc",
		Enabled:   true,
		Issuer:    "https://idp2.example.test",
		ClientID:  "client-2",
		Scopes:    "openid profile email",
		CreatedAt: now.Add(time.Second),
		UpdatedAt: now.Add(time.Second),
	})
	tenant1, _ := dataStore.GetTenant("tenant-1")
	tenant1.DefaultIdPID = "idp-1"
	dataStore.SaveTenant(tenant1)
	tenant2, _ := dataStore.GetTenant("tenant-2")
	tenant2.DefaultIdPID = "idp-2"
	dataStore.SaveTenant(tenant2)

	server := newIdentityProviderTestServer(dataStore)

	request := httptest.NewRequest(http.MethodGet, "/auth/authorize?organization_id=tenant-2", nil)
	idpCfg, tenant, err := server.resolveIdentityProvider(request, "connect-app")
	if err != nil {
		t.Fatalf("resolveIdentityProvider returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-2" || tenant == nil || tenant.ID != "tenant-2" {
		t.Fatalf("tenant default IdP mismatch: idp=%+v tenant=%+v", idpCfg, tenant)
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize?login_hint=alice@example.test", nil)
	idpCfg, tenant, err = server.resolveIdentityProvider(request, "connect-app")
	if err != nil {
		t.Fatalf("resolveIdentityProvider domain returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-1" || tenant == nil || tenant.ID != "tenant-1" {
		t.Fatalf("domain IdP mismatch: idp=%+v tenant=%+v", idpCfg, tenant)
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize?organization_id=tenant-2&login_hint=alice@example.test", nil)
	if _, _, err = server.resolveIdentityProvider(request, "connect-app"); err == nil {
		t.Fatalf("expected tenant/login_hint mismatch to be rejected")
	}
}

func TestResolveIdentityProviderUsesTenantDomainForDefaultIdP(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveTenant(&models.Tenant{
		ID:        "tenant-1",
		Name:      "Tenant 1",
		Domain:    "company-a.test",
		Domains:   []string{"branch.company-a.test"},
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:        "idp-1",
		TenantID:  "tenant-1",
		Name:      "Tenant 1 IdP",
		Type:      "oidc",
		Enabled:   true,
		Issuer:    "https://idp1.example.test",
		ClientID:  "client-1",
		Scopes:    "openid profile email",
		CreatedAt: now,
		UpdatedAt: now,
	})
	tenant, _ := dataStore.GetTenant("tenant-1")
	tenant.DefaultIdPID = "idp-1"
	dataStore.SaveTenant(tenant)

	server := newIdentityProviderTestServer(dataStore)

	request := httptest.NewRequest(http.MethodGet, "/auth/authorize?login_hint=alice@company-a.test", nil)
	idpCfg, resolvedTenant, err := server.resolveIdentityProvider(request, "connect-app")
	if err != nil {
		t.Fatalf("resolveIdentityProvider primary domain returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-1" || resolvedTenant == nil || resolvedTenant.ID != "tenant-1" {
		t.Fatalf("tenant primary domain mismatch: idp=%+v tenant=%+v", idpCfg, resolvedTenant)
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize?login_hint=bob@branch.company-a.test", nil)
	idpCfg, resolvedTenant, err = server.resolveIdentityProvider(request, "connect-app")
	if err != nil {
		t.Fatalf("resolveIdentityProvider domain alias returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-1" || resolvedTenant == nil || resolvedTenant.ID != "tenant-1" {
		t.Fatalf("tenant alias domain mismatch: idp=%+v tenant=%+v", idpCfg, resolvedTenant)
	}
}

func TestAdminIdentityProvidersAllowOnePerTenant(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveTenant(&models.Tenant{ID: "tenant-1", Name: "Tenant 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveTenant(&models.Tenant{ID: "tenant-2", Name: "Tenant 2", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveOrganizationMembership(&models.OrganizationMembership{UserID: "admin-1", OrganizationID: "tenant-1", Role: "platform_admin", CreatedAt: now})
	dataStore.SaveOrganizationMembership(&models.OrganizationMembership{UserID: "admin-1", OrganizationID: "tenant-2", Role: "platform_admin", CreatedAt: now})
	server := newIdentityProviderTestServer(dataStore)

	body := `{"id":"idp-1","name":"IdP 1","issuer":"https://idp1.example.test","client_id":"client-1"}`
	recorder := httptest.NewRecorder()
	request := authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=tenant-1", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("first IdP status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	body = `{"id":"idp-2","name":"IdP 2","issuer":"https://idp2.example.test","client_id":"client-2","is_default":true}`
	recorder = httptest.NewRecorder()
	request = authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=tenant-1", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("second IdP status = %d, want %d, body=%s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}

	cfgs := dataStore.ListIdentityProviderConfigsForTenant("tenant-1")
	if len(cfgs) != 1 {
		t.Fatalf("IdP count = %d, want 1", len(cfgs))
	}
	tenant, _ := dataStore.GetTenant("tenant-1")
	if tenant.DefaultIdPID != "idp-1" {
		t.Fatalf("default IdP = %q, want idp-1", tenant.DefaultIdPID)
	}

	body = `{"id":"idp-2","name":"IdP 2","issuer":"https://idp2.example.test","client_id":"client-2"}`
	recorder = httptest.NewRecorder()
	request = authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=tenant-2", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("second tenant IdP status = %d, body=%s", recorder.Code, recorder.Body.String())
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
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = dataStore.Close() })
	return dataStore
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
