package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pdp/config"
	"pdp/internal/testdb"
	"pdp/models"
	"pdp/pa"
	"pdp/pa/audit"
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
		ClientSecret:   "secret-1",
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
		ClientSecret:   "secret-2",
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
		ClientSecret:   "secret-1",
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

func TestResolveIdentityProviderRequiresExplicitOrganizationContext(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveOrganization(&models.Organization{
		ID:        "organization-1",
		Name:      "Organization 1",
		Domain:    "company-a.test",
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
		ClientSecret:   "secret-1",
		Scopes:         "openid profile email",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	organization, _ := dataStore.GetOrganization("organization-1")
	organization.DefaultIdPID = "idp-1"
	dataStore.SaveOrganization(organization)

	server := newIdentityProviderTestServer(dataStore)
	request := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
	idpCfg, resolvedOrganization, err := server.resolveIdentityProvider(request, "trustagent-endpoint")
	if err != nil {
		t.Fatalf("resolveIdentityProvider returned error: %v", err)
	}
	if idpCfg != nil || resolvedOrganization != nil {
		t.Fatalf("implicit IdP selection should not resolve: idp=%+v organization=%+v", idpCfg, resolvedOrganization)
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

	body := `{"id":"idp-1","name":"IdP 1","issuer":"https://idp1.example.test","client_id":"client-1","client_secret":"secret-1"}`
	recorder := httptest.NewRecorder()
	request := authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=organization-1", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("first IdP status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	body = `{"id":"idp-2","name":"IdP 2","issuer":"https://idp2.example.test","client_id":"client-2","client_secret":"secret-2","is_default":true}`
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

	body = `{"id":"idp-2","name":"IdP 2","issuer":"https://idp2.example.test","client_id":"client-2","client_secret":"secret-2"}`
	recorder = httptest.NewRecorder()
	request = authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=organization-2", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("second organization IdP status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAdminIdentityProviderRequiresClientSecret(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveOrganization(&models.Organization{ID: "organization-1", Name: "Organization 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveOrganizationMembership(&models.OrganizationMembership{UserID: "admin-1", OrganizationID: "organization-1", Role: "platform_admin", CreatedAt: now})
	server := newIdentityProviderTestServer(dataStore)

	body := `{"id":"idp-1","name":"IdP 1","issuer":"https://idp1.example.test","client_id":"client-1"}`
	recorder := httptest.NewRecorder()
	request := authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=organization-1", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create IdP without client_secret status = %d, want %d, body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func TestAdminIdentityProviderSCIMTokenGetsExpiryRotationAndAudit(t *testing.T) {
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now().UTC()
	dataStore.SaveOrganization(&models.Organization{ID: "organization-1", Name: "Organization 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveOrganizationMembership(&models.OrganizationMembership{UserID: "admin-1", OrganizationID: "organization-1", Role: "platform_admin", CreatedAt: now})
	server := newIdentityProviderTestServer(dataStore)

	body := `{"id":"idp-1","name":"IdP 1","issuer":"https://idp1.example.test","client_id":"client-1","client_secret":"secret-1"}`
	recorder := httptest.NewRecorder()
	request := authorizedIdentityProviderRequest(http.MethodPost, "/api/admin/organizations/idps?organization_id=organization-1", body)
	server.handleAdminIdentityProviders(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create IdP status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	created := decodeIdentityProviderAPIResponse(t, recorder)
	firstToken := stringField(created, "scim_token")
	if firstToken == "" {
		t.Fatalf("create response did not include the one-time SCIM token")
	}
	cfg, found := dataStore.GetIdentityProviderConfig("idp-1")
	if !found {
		t.Fatalf("created IdP not found")
	}
	if cfg.SCIMTokenExpiresAt.IsZero() || !cfg.SCIMTokenExpiresAt.After(now) {
		t.Fatalf("SCIM token expiry = %v, want future timestamp", cfg.SCIMTokenExpiresAt)
	}
	if cfg.SCIMTokenRotatedAt.IsZero() || cfg.SCIMTokenRotatedAt.Before(now.Add(-time.Second)) {
		t.Fatalf("SCIM token rotation timestamp = %v, want current timestamp", cfg.SCIMTokenRotatedAt)
	}

	recorder = httptest.NewRecorder()
	request = authorizedIdentityProviderRequest(http.MethodPut, "/api/admin/organizations/idps/idp-1", `{"regenerate_scim_token":true}`)
	server.handleAdminIdentityProviderByID(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("regenerate IdP status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	updatedData := decodeIdentityProviderAPIResponse(t, recorder)
	secondToken := stringField(updatedData, "scim_token")
	if secondToken == "" {
		t.Fatalf("regenerate response did not include the new SCIM token")
	}
	if secondToken == firstToken {
		t.Fatalf("regenerated SCIM token should differ from original token")
	}
	updated, found := dataStore.GetIdentityProviderConfig("idp-1")
	if !found {
		t.Fatalf("updated IdP not found")
	}
	if updated.SCIMTokenExpiresAt.IsZero() || !updated.SCIMTokenExpiresAt.After(now) {
		t.Fatalf("regenerated SCIM token expiry = %v, want future timestamp", updated.SCIMTokenExpiresAt)
	}

	entries := dataStore.GetAuditLog(10)
	if !hasAuditEvent(entries, "scim_token_created") {
		t.Fatalf("audit log missing scim_token_created event: %+v", entries)
	}
	if !hasAuditEvent(entries, "scim_token_rotated") {
		t.Fatalf("audit log missing scim_token_rotated event: %+v", entries)
	}
}

func decodeIdentityProviderAPIResponse(t *testing.T, recorder *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode API response: %v", err)
	}
	if response.Data == nil {
		t.Fatalf("API response did not include data: %s", recorder.Body.String())
	}
	return response.Data
}

func stringField(data map[string]interface{}, key string) string {
	value, _ := data[key].(string)
	return value
}

func hasAuditEvent(entries []*models.AuditEntry, eventType string) bool {
	for _, entry := range entries {
		if entry != nil && entry.EventType == eventType {
			return true
		}
	}
	return false
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
			Audit: audit.NewAuditLogger(dataStore),
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
