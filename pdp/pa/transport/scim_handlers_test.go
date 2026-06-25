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
	"pdp/store"
)

func TestSCIMProvisioningCreatesUsersGroupsAndMemberships(t *testing.T) {
	dataStore := newSCIMTestStore(t)
	server := newSCIMTestServer(dataStore)

	userBody := `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"externalId":"u-1",
		"userName":"alice@example.test",
		"displayName":"Alice Example",
		"active":true,
		"emails":[{"value":"alice@example.test","primary":true}]
	}`
	recorder := performSCIMRequest(server, http.MethodPost, "/scim/v2/organization-1/Users", userBody, "scim-secret")
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST user status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var userResp scimUserResource
	if err := json.Unmarshal(recorder.Body.Bytes(), &userResp); err != nil {
		t.Fatalf("decode user response: %v", err)
	}
	if userResp.ID == "" {
		t.Fatalf("SCIM user response did not include an id")
	}

	groupBody := `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"externalId":"g-1",
		"displayName":"Finance",
		"members":[{"value":"` + userResp.ID + `","display":"Alice Example"}]
	}`
	recorder = performSCIMRequest(server, http.MethodPost, "/scim/v2/organization-1/Groups", groupBody, "scim-secret")
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST group status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var groupResp scimGroupResource
	if err := json.Unmarshal(recorder.Body.Bytes(), &groupResp); err != nil {
		t.Fatalf("decode group response: %v", err)
	}
	if groupResp.ID == "" || len(groupResp.Members) != 1 || groupResp.Members[0].Value != userResp.ID {
		t.Fatalf("group response mismatch: %+v", groupResp)
	}

	members := dataStore.ListDirectoryGroupMembers("organization-1", "idp-1", groupResp.ID)
	if len(members) != 1 || members[0].UserID != userResp.ID {
		t.Fatalf("stored members = %+v, want user %s", members, userResp.ID)
	}

	recorder = performSCIMRequest(server, http.MethodGet, `/scim/v2/organization-1/Groups?filter=displayName%20eq%20%22Finance%22`, "", "scim-secret")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET groups status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var list scimListResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if list.TotalResults != 1 || len(list.Resources) != 1 {
		t.Fatalf("list response = %+v, want one group", list)
	}
}

func TestSCIMRejectsInvalidBearerToken(t *testing.T) {
	dataStore := newSCIMTestStore(t)
	server := newSCIMTestServer(dataStore)

	recorder := performSCIMRequest(server, http.MethodGet, "/scim/v2/organization-1/Users", "", "wrong-token")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
}

func TestSCIMRejectsExpiredBearerToken(t *testing.T) {
	dataStore := newSCIMTestStore(t)
	cfgs := dataStore.ListIdentityProviderConfigsForOrganization("organization-1")
	if len(cfgs) != 1 {
		t.Fatalf("IdP count = %d, want 1", len(cfgs))
	}
	cfgs[0].SCIMTokenExpiresAt = time.Now().UTC().Add(-time.Minute)
	dataStore.SaveIdentityProviderConfig(cfgs[0])
	server := newSCIMTestServer(dataStore)

	recorder := performSCIMRequest(server, http.MethodGet, "/scim/v2/organization-1/Users", "", "scim-secret")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "expired") {
		t.Fatalf("response body = %s, want expired token message", recorder.Body.String())
	}
}

func TestSCIMRejectsBearerTokenWithoutExpiry(t *testing.T) {
	dataStore := newSCIMTestStore(t)
	cfgs := dataStore.ListIdentityProviderConfigsForOrganization("organization-1")
	if len(cfgs) != 1 {
		t.Fatalf("IdP count = %d, want 1", len(cfgs))
	}
	cfgs[0].SCIMTokenExpiresAt = time.Time{}
	dataStore.SaveIdentityProviderConfig(cfgs[0])
	server := newSCIMTestServer(dataStore)

	recorder := performSCIMRequest(server, http.MethodGet, "/scim/v2/organization-1/Users", "", "scim-secret")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "expired") {
		t.Fatalf("response body = %s, want expired token message", recorder.Body.String())
	}
}

func TestSCIMRejectsUnknownUserFilter(t *testing.T) {
	dataStore := newSCIMTestStore(t)
	now := time.Now().UTC()
	dataStore.SaveDirectoryUser(&models.DirectoryUser{
		ID:             "dirusr-1",
		OrganizationID: "organization-1",
		IdPID:          "idp-1",
		UserName:       "alice@example.test",
		Email:          "alice@example.test",
		Active:         true,
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	server := newSCIMTestServer(dataStore)

	recorder := performSCIMRequest(server, http.MethodGet, `/scim/v2/organization-1/Users?filter=unknown%20eq%20%22alice%22`, "", "scim-secret")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalidFilter") {
		t.Fatalf("response body = %s, want invalidFilter", recorder.Body.String())
	}
}

func TestSCIMRejectsUnknownGroupFilter(t *testing.T) {
	dataStore := newSCIMTestStore(t)
	now := time.Now().UTC()
	dataStore.SaveDirectoryGroup(&models.DirectoryGroup{
		ID:             "dirgrp-1",
		OrganizationID: "organization-1",
		IdPID:          "idp-1",
		DisplayName:    "Engineering",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	server := newSCIMTestServer(dataStore)

	recorder := performSCIMRequest(server, http.MethodGet, `/scim/v2/organization-1/Groups?filter=unknown%20eq%20%22Engineering%22`, "", "scim-secret")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalidFilter") {
		t.Fatalf("response body = %s, want invalidFilter", recorder.Body.String())
	}
}

func newSCIMTestStore(t *testing.T) *store.Store {
	t.Helper()
	dataStore := testdb.NewStore(t)

	now := time.Now().UTC()
	dataStore.SaveOrganization(&models.Organization{ID: "organization-1", Name: "Organization 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:                 "idp-1",
		OrganizationID:     "organization-1",
		Name:               "Organization 1 IdP",
		Type:               "oidc",
		Enabled:            true,
		Issuer:             "https://idp.example.test",
		ClientID:           "client-1",
		SCIMToken:          "scim-secret",
		SCIMTokenExpiresAt: now.Add(24 * time.Hour),
		SCIMTokenRotatedAt: now,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	return dataStore
}

func newSCIMTestServer(dataStore *store.Store) *Server {
	return &Server{
		pa: &pa.PolicyAdministrator{
			Store: dataStore,
			Cfg:   &config.Config{},
		},
	}
}

func performSCIMRequest(server *Server, method, target, body, token string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/scim+json")
	}
	server.handleSCIM(recorder, request)
	return recorder
}
