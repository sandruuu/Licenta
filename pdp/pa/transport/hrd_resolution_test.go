package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pdp/models"
)

func TestHRDRejectsUnknownLoginHintDomainBeforeSingleTenantFallback(t *testing.T) {
	server := newHRDResolutionTestServer(t, "demo.trustcloud.test", []string{"demo.trustcloud.test"})

	request := httptest.NewRequest(http.MethodGet, "/auth/authorize?login_hint=user@unknown.test", nil)
	if _, _, err := server.resolveIdentityProvider(request, "connect-app"); err == nil {
		t.Fatalf("expected unknown login_hint domain to be rejected")
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
	idpCfg, tenant, err := server.resolveIdentityProvider(request, "connect-app")
	if err != nil {
		t.Fatalf("resolveIdentityProvider without login_hint returned error: %v", err)
	}
	if idpCfg == nil || idpCfg.ID != "idp-1" || tenant == nil || tenant.ID != "tenant-1" {
		t.Fatalf("single tenant fallback mismatch: idp=%+v tenant=%+v", idpCfg, tenant)
	}
}

func TestEnrollmentHRDRejectsUnknownEmailDomainBeforeSingleTenantFallback(t *testing.T) {
	server := newHRDResolutionTestServer(t, "demo.trustcloud.test", []string{"demo.trustcloud.test"})

	if idpCfg, tenant, ok := server.resolveEnrollmentIdentityProvider("user@unknown.test"); ok {
		t.Fatalf("unknown enrollment email resolved unexpectedly: idp=%+v tenant=%+v", idpCfg, tenant)
	}

	idpCfg, tenant, ok := server.resolveEnrollmentIdentityProvider("")
	if !ok || idpCfg == nil || idpCfg.ID != "idp-1" || tenant == nil || tenant.ID != "tenant-1" {
		t.Fatalf("single tenant enrollment fallback mismatch: ok=%v idp=%+v tenant=%+v", ok, idpCfg, tenant)
	}
}

func TestAgentSessionHRDRejectsUnknownEmailDomainBeforeDefaultTenantFallback(t *testing.T) {
	server := newHRDResolutionTestServer(t, "demo.trustcloud.test", nil)

	if idpCfg, ok := server.resolveAgentSessionIdentityProvider("tenant-1", "user@unknown.test"); ok {
		t.Fatalf("unknown agent-session email resolved unexpectedly: idp=%+v", idpCfg)
	}

	idpCfg, ok := server.resolveAgentSessionIdentityProvider("tenant-1", "user@demo.trustcloud.test")
	if !ok || idpCfg == nil || idpCfg.ID != "idp-1" {
		t.Fatalf("tenant-domain agent-session HRD mismatch: ok=%v idp=%+v", ok, idpCfg)
	}
}

func newHRDResolutionTestServer(t *testing.T, tenantDomain string, idpDomains []string) *Server {
	t.Helper()
	dataStore := newIdentityProviderTestStore(t)
	now := time.Now()
	dataStore.SaveTenant(&models.Tenant{
		ID:           "tenant-1",
		Name:         "Tenant 1",
		Domain:       tenantDomain,
		Enabled:      true,
		DefaultIdPID: "idp-1",
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	dataStore.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:        "idp-1",
		TenantID:  "tenant-1",
		Name:      "Tenant 1 IdP",
		Type:      "oidc",
		Enabled:   true,
		Domains:   idpDomains,
		Issuer:    "https://idp1.example.test",
		ClientID:  "client-1",
		Scopes:    "openid profile email",
		CreatedAt: now,
		UpdatedAt: now,
	})
	return newIdentityProviderTestServer(dataStore)
}
