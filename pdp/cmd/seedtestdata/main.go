package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"pdp/models"
	"pdp/store"
)

func main() {
	var (
		dataDir        = flag.String("data-dir", "data", "PDP data directory")
		databasePath   = flag.String("database-path", "", "SQLite database path; defaults to data-dir/trustcloud.db")
		organizationID = flag.String("organization-id", "", "organization to seed; defaults to demo domain or the only organization")
		domain         = flag.String("domain", "demo.trustcloud.test", "organization and IdP email domain")
		issuer         = flag.String("issuer", "http://keycloak:8080/realms/trustcloud-lab", "Keycloak OIDC issuer")
		clientID       = flag.String("client-id", "trustcloud", "Keycloak OIDC client ID")
		clientSecret   = flag.String("client-secret", "trustcloud-dev-secret", "Keycloak OIDC client secret")
		idpID          = flag.String("idp-id", "idp_keycloak_trustcloud_lab", "IdP config ID to create when the organization has none")
	)
	flag.Parse()

	dataStore := store.NewWithDatabasePath(*dataDir, *databasePath)
	if err := dataStore.InitDB(); err != nil {
		fatalf("init store: %v", err)
	}
	defer dataStore.Close()

	tenant, err := resolveOrganization(dataStore, strings.TrimSpace(*organizationID), strings.TrimSpace(*domain))
	if err != nil {
		fatalf("%v", err)
	}

	now := time.Now().UTC()
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = now
	}
	tenant.Enabled = true
	ensureOrganizationDomain(tenant, *domain)

	existingID := firstIdentityProviderID(dataStore, tenant.ID)
	targetID := strings.TrimSpace(*idpID)
	if existingID != "" {
		targetID = existingID
	}
	if targetID == "" {
		targetID = "idp_keycloak_trustcloud_lab"
	}

	idp := &models.IdentityProviderConfig{
		ID:               targetID,
		TenantID:         tenant.ID,
		Name:             "Keycloak TrustCloud Lab",
		Type:             "oidc",
		Enabled:          true,
		Domains:          []string{strings.TrimSpace(strings.ToLower(*domain))},
		Issuer:           strings.TrimRight(strings.TrimSpace(*issuer), "/"),
		ClientID:         strings.TrimSpace(*clientID),
		ClientSecret:     *clientSecret,
		Scopes:           "openid profile email groups",
		AutoDiscovery:    true,
		ClaimMapping:     map[string]string{"username": "preferred_username", "email": "email", "groups": "groups"},
		GroupRoleMapping: []models.GroupRoleRule{{GroupName: "TrustCloud-Admins", Role: "admin"}, {GroupName: "TrustCloud-Users", Role: "user"}},
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	dataStore.SaveIdentityProviderConfig(idp)

	tenant.DefaultIdPID = idp.ID
	tenant.UpdatedAt = now
	dataStore.SaveTenant(tenant)
	dataStore.EnsureDefaultGlobalPolicyForTenant(tenant.ID)

	action := "created"
	if existingID != "" {
		action = "updated"
	}
	fmt.Printf("%s Keycloak IdP %s for organization %s (%s)\n", action, idp.ID, tenant.ID, tenant.Domain)
	fmt.Printf("issuer=%s client_id=%s domains=%v default_idp_id=%s\n", idp.Issuer, idp.ClientID, idp.Domains, tenant.DefaultIdPID)
}

func resolveOrganization(dataStore *store.Store, organizationID, domain string) (*models.Tenant, error) {
	if organizationID != "" {
		if tenant, ok := dataStore.GetTenant(organizationID); ok && tenant != nil {
			return tenant, nil
		}
		return nil, fmt.Errorf("organization %q was not found", organizationID)
	}
	if domain != "" {
		if tenant, ok := dataStore.FindTenantByDomain(domain); ok && tenant != nil {
			return tenant, nil
		}
	}
	tenants := dataStore.ListTenants()
	if len(tenants) == 1 && tenants[0] != nil {
		return tenants[0], nil
	}
	if len(tenants) == 0 {
		now := time.Now().UTC()
		return &models.Tenant{
			ID:          "tenant_demo_trustcloud",
			Name:        "TrustCloud Demo",
			Domain:      strings.TrimSpace(strings.ToLower(domain)),
			Description: "Local demo organization",
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		}, nil
	}
	return nil, fmt.Errorf("multiple organizations exist; pass -organization-id explicitly")
}

func ensureOrganizationDomain(tenant *models.Tenant, domain string) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if tenant == nil || domain == "" {
		return
	}
	if strings.TrimSpace(tenant.Domain) == "" {
		tenant.Domain = domain
		return
	}
	if strings.EqualFold(tenant.Domain, domain) {
		return
	}
	for _, alias := range tenant.Domains {
		if strings.EqualFold(alias, domain) {
			return
		}
	}
	tenant.Domains = append(tenant.Domains, domain)
}

func firstIdentityProviderID(dataStore *store.Store, organizationID string) string {
	for _, cfg := range dataStore.ListIdentityProviderConfigsForTenant(organizationID) {
		if cfg != nil && strings.TrimSpace(cfg.ID) != "" {
			return cfg.ID
		}
	}
	return ""
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
