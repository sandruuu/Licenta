package catalog

import (
	"testing"
	"time"

	"pdp/models"
	"pdp/store"
)

func TestBuildForTenantUserDerivesFQDNFromExternalURL(t *testing.T) {
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = dataStore.Close() })
	now := time.Now()

	dataStore.SaveResource(&models.Resource{
		ID:          "res-1",
		Name:        "Internal Web",
		Type:        "web",
		ExternalURL: "https://internal-web.ztna.test/app",
		TenantID:    "tenant-1",
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:        "policy-allow",
		Name:      "Allow catalog",
		Priority:  1,
		Enabled:   true,
		Action:    "allow",
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:         "assign-allow",
		PolicyID:   "policy-allow",
		TenantID:   "tenant-1",
		Level:      "resource",
		ResourceID: "res-1",
		Priority:   1,
		Enabled:    true,
		CreatedAt:  now,
		UpdatedAt:  now,
	})

	snapshot := NewService(dataStore).BuildForTenantUser("tenant-1", &models.User{
		ID:       "user-1",
		Username: "user@example.test",
		Email:    "user@example.test",
		Role:     "user",
		TenantID: "tenant-1",
	}, nil, nil)
	if len(snapshot.Resources) != 1 {
		t.Fatalf("resources = %+v, want one resource", snapshot.Resources)
	}
	if snapshot.Resources[0].FQDN != "internal-web.ztna.test" {
		t.Fatalf("FQDN = %q, want hostname derived from external_url", snapshot.Resources[0].FQDN)
	}
	if len(snapshot.DNSSuffixes) != 1 || snapshot.DNSSuffixes[0] != "ztna.test" {
		t.Fatalf("DNSSuffixes = %+v, want derived parent suffix", snapshot.DNSSuffixes)
	}
}

func TestBuildForTenantUserIncludesOnlyPolicyAllowedResources(t *testing.T) {
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = dataStore.Close() })

	now := time.Now()
	for _, resource := range []*models.Resource{
		{ID: "res-users", Name: "Users App", Type: "web", ExternalURL: "https://users.ztna.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-all", Name: "All App", Type: "web", ExternalURL: "https://all.ztna.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-denied", Name: "Denied App", Type: "web", ExternalURL: "https://denied.ztna.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-unassigned", Name: "Unassigned App", Type: "web", ExternalURL: "https://unassigned.ztna.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SaveResource(resource)
	}
	for _, rule := range []*models.PolicyRule{
		{ID: "policy-users", Name: "Users", Priority: 10, Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-all", Name: "All", Priority: 20, Enabled: true, Action: "mfa_required", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-deny", Name: "Deny", Priority: 1, Enabled: true, Action: "deny", CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SavePolicyRule(rule)
	}
	for _, assignment := range []*models.PolicyAssignment{
		{ID: "assign-users", PolicyID: "policy-users", TenantID: "tenant-1", Level: "resource_group", ResourceID: "res-users", GroupID: "grp-users", GroupName: "ZTNA-Users", Priority: 10, Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-all", PolicyID: "policy-all", TenantID: "tenant-1", Level: "resource", ResourceID: "res-all", Priority: 20, Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-deny", PolicyID: "policy-deny", TenantID: "tenant-1", Level: "resource_group", ResourceID: "res-denied", GroupID: "grp-users", GroupName: "ZTNA-Users", Priority: 1, Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SavePolicyAssignment(assignment)
	}

	snapshot := NewService(dataStore).BuildForTenantUser("tenant-1", &models.User{
		ID:       "user-1",
		Username: "user@example.test",
		Email:    "user@example.test",
		Role:     "user",
		TenantID: "tenant-1",
	}, []string{"grp-users"}, []string{"ZTNA-Users"})

	got := make([]string, 0, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		got = append(got, resource.ResourceID)
	}
	want := []string{"res-all", "res-users"}
	if len(got) != len(want) {
		t.Fatalf("resource IDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("resource IDs = %v, want %v", got, want)
		}
	}
}
