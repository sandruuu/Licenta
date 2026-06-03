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
		ExternalURL: "https://internal-web.trustcloud.test/app",
		TenantID:    "tenant-1",
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:        "policy-allow",
		Name:      "Allow catalog",
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
	if snapshot.Resources[0].FQDN != "internal-web.trustcloud.test" {
		t.Fatalf("FQDN = %q, want hostname derived from external_url", snapshot.Resources[0].FQDN)
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
		{ID: "res-users", Name: "Users App", Type: "web", ExternalURL: "https://users.trustcloud.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-all", Name: "All App", Type: "web", ExternalURL: "https://all.trustcloud.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-denied", Name: "Denied App", Type: "web", ExternalURL: "https://denied.trustcloud.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-unassigned", Name: "Unassigned App", Type: "web", ExternalURL: "https://unassigned.trustcloud.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SaveResource(resource)
	}
	for _, rule := range []*models.PolicyRule{
		{ID: "policy-users", Name: "Users", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-all", Name: "All", Enabled: true, Action: "step_up_required", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-deny", Name: "Deny", Enabled: true, Action: "deny", CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SavePolicyRule(rule)
	}
	for _, assignment := range []*models.PolicyAssignment{
		{ID: "assign-users", PolicyID: "policy-users", TenantID: "tenant-1", Level: "resource_group", ResourceID: "res-users", GroupID: "grp-users", GroupName: "TrustCloud-Users", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-all", PolicyID: "policy-all", TenantID: "tenant-1", Level: "resource", ResourceID: "res-all", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-deny", PolicyID: "policy-deny", TenantID: "tenant-1", Level: "resource_group", ResourceID: "res-denied", GroupID: "grp-users", GroupName: "TrustCloud-Users", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SavePolicyAssignment(assignment)
	}

	snapshot := NewService(dataStore).BuildForTenantUser("tenant-1", &models.User{
		ID:       "user-1",
		Username: "user@example.test",
		Email:    "user@example.test",
		Role:     "user",
		TenantID: "tenant-1",
	}, []string{"grp-users"}, []string{"TrustCloud-Users"})

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

func TestBuildForTenantUserDoesNotPublishResourcesFromOrganizationPolicies(t *testing.T) {
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = dataStore.Close() })

	now := time.Now()
	for _, resource := range []*models.Resource{
		{ID: "res-web", Name: "Web", Type: "web", ExternalURL: "https://web.trustcloud.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-ssh", Name: "SSH", Type: "ssh", ExternalURL: "ssh.trustcloud.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-rdp", Name: "RDP", Type: "rdp", ExternalURL: "rdp.trustcloud.test", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SaveResource(resource)
	}

	dataStore.EnsureDefaultGlobalPolicyForTenant("tenant-1")
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:        "policy-org-baseline",
		Name:      "Organization baseline",
		Enabled:   true,
		Action:    models.DecisionStepUpRequired,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:        "assign-org-baseline",
		PolicyID:  "policy-org-baseline",
		TenantID:  "tenant-1",
		Level:     "organization",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})

	snapshot := NewService(dataStore).BuildForTenantUser("tenant-1", &models.User{
		ID:       "user-1",
		Username: "user@example.test",
		Email:    "user@example.test",
		Role:     "user",
		TenantID: "tenant-1",
	}, nil, nil)
	if len(snapshot.Resources) != 0 {
		t.Fatalf("resources = %+v, want none without an explicit resource policy", snapshot.Resources)
	}
}
