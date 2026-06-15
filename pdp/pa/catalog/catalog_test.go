package catalog

import (
	"testing"
	"time"

	"pdp/internal/testdb"
	"pdp/models"
)

func TestBuildForOrganizationUserDerivesFQDNFromExternalURL(t *testing.T) {
	dataStore := testdb.NewStore(t)
	now := time.Now()

	dataStore.SaveResource(&models.Resource{
		ID:             "res-1",
		Name:           "Internal Web",
		Type:           "web",
		ExternalURL:    "https://internal-web.trustcloud.test/app",
		OrganizationID: "organization-1",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
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
		ID:             "assign-allow",
		PolicyID:       "policy-allow",
		OrganizationID: "organization-1",
		Level:          "resource",
		ResourceID:     "res-1",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	snapshot := NewService(dataStore).BuildForOrganizationUser("organization-1", &models.User{
		ID:             "user-1",
		Username:       "user@example.test",
		Email:          "user@example.test",
		Role:           "user",
		OrganizationID: "organization-1",
	}, nil, nil)
	if len(snapshot.Resources) != 1 {
		t.Fatalf("resources = %+v, want one resource", snapshot.Resources)
	}
	if snapshot.Resources[0].FQDN != "internal-web.trustcloud.test" {
		t.Fatalf("FQDN = %q, want hostname derived from external_url", snapshot.Resources[0].FQDN)
	}
}

func TestBuildForOrganizationUserIncludesOnlyPolicyAllowedResources(t *testing.T) {
	dataStore := testdb.NewStore(t)

	now := time.Now()
	for _, resource := range []*models.Resource{
		{ID: "res-users", Name: "Users App", Type: "web", ExternalURL: "https://users.trustcloud.test", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-all", Name: "All App", Type: "web", ExternalURL: "https://all.trustcloud.test", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-denied", Name: "Denied App", Type: "web", ExternalURL: "https://denied.trustcloud.test", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-unassigned", Name: "Unassigned App", Type: "web", ExternalURL: "https://unassigned.trustcloud.test", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
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
		{ID: "assign-users", PolicyID: "policy-users", OrganizationID: "organization-1", Level: "resource_group", ResourceID: "res-users", GroupID: "grp-users", GroupName: "TrustCloud-Users", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-all", PolicyID: "policy-all", OrganizationID: "organization-1", Level: "resource", ResourceID: "res-all", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-deny", PolicyID: "policy-deny", OrganizationID: "organization-1", Level: "resource_group", ResourceID: "res-denied", GroupID: "grp-users", GroupName: "TrustCloud-Users", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SavePolicyAssignment(assignment)
	}

	snapshot := NewService(dataStore).BuildForOrganizationUser("organization-1", &models.User{
		ID:             "user-1",
		Username:       "user@example.test",
		Email:          "user@example.test",
		Role:           "user",
		OrganizationID: "organization-1",
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

func TestBuildForOrganizationUserDoesNotPublishResourcesFromOrganizationPolicies(t *testing.T) {
	dataStore := testdb.NewStore(t)

	now := time.Now()
	for _, resource := range []*models.Resource{
		{ID: "res-web", Name: "Web", Type: "web", ExternalURL: "https://web.trustcloud.test", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-ssh", Name: "SSH", Type: "ssh", ExternalURL: "ssh.trustcloud.test", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "res-rdp", Name: "RDP", Type: "rdp", ExternalURL: "rdp.trustcloud.test", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		dataStore.SaveResource(resource)
	}

	dataStore.EnsureDefaultGlobalPolicyForOrganization("organization-1")
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:        "policy-org-baseline",
		Name:      "Organization baseline",
		Enabled:   true,
		Action:    models.DecisionStepUpRequired,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:             "assign-org-baseline",
		PolicyID:       "policy-org-baseline",
		OrganizationID: "organization-1",
		Level:          "organization",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	snapshot := NewService(dataStore).BuildForOrganizationUser("organization-1", &models.User{
		ID:             "user-1",
		Username:       "user@example.test",
		Email:          "user@example.test",
		Role:           "user",
		OrganizationID: "organization-1",
	}, nil, nil)
	if len(snapshot.Resources) != 0 {
		t.Fatalf("resources = %+v, want none without an explicit resource policy", snapshot.Resources)
	}
}
