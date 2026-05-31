package main

import "testing"

func TestUserToSCIMUsesKeycloakIDAsExternalID(t *testing.T) {
	enabled := true
	user := userToSCIM(keycloakUser{
		ID:        "kc-user-1",
		Username:  "user@example.test",
		FirstName: "Demo",
		LastName:  "User",
		Email:     "user@example.test",
		Enabled:   &enabled,
	})

	if user.ExternalID != "kc-user-1" {
		t.Fatalf("ExternalID = %q, want Keycloak user id", user.ExternalID)
	}
	if user.UserName != "user@example.test" || user.DisplayName != "Demo User" {
		t.Fatalf("unexpected SCIM user mapping: %+v", user)
	}
	if user.Active == nil || !*user.Active {
		t.Fatalf("Active = %v, want true", user.Active)
	}
}

func TestGroupToSCIMUsesProvisionedSCIMMemberIDs(t *testing.T) {
	group := groupToSCIM(
		keycloakGroup{ID: "kc-group-1", Name: "TrustCloud-Users"},
		[]keycloakUser{
			{ID: "kc-user-1", Username: "user@example.test"},
			{ID: "kc-user-missing", Username: "missing@example.test"},
			{ID: "kc-service", Username: "service-account-sync"},
		},
		map[string]string{"kc-user-1": "dirusr-1"},
		true,
	)

	if group.ExternalID != "kc-group-1" || group.DisplayName != "TrustCloud-Users" {
		t.Fatalf("unexpected SCIM group mapping: %+v", group)
	}
	if len(group.Members) != 1 || group.Members[0].Value != "dirusr-1" {
		t.Fatalf("members = %+v, want only provisioned non-service user", group.Members)
	}
}

func TestFlattenGroupsIncludesNestedGroups(t *testing.T) {
	flat := flattenGroups([]keycloakGroup{{
		ID:   "parent",
		Name: "Parent",
		SubGroups: []keycloakGroup{{
			ID:   "child",
			Name: "Child",
		}},
	}})

	if len(flat) != 2 || flat[0].ID != "parent" || flat[1].ID != "child" {
		t.Fatalf("flat groups = %+v", flat)
	}
}
