package store

import (
	"testing"
	"time"

	"pdp/models"
)

func TestDirectoryStoreUsersGroupsAndMemberships(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	user := &models.DirectoryUser{
		ID:         "dirusr-1",
		TenantID:   "tenant-1",
		IdPID:      "idp-1",
		ExternalID: "external-user-1",
		UserName:   "alice@example.test",
		Email:      "alice@example.test",
		Active:     true,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	s.SaveDirectoryUser(user)

	if found, ok := s.FindDirectoryUserByExternalID("tenant-1", "idp-1", "external-user-1"); !ok || found.ID != user.ID {
		t.Fatalf("FindDirectoryUserByExternalID mismatch: user=%+v ok=%v", found, ok)
	}
	if found, ok := s.FindDirectoryUserByUserName("tenant-1", "idp-1", "alice@example.test"); !ok || found.ID != user.ID {
		t.Fatalf("FindDirectoryUserByUserName mismatch: user=%+v ok=%v", found, ok)
	}

	group := &models.DirectoryGroup{
		ID:          "dirgrp-1",
		TenantID:    "tenant-1",
		IdPID:       "idp-1",
		ExternalID:  "external-group-1",
		DisplayName: "Finance",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.SaveDirectoryGroup(group)
	if err := s.ReplaceDirectoryGroupMembers("tenant-1", "idp-1", group.ID, []string{user.ID}, now); err != nil {
		t.Fatalf("ReplaceDirectoryGroupMembers returned error: %v", err)
	}

	members := s.ListDirectoryGroupMembers("tenant-1", "idp-1", group.ID)
	if len(members) != 1 || members[0].UserID != user.ID {
		t.Fatalf("members = %+v, want one member %s", members, user.ID)
	}
	groups := s.ListDirectoryGroupsForUser("tenant-1", "idp-1", user.ID)
	if len(groups) != 1 || groups[0].ID != group.ID {
		t.Fatalf("groups for user = %+v, want %s", groups, group.ID)
	}

	if err := s.RemoveDirectoryGroupMembers("tenant-1", "idp-1", group.ID, []string{user.ID}); err != nil {
		t.Fatalf("RemoveDirectoryGroupMembers returned error: %v", err)
	}
	if members := s.ListDirectoryGroupMembers("tenant-1", "idp-1", group.ID); len(members) != 0 {
		t.Fatalf("members after remove = %+v, want empty", members)
	}
}
