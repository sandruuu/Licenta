package main

import (
	"context"
	"fmt"
	"strings"
)

type syncStats struct {
	UsersUpserted       int
	GroupsUpserted      int
	UsersDeprovisioned  int
	GroupsDeprovisioned int
}

func syncDirectory(ctx context.Context, cfg config, kc *keycloakClient, scim *scimClient) (syncStats, error) {
	token, err := kc.accessToken(ctx)
	if err != nil {
		return syncStats{}, err
	}

	users, err := kc.users(ctx, token)
	if err != nil {
		return syncStats{}, err
	}
	groups, err := kc.groups(ctx, token)
	if err != nil {
		return syncStats{}, err
	}

	existingUsers, err := scim.users(ctx)
	if err != nil {
		return syncStats{}, fmt.Errorf("list SCIM users: %w", err)
	}
	existingGroups, err := scim.groups(ctx)
	if err != nil {
		return syncStats{}, fmt.Errorf("list SCIM groups: %w", err)
	}

	stats := syncStats{}
	seenUsers := map[string]bool{}
	seenGroups := map[string]bool{}
	scimUserIDs := map[string]string{}

	for _, user := range users {
		if shouldSkipUser(user, cfg.SkipServiceAccounts) {
			continue
		}
		scimUser, err := scim.upsertUser(ctx, userToSCIM(user))
		if err != nil {
			return stats, fmt.Errorf("upsert user %s: %w", firstNonEmpty(user.Username, user.ID), err)
		}
		stats.UsersUpserted++
		seenUsers[user.ID] = true
		scimUserIDs[user.ID] = scimUser.ID
	}

	flatGroups := flattenGroups(groups)
	for _, group := range flatGroups {
		if strings.TrimSpace(group.ID) == "" {
			continue
		}
		members, err := kc.groupMembers(ctx, token, group.ID)
		if err != nil {
			return stats, fmt.Errorf("fetch members for group %s: %w", firstNonEmpty(group.Name, group.ID), err)
		}
		scimGroup, err := scim.upsertGroup(ctx, groupToSCIM(group, members, scimUserIDs, cfg.SkipServiceAccounts))
		if err != nil {
			return stats, fmt.Errorf("upsert group %s: %w", firstNonEmpty(group.Name, group.ID), err)
		}
		_ = scimGroup
		stats.GroupsUpserted++
		seenGroups[group.ID] = true
	}

	if cfg.DisableMissingUsers {
		for _, user := range existingUsers {
			if user.ExternalID == "" || seenUsers[user.ExternalID] {
				continue
			}
			if err := scim.deleteUser(ctx, user.ID); err != nil {
				return stats, fmt.Errorf("disable missing user %s: %w", firstNonEmpty(user.UserName, user.ExternalID, user.ID), err)
			}
			stats.UsersDeprovisioned++
		}
	}
	if cfg.DeleteMissingGroups {
		for _, group := range existingGroups {
			if group.ExternalID == "" || seenGroups[group.ExternalID] {
				continue
			}
			if err := scim.deleteGroup(ctx, group.ID); err != nil {
				return stats, fmt.Errorf("delete missing group %s: %w", firstNonEmpty(group.DisplayName, group.ExternalID, group.ID), err)
			}
			stats.GroupsDeprovisioned++
		}
	}
	return stats, nil
}
