package main

import "strings"

func userToSCIM(user keycloakUser) scimUser {
	active := true
	if user.Enabled != nil {
		active = *user.Enabled
	}
	display := strings.TrimSpace(strings.Join([]string{user.FirstName, user.LastName}, " "))
	if display == "" {
		display = firstNonEmpty(user.Username, user.Email, user.ID)
	}
	email := strings.TrimSpace(user.Email)
	if email == "" && strings.Contains(user.Username, "@") {
		email = user.Username
	}
	scim := scimUser{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ExternalID:  user.ID,
		UserName:    firstNonEmpty(user.Username, email, user.ID),
		DisplayName: display,
		Active:      &active,
	}
	if email != "" {
		scim.Emails = []scimEmail{{Value: email, Type: "work", Primary: true}}
	}
	return scim
}

func groupToSCIM(group keycloakGroup, members []keycloakUser, scimUserIDs map[string]string, skipServiceAccounts bool) scimGroup {
	scimMembers := make([]scimMember, 0, len(members))
	for _, member := range members {
		if shouldSkipUser(member, skipServiceAccounts) {
			continue
		}
		scimID := scimUserIDs[member.ID]
		if scimID == "" {
			continue
		}
		scimMembers = append(scimMembers, scimMember{
			Value:   scimID,
			Display: firstNonEmpty(member.Username, member.Email, member.ID),
		})
	}
	return scimGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ExternalID:  group.ID,
		DisplayName: firstNonEmpty(group.Name, strings.TrimPrefix(group.Path, "/"), group.ID),
		Members:     scimMembers,
	}
}

func flattenGroups(groups []keycloakGroup) []keycloakGroup {
	var flat []keycloakGroup
	var visit func([]keycloakGroup)
	visit = func(items []keycloakGroup) {
		for _, group := range items {
			flat = append(flat, group)
			if len(group.SubGroups) > 0 {
				visit(group.SubGroups)
			}
		}
	}
	visit(groups)
	return flat
}

func shouldSkipUser(user keycloakUser, skipServiceAccounts bool) bool {
	if strings.TrimSpace(user.ID) == "" {
		return true
	}
	return skipServiceAccounts && strings.HasPrefix(strings.ToLower(strings.TrimSpace(user.Username)), "service-account-")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
