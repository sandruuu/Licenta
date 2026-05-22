package pa

import (
	"strings"

	"pdp/models"
	"pdp/pe/evaluation"
)

type DirectoryUserContext struct {
	Found      bool
	Active     bool
	UserID     string
	UserName   string
	Email      string
	GroupIDs   []string
	GroupNames []string
}

func (pa *PolicyAdministrator) DirectoryContextForUser(user *models.User) DirectoryUserContext {
	result := DirectoryUserContext{Active: true}
	if pa == nil || pa.Store == nil || user == nil {
		return result
	}

	result.Email = strings.TrimSpace(user.Email)
	dirUser, ok := pa.resolveDirectoryUser(user)
	if !ok || dirUser == nil {
		return result
	}

	result.Found = true
	result.Active = dirUser.Active
	result.UserID = dirUser.ID
	result.UserName = dirUser.UserName
	result.Email = firstNonEmptyString(result.Email, dirUser.Email)
	if !dirUser.Active {
		return result
	}

	for _, group := range pa.Store.ListDirectoryGroupsForUser(dirUser.TenantID, dirUser.IdPID, dirUser.ID) {
		if group == nil {
			continue
		}
		result.GroupIDs = appendUnique(result.GroupIDs, group.ID, group.ExternalID)
		result.GroupNames = appendUnique(result.GroupNames, group.DisplayName)
	}
	return result
}

func (pa *PolicyAdministrator) populateDirectoryContext(ctx *evaluation.AccessContext, user *models.User) *models.AccessDecision {
	if pa == nil || pa.Store == nil || ctx == nil || user == nil {
		return nil
	}

	directory := pa.DirectoryContextForUser(user)
	ctx.UserEmail = directory.Email
	if !directory.Found {
		return nil
	}
	if !directory.Active {
		return &models.AccessDecision{
			Decision:  "deny",
			Reason:    "directory user is disabled",
			RiskScore: 100,
		}
	}

	ctx.DirectoryUserID = directory.UserID
	ctx.DirectoryUserName = directory.UserName
	ctx.DirectoryGroupIDs = appendUnique(ctx.DirectoryGroupIDs, directory.GroupIDs...)
	ctx.DirectoryGroupNames = appendUnique(ctx.DirectoryGroupNames, directory.GroupNames...)
	return nil
}

func (pa *PolicyAdministrator) resolveDirectoryUser(user *models.User) (*models.DirectoryUser, bool) {
	if user == nil || pa == nil || pa.Store == nil {
		return nil, false
	}
	tenantID := strings.TrimSpace(user.TenantID)
	if tenantID == "" {
		return nil, false
	}

	for _, idp := range pa.directoryIdPCandidates(user) {
		if dirUser, ok := pa.findDirectoryUserInIdP(user, idp); ok {
			return dirUser, true
		}
	}
	return nil, false
}

func (pa *PolicyAdministrator) directoryIdPCandidates(user *models.User) []*models.IdentityProviderConfig {
	if user == nil || pa == nil || pa.Store == nil {
		return nil
	}

	authSource := strings.TrimSpace(user.AuthSource)
	all := pa.Store.ListIdentityProviderConfigsForTenant(user.TenantID)
	seen := map[string]bool{}
	candidates := make([]*models.IdentityProviderConfig, 0, len(all))
	add := func(cfg *models.IdentityProviderConfig) {
		if cfg == nil || !cfg.Enabled || seen[cfg.ID] {
			return
		}
		seen[cfg.ID] = true
		candidates = append(candidates, cfg)
	}

	if authSource != "" {
		for _, cfg := range all {
			if strings.EqualFold(cfg.ID, authSource) || strings.EqualFold(cfg.Issuer, authSource) {
				add(cfg)
			}
		}
	}
	for _, cfg := range all {
		add(cfg)
	}
	return candidates
}

func (pa *PolicyAdministrator) findDirectoryUserInIdP(user *models.User, idp *models.IdentityProviderConfig) (*models.DirectoryUser, bool) {
	if user == nil || idp == nil || pa == nil || pa.Store == nil {
		return nil, false
	}

	tenantID := strings.TrimSpace(idp.TenantID)
	idpID := strings.TrimSpace(idp.ID)
	for _, value := range []string{user.ExternalSubject} {
		if value == "" {
			continue
		}
		if dirUser, ok := pa.Store.GetDirectoryUser(tenantID, idpID, value); ok {
			return dirUser, true
		}
		if dirUser, ok := pa.Store.FindDirectoryUserByExternalID(tenantID, idpID, value); ok {
			return dirUser, true
		}
	}
	if dirUser, ok := pa.Store.FindDirectoryUserByUserName(tenantID, idpID, user.Username); ok {
		return dirUser, true
	}
	if dirUser, ok := pa.Store.FindDirectoryUserByEmail(tenantID, idpID, user.Email); ok {
		return dirUser, true
	}
	return nil, false
}

func appendUnique(values []string, candidates ...string) []string {
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		found := false
		for _, existing := range values {
			if strings.EqualFold(strings.TrimSpace(existing), candidate) {
				found = true
				break
			}
		}
		if !found {
			values = append(values, candidate)
		}
	}
	return values
}
