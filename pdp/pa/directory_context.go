package pa

import (
	"strings"

	"pdp/models"
	"pdp/pe/evaluation"
)

func (pa *PolicyAdministrator) populateDirectoryContext(ctx *evaluation.AccessContext, user *models.User) *models.AccessDecision {
	if pa == nil || pa.Store == nil || ctx == nil || user == nil {
		return nil
	}

	ctx.UserEmail = strings.TrimSpace(user.Email)

	dirUser, ok := pa.resolveDirectoryUser(user)
	if !ok || dirUser == nil {
		return nil
	}
	if !dirUser.Active {
		return &models.AccessDecision{
			Decision:  "deny",
			Reason:    "directory user is disabled",
			RiskScore: 100,
		}
	}

	ctx.DirectoryUserID = dirUser.ID
	ctx.DirectoryUserName = dirUser.UserName
	ctx.UserEmail = firstNonEmptyString(ctx.UserEmail, dirUser.Email)

	for _, group := range pa.Store.ListDirectoryGroupsForUser(dirUser.TenantID, dirUser.IdPID, dirUser.ID) {
		if group == nil {
			continue
		}
		ctx.DirectoryGroupIDs = appendUnique(ctx.DirectoryGroupIDs, group.ID, group.ExternalID)
		ctx.DirectoryGroupNames = appendUnique(ctx.DirectoryGroupNames, group.DisplayName)
	}
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
