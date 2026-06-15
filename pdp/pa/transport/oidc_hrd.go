package transport

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"pdp/models"
)

// resolveIdentityProvider determines which organization IdP should authenticate
// the user. Priority: explicit idp_id, login_hint domain, explicit
// organization_id, then single-organization fallback when unambiguous.
func (s *Server) resolveIdentityProvider(r *http.Request, clientID string) (*models.IdentityProviderConfig, *models.Organization, error) {
	_ = clientID
	queryOrganizationID := strings.TrimSpace(r.URL.Query().Get("organization_id"))

	if idpID := r.URL.Query().Get("idp_id"); idpID != "" {
		if idpCfg, ok := s.pa.Store.GetIdentityProviderConfig(idpID); ok && idpCfg.Enabled {
			if queryOrganizationID != "" && !strings.EqualFold(queryOrganizationID, idpCfg.OrganizationID) {
				return nil, nil, fmt.Errorf("selected identity provider does not belong to organization")
			}
			organization, _ := s.pa.Store.GetOrganization(idpCfg.OrganizationID)
			if organization == nil || !organization.Enabled {
				return nil, nil, fmt.Errorf("identity provider organization not found or disabled")
			}
			log.Printf("[HRD] Direct IdP selection: idp=%s organization=%s", idpCfg.Name, idpCfg.OrganizationID)
			return idpCfg, organization, nil
		}
		return nil, nil, fmt.Errorf("selected identity provider not found or disabled")
	}

	if loginHint := r.URL.Query().Get("login_hint"); loginHint != "" {
		domain := extractDomainFromHint(loginHint)
		if idpCfg, ok := s.pa.Store.FindIdentityProviderByDomain(domain); ok && idpCfg.Enabled {
			if queryOrganizationID != "" && !strings.EqualFold(queryOrganizationID, idpCfg.OrganizationID) {
				return nil, nil, fmt.Errorf("login_hint domain resolves to a different organization")
			}
			organization, _ := s.pa.Store.GetOrganization(idpCfg.OrganizationID)
			if organization == nil || !organization.Enabled {
				return nil, nil, fmt.Errorf("identity provider organization not found or disabled")
			}
			log.Printf("[HRD] Domain-based discovery: domain=%s -> idp=%s organization=%s", domain, idpCfg.Name, idpCfg.OrganizationID)
			return idpCfg, organization, nil
		}
		if organization, ok := s.pa.Store.FindOrganizationByDomain(domain); ok {
			if queryOrganizationID != "" && !strings.EqualFold(queryOrganizationID, organization.ID) {
				return nil, nil, fmt.Errorf("login_hint domain resolves to a different organization")
			}
			if !organization.Enabled {
				return nil, nil, fmt.Errorf("identity provider organization not found or disabled")
			}
			if idpCfg, resolvedOrganization, ok := s.defaultIdentityProviderForOrganization(organization.ID); ok {
				log.Printf("[HRD] Organization domain discovery: domain=%s -> organization=%s -> idp=%s", domain, organization.ID, idpCfg.Name)
				return idpCfg, resolvedOrganization, nil
			}
			return nil, nil, fmt.Errorf("organization has no enabled default identity provider")
		}
		log.Printf("[HRD] No IdP found for domain=%s", domain)
		if domain != "" {
			return nil, nil, fmt.Errorf("login_hint domain is not configured for an identity provider")
		}
	}

	if queryOrganizationID != "" {
		if idpCfg, organization, ok := s.defaultIdentityProviderForOrganization(queryOrganizationID); ok {
			log.Printf("[HRD] Organization context: organization=%s -> idp=%s", queryOrganizationID, idpCfg.Name)
			return idpCfg, organization, nil
		}
		return nil, nil, fmt.Errorf("organization has no enabled default identity provider")
	}

	if idpCfg, organization, ok := s.singleOrganizationIdentityProvider(); ok {
		log.Printf("[HRD] Single-organization fallback: organization=%s -> idp=%s", organization.ID, idpCfg.Name)
		return idpCfg, organization, nil
	}

	return nil, nil, nil
}

func (s *Server) defaultIdentityProviderForOrganization(organizationID string) (*models.IdentityProviderConfig, *models.Organization, bool) {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil, nil, false
	}
	organization, found := s.pa.Store.GetOrganization(organizationID)
	if !found || organization == nil || !organization.Enabled {
		return nil, nil, false
	}
	idpCfg, ok := s.pa.Store.GetDefaultIdentityProviderForOrganization(organizationID)
	if !ok || idpCfg == nil || !idpCfg.Enabled {
		for _, cfg := range s.pa.Store.ListIdentityProviderConfigsForOrganization(organizationID) {
			if cfg != nil && cfg.Enabled {
				return cfg, organization, true
			}
		}
		return nil, organization, false
	}
	return idpCfg, organization, true
}

func (s *Server) singleOrganizationIdentityProvider() (*models.IdentityProviderConfig, *models.Organization, bool) {
	var selectedOrganization *models.Organization
	var selectedIdP *models.IdentityProviderConfig
	for _, organization := range s.pa.Store.ListOrganizations() {
		if organization == nil || !organization.Enabled {
			continue
		}
		idpCfg, resolvedOrganization, ok := s.defaultIdentityProviderForOrganization(organization.ID)
		if !ok || idpCfg == nil {
			continue
		}
		if selectedIdP != nil {
			return nil, nil, false
		}
		selectedOrganization = resolvedOrganization
		selectedIdP = idpCfg
	}
	if selectedIdP == nil {
		return nil, nil, false
	}
	return selectedIdP, selectedOrganization, true
}

func organizationMatchesDomain(organization *models.Organization, domain string) bool {
	if organization == nil {
		return false
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	if strings.EqualFold(organization.Domain, domain) {
		return true
	}
	for _, alias := range organization.Domains {
		if strings.EqualFold(alias, domain) {
			return true
		}
	}
	return false
}

// extractDomainFromHint extracts the email domain from a login hint string.
// For "user@company.com" returns "company.com". For plain domain strings,
// returns the string as-is.
func extractDomainFromHint(hint string) string {
	if idx := strings.LastIndex(hint, "@"); idx >= 0 && idx < len(hint)-1 {
		return strings.ToLower(strings.TrimSpace(hint[idx+1:]))
	}
	return strings.ToLower(strings.TrimSpace(hint))
}
