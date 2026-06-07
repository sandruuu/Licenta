package transport

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"pdp/models"
)

// ──────────────────────────────────────────────────────────────────────
// Home Realm Discovery (HRD) — Identity Provider Resolution
// ──────────────────────────────────────────────────────────────────────

// resolveIdentityProvider determines which organization IdP should authenticate
// the user. Priority: explicit idp_id, login_hint domain, explicit organization_id,
// then legacy gateway client_id only as organization context.
func (s *Server) resolveIdentityProvider(r *http.Request, clientID string) (*models.IdentityProviderConfig, *models.Tenant, error) {
	gw, _ := s.pa.Store.GetGatewayByOIDCClientID(clientID)
	queryOrganizationID := strings.TrimSpace(r.URL.Query().Get("organization_id"))

	// Step 1 — explicit IdP selection.
	if idpID := r.URL.Query().Get("idp_id"); idpID != "" {
		if idpCfg, ok := s.pa.Store.GetIdentityProviderConfig(idpID); ok && idpCfg.Enabled {
			if queryOrganizationID != "" && !strings.EqualFold(queryOrganizationID, idpCfg.TenantID) {
				return nil, nil, fmt.Errorf("selected identity provider does not belong to organization")
			}
			if gw != nil {
				tenantID := resolveTenantFromGateway(gw)
				if tenantID != "" && !strings.EqualFold(tenantID, idpCfg.TenantID) {
					return nil, nil, fmt.Errorf("selected identity provider does not belong to gateway organization")
				}
			}
			tenant, _ := s.pa.Store.GetTenant(idpCfg.TenantID)
			if tenant == nil || !tenant.Enabled {
				return nil, nil, fmt.Errorf("identity provider organization not found or disabled")
			}
			log.Printf("[HRD] Direct IdP selection: idp=%s organization=%s", idpCfg.Name, idpCfg.TenantID)
			return idpCfg, tenant, nil
		}
		return nil, nil, fmt.Errorf("selected identity provider not found or disabled")
	}

	// Step 2 — login_hint domain matching
	if loginHint := r.URL.Query().Get("login_hint"); loginHint != "" {
		domain := extractDomainFromHint(loginHint)
		if idpCfg, ok := s.pa.Store.FindIdentityProviderByDomain(domain); ok && idpCfg.Enabled {
			if queryOrganizationID != "" && !strings.EqualFold(queryOrganizationID, idpCfg.TenantID) {
				return nil, nil, fmt.Errorf("login_hint domain resolves to a different organization")
			}
			tenant, _ := s.pa.Store.GetTenant(idpCfg.TenantID)
			if tenant == nil || !tenant.Enabled {
				return nil, nil, fmt.Errorf("identity provider organization not found or disabled")
			}
			log.Printf("[HRD] Domain-based discovery: domain=%s → idp=%s organization=%s", domain, idpCfg.Name, idpCfg.TenantID)
			return idpCfg, tenant, nil
		}
		if tenant, ok := s.pa.Store.FindTenantByDomain(domain); ok {
			if queryOrganizationID != "" && !strings.EqualFold(queryOrganizationID, tenant.ID) {
				return nil, nil, fmt.Errorf("login_hint domain resolves to a different organization")
			}
			if !tenant.Enabled {
				return nil, nil, fmt.Errorf("identity provider organization not found or disabled")
			}
			if idpCfg, resolvedTenant, ok := s.defaultIdentityProviderForTenant(tenant.ID); ok {
				log.Printf("[HRD] Organization domain discovery: domain=%s -> organization=%s -> idp=%s", domain, tenant.ID, idpCfg.Name)
				return idpCfg, resolvedTenant, nil
			}
			return nil, nil, fmt.Errorf("organization has no enabled default identity provider")
		}
		log.Printf("[HRD] No IdP found for domain=%s", domain)
		if domain != "" {
			return nil, nil, fmt.Errorf("login_hint domain is not configured for an identity provider")
		}
	}

	// Step 3 — explicit organization context from the native client.
	if queryOrganizationID != "" {
		if idpCfg, tenant, ok := s.defaultIdentityProviderForTenant(queryOrganizationID); ok {
			log.Printf("[HRD] Organization context: organization=%s → idp=%s", queryOrganizationID, idpCfg.Name)
			return idpCfg, tenant, nil
		}
		return nil, nil, fmt.Errorf("organization has no enabled default identity provider")
	}

	// Step 4 — legacy gateway client_id as organization context only.
	if gw != nil {
		tenantID := resolveTenantFromGateway(gw)
		if tenantID != "" {
			if idpCfg, tenant, ok := s.defaultIdentityProviderForTenant(tenantID); ok {
				log.Printf("[HRD] Gateway organization context: gateway=%s → organization=%s → idp=%s", gw.Name, tenantID, idpCfg.Name)
				return idpCfg, tenant, nil
			}
		}
	}

	// Step 5 — single-organization deployment fallback.
	if idpCfg, tenant, ok := s.singleTenantIdentityProvider(); ok {
		log.Printf("[HRD] Single-organization fallback: organization=%s → idp=%s", tenant.ID, idpCfg.Name)
		return idpCfg, tenant, nil
	}

	return nil, nil, nil
}

func (s *Server) defaultIdentityProviderForTenant(tenantID string) (*models.IdentityProviderConfig, *models.Tenant, bool) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil, false
	}
	tenant, found := s.pa.Store.GetTenant(tenantID)
	if !found || tenant == nil || !tenant.Enabled {
		return nil, nil, false
	}
	idpCfg, ok := s.pa.Store.GetDefaultIdentityProviderForTenant(tenantID)
	if !ok || idpCfg == nil || !idpCfg.Enabled {
		for _, cfg := range s.pa.Store.ListIdentityProviderConfigsForTenant(tenantID) {
			if cfg != nil && cfg.Enabled {
				return cfg, tenant, true
			}
		}
		return nil, tenant, false
	}
	return idpCfg, tenant, true
}

func (s *Server) singleTenantIdentityProvider() (*models.IdentityProviderConfig, *models.Tenant, bool) {
	var selectedTenant *models.Tenant
	var selectedIdP *models.IdentityProviderConfig
	for _, tenant := range s.pa.Store.ListTenants() {
		if tenant == nil || !tenant.Enabled {
			continue
		}
		idpCfg, resolvedTenant, ok := s.defaultIdentityProviderForTenant(tenant.ID)
		if !ok || idpCfg == nil {
			continue
		}
		if selectedIdP != nil {
			return nil, nil, false
		}
		selectedTenant = resolvedTenant
		selectedIdP = idpCfg
	}
	if selectedIdP == nil {
		return nil, nil, false
	}
	return selectedIdP, selectedTenant, true
}

func tenantMatchesDomain(tenant *models.Tenant, domain string) bool {
	if tenant == nil {
		return false
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	if strings.EqualFold(tenant.Domain, domain) {
		return true
	}
	for _, alias := range tenant.Domains {
		if strings.EqualFold(alias, domain) {
			return true
		}
	}
	return false
}

// resolveTenantFromGateway determines which tenant a gateway serves.
func resolveTenantFromGateway(gw *models.Gateway) string {
	if gw.TenantID != "" {
		return gw.TenantID
	}
	if len(gw.TenantIDs) == 1 {
		return gw.TenantIDs[0]
	}
	return ""
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
