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

// resolveIdentityProvider determines which tenant-level IdP should authenticate
// the user. Priority: explicit idp_id, login_hint domain, explicit tenant_id,
// then legacy gateway client_id only as tenant context.
func (s *Server) resolveIdentityProvider(r *http.Request, clientID string) (*models.IdentityProviderConfig, *models.Tenant, error) {
	gw, _ := s.pa.Store.GetGatewayByOIDCClientID(clientID)
	queryTenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))

	// Step 1 — explicit IdP selection.
	if idpID := r.URL.Query().Get("idp_id"); idpID != "" {
		if idpCfg, ok := s.pa.Store.GetIdentityProviderConfig(idpID); ok && idpCfg.Enabled {
			if queryTenantID != "" && !strings.EqualFold(queryTenantID, idpCfg.TenantID) {
				return nil, nil, fmt.Errorf("selected identity provider does not belong to tenant")
			}
			if gw != nil {
				tenantID := resolveTenantFromGateway(gw)
				if tenantID != "" && !strings.EqualFold(tenantID, idpCfg.TenantID) {
					return nil, nil, fmt.Errorf("selected identity provider does not belong to gateway tenant")
				}
			}
			tenant, _ := s.pa.Store.GetTenant(idpCfg.TenantID)
			if tenant == nil || !tenant.Enabled {
				return nil, nil, fmt.Errorf("identity provider tenant not found or disabled")
			}
			log.Printf("[HRD] Direct IdP selection: idp=%s tenant=%s", idpCfg.Name, idpCfg.TenantID)
			return idpCfg, tenant, nil
		}
		return nil, nil, fmt.Errorf("selected identity provider not found or disabled")
	}

	// Step 2 — login_hint domain matching
	if loginHint := r.URL.Query().Get("login_hint"); loginHint != "" {
		domain := extractDomainFromHint(loginHint)
		if idpCfg, ok := s.pa.Store.FindIdentityProviderByDomain(domain); ok && idpCfg.Enabled {
			if queryTenantID != "" && !strings.EqualFold(queryTenantID, idpCfg.TenantID) {
				return nil, nil, fmt.Errorf("login_hint domain resolves to a different tenant")
			}
			tenant, _ := s.pa.Store.GetTenant(idpCfg.TenantID)
			if tenant == nil || !tenant.Enabled {
				return nil, nil, fmt.Errorf("identity provider tenant not found or disabled")
			}
			log.Printf("[HRD] Domain-based discovery: domain=%s → idp=%s tenant=%s", domain, idpCfg.Name, idpCfg.TenantID)
			return idpCfg, tenant, nil
		}
		if tenant, ok := s.pa.Store.FindTenantByDomain(domain); ok {
			if queryTenantID != "" && !strings.EqualFold(queryTenantID, tenant.ID) {
				return nil, nil, fmt.Errorf("login_hint domain resolves to a different tenant")
			}
			if !tenant.Enabled {
				return nil, nil, fmt.Errorf("identity provider tenant not found or disabled")
			}
			if idpCfg, resolvedTenant, ok := s.defaultIdentityProviderForTenant(tenant.ID); ok {
				log.Printf("[HRD] Tenant domain discovery: domain=%s -> tenant=%s -> idp=%s", domain, tenant.ID, idpCfg.Name)
				return idpCfg, resolvedTenant, nil
			}
			return nil, nil, fmt.Errorf("tenant has no enabled default identity provider")
		}
		log.Printf("[HRD] No IdP found for domain=%s", domain)
	}

	// Step 3 — explicit tenant context from the native client.
	if queryTenantID != "" {
		if idpCfg, tenant, ok := s.defaultIdentityProviderForTenant(queryTenantID); ok {
			log.Printf("[HRD] Tenant context: tenant=%s → idp=%s", queryTenantID, idpCfg.Name)
			return idpCfg, tenant, nil
		}
		return nil, nil, fmt.Errorf("tenant has no enabled default identity provider")
	}

	// Step 4 — legacy gateway client_id as tenant context only.
	if gw != nil {
		tenantID := resolveTenantFromGateway(gw)
		if tenantID != "" {
			if idpCfg, tenant, ok := s.defaultIdentityProviderForTenant(tenantID); ok {
				log.Printf("[HRD] Gateway tenant context: gateway=%s → tenant=%s → idp=%s", gw.Name, tenantID, idpCfg.Name)
				return idpCfg, tenant, nil
			}
		}
	}

	// Step 5 — single-tenant deployment fallback.
	if idpCfg, tenant, ok := s.singleTenantIdentityProvider(); ok {
		log.Printf("[HRD] Single-tenant fallback: tenant=%s → idp=%s", tenant.ID, idpCfg.Name)
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
