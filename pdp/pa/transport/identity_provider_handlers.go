package transport

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	"pdp/util"
)

// ──────────────────────────────────────────────────────────────────────
// Admin Identity Provider Config endpoints (per Tenant)
// ──────────────────────────────────────────────────────────────────────

// handleAdminIdentityProviders handles GET/POST /api/admin/tenants/idps
// Query param: tenant_id (required).
// GET  — list IdP configs for a tenant
// POST — create a new IdP config
func (s *Server) handleAdminIdentityProviders(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id query parameter is required"})
		return
	}
	tenant, found := s.pa.Store.GetTenant(tenantID)
	if !found || tenant == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		cfgs := s.pa.Store.ListIdentityProviderConfigsForTenant(tenantID)
		if cfgs == nil {
			cfgs = []*models.IdentityProviderConfig{}
		}
		// Strip secrets from response
		safe := make([]map[string]interface{}, 0, len(cfgs))
		for _, cfg := range cfgs {
			safe = append(safe, s.sanitizeIdPConfigForTenant(cfg, tenantID))
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: safe})

	case http.MethodPost:
		appCfg := s.appConfig()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var cfg models.IdentityProviderConfig
		if err := json.Unmarshal(body, &cfg); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(body, &raw)
		makeDefault := idpMakeDefaultRequested(raw)

		cfg.TenantID = tenantID
		if cfg.ID == "" {
			var err error
			cfg.ID, err = util.GenerateID("idp")
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate ID"})
				return
			}
		}
		if cfg.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
			return
		}
		if cfg.Issuer == "" || cfg.ClientID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "issuer and client_id are required"})
			return
		}
		if cfg.Type == "" {
			cfg.Type = "oidc"
		}
		if cfg.Scopes == "" {
			cfg.Scopes = appCfg.Public.OIDCDefaultScopes
		}
		if cfg.ClaimMapping == nil {
			cfg.ClaimMapping = map[string]string{}
			for key, value := range appCfg.Public.OIDCDefaultClaimMapping {
				cfg.ClaimMapping[key] = value
			}
		}
		if _, ok := raw["enabled"]; !ok {
			cfg.Enabled = true
		}
		cfg.CreatedAt = time.Now()
		cfg.UpdatedAt = cfg.CreatedAt

		s.pa.Store.SaveIdentityProviderConfig(&cfg)
		if makeDefault {
			if err := s.setTenantDefaultIdP(tenantID, cfg.ID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		} else {
			s.reconcileTenantDefaultIdP(tenantID)
		}
		log.Printf("[ADMIN] IdP config created: %s (%s) tenant=%s", cfg.ID, cfg.Name, tenantID)

		writeJSON(w, http.StatusCreated, models.APIResponse{
			Success: true,
			Message: "Identity Provider configuration created",
			Data:    s.sanitizeIdPConfigForTenant(&cfg, tenantID),
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleAdminIdentityProviderByID handles GET/PUT/DELETE /api/admin/tenants/idps/{id}
func (s *Server) handleAdminIdentityProviderByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/tenants/idps/")
	id = strings.TrimSpace(id)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "IdP config ID required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		cfg, found := s.pa.Store.GetIdentityProviderConfig(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "IdP config not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: s.sanitizeIdPConfigForTenant(cfg, cfg.TenantID)})

	case http.MethodPut:
		existing, found := s.pa.Store.GetIdentityProviderConfig(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "IdP config not found"})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var update models.IdentityProviderConfig
		if err := json.Unmarshal(body, &update); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(body, &raw)
		makeDefault := idpMakeDefaultRequested(raw)

		if update.Name != "" {
			existing.Name = update.Name
		}
		if update.Issuer != "" {
			existing.Issuer = update.Issuer
		}
		if update.ClientID != "" {
			existing.ClientID = update.ClientID
		}
		if update.ClientSecret != "" {
			existing.ClientSecret = update.ClientSecret
		}
		if update.Scopes != "" {
			existing.Scopes = update.Scopes
		}
		if update.Domains != nil {
			existing.Domains = update.Domains
		}
		if update.ClaimMapping != nil {
			existing.ClaimMapping = update.ClaimMapping
		}
		if update.GroupRoleMapping != nil {
			existing.GroupRoleMapping = update.GroupRoleMapping
		}
		if _, ok := raw["enabled"]; ok {
			existing.Enabled = update.Enabled
		}
		if _, ok := raw["auto_discovery"]; ok {
			existing.AutoDiscovery = update.AutoDiscovery
		}
		existing.UpdatedAt = time.Now()

		s.pa.Store.SaveIdentityProviderConfig(existing)
		if makeDefault {
			if err := s.setTenantDefaultIdP(existing.TenantID, existing.ID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		} else {
			s.reconcileTenantDefaultIdP(existing.TenantID)
		}
		log.Printf("[ADMIN] IdP config updated: %s (%s)", existing.ID, existing.Name)

		writeJSON(w, http.StatusOK, models.APIResponse{
			Success: true,
			Message: "Identity Provider configuration updated",
			Data:    s.sanitizeIdPConfigForTenant(existing, existing.TenantID),
		})

	case http.MethodDelete:
		existing, found := s.pa.Store.GetIdentityProviderConfig(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "IdP config not found"})
			return
		}
		if !s.pa.Store.DeleteIdentityProviderConfig(id) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete IdP config"})
			return
		}
		s.reconcileTenantDefaultIdP(existing.TenantID)
		log.Printf("[ADMIN] IdP config deleted: %s (%s) tenant=%s", id, existing.Name, existing.TenantID)

		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Identity Provider configuration deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) reconcileTenantDefaultIdP(tenantID string) {
	tenant, found := s.pa.Store.GetTenant(tenantID)
	if !found || tenant == nil {
		return
	}
	if tenant.DefaultIdPID != "" {
		if cfg, ok := s.pa.Store.GetIdentityProviderConfig(tenant.DefaultIdPID); ok && cfg != nil && cfg.Enabled && strings.EqualFold(cfg.TenantID, tenantID) {
			return
		}
	}

	tenant.DefaultIdPID = ""
	for _, cfg := range s.pa.Store.ListIdentityProviderConfigsForTenant(tenantID) {
		if cfg != nil && cfg.Enabled {
			tenant.DefaultIdPID = cfg.ID
			break
		}
	}
	tenant.UpdatedAt = time.Now()
	s.pa.Store.SaveTenant(tenant)
}

func (s *Server) setTenantDefaultIdP(tenantID, idpID string) error {
	tenant, found := s.pa.Store.GetTenant(tenantID)
	if !found || tenant == nil {
		return fmt.Errorf("tenant not found")
	}
	cfg, found := s.pa.Store.GetIdentityProviderConfig(idpID)
	if !found || cfg == nil || !strings.EqualFold(cfg.TenantID, tenantID) {
		return fmt.Errorf("identity provider not found for tenant")
	}
	if !cfg.Enabled {
		return fmt.Errorf("disabled identity provider cannot be default")
	}
	tenant.DefaultIdPID = cfg.ID
	tenant.UpdatedAt = time.Now()
	s.pa.Store.SaveTenant(tenant)
	return nil
}

func idpMakeDefaultRequested(raw map[string]json.RawMessage) bool {
	for _, key := range []string{"default", "is_default", "make_default"} {
		value, ok := raw[key]
		if !ok {
			continue
		}
		var requested bool
		if err := json.Unmarshal(value, &requested); err == nil && requested {
			return true
		}
	}
	return false
}

func (s *Server) sanitizeIdPConfigForTenant(cfg *models.IdentityProviderConfig, tenantID string) map[string]interface{} {
	safe := sanitizeIdPConfig(cfg)
	if safe == nil {
		return nil
	}
	tenant, found := s.pa.Store.GetTenant(tenantID)
	safe["is_default"] = found && tenant != nil && tenant.DefaultIdPID == cfg.ID
	return safe
}

// sanitizeIdPConfig returns a safe copy of an IdentityProviderConfig without secrets.
func sanitizeIdPConfig(cfg *models.IdentityProviderConfig) map[string]interface{} {
	if cfg == nil {
		return nil
	}
	return map[string]interface{}{
		"id":                 cfg.ID,
		"tenant_id":          cfg.TenantID,
		"name":               cfg.Name,
		"type":               cfg.Type,
		"enabled":            cfg.Enabled,
		"domains":            cfg.Domains,
		"issuer":             cfg.Issuer,
		"client_id":          cfg.ClientID,
		"client_secret":      "",
		"has_client_secret":  cfg.ClientSecret != "",
		"scopes":             cfg.Scopes,
		"auto_discovery":     cfg.AutoDiscovery,
		"claim_mapping":      cfg.ClaimMapping,
		"group_role_mapping": cfg.GroupRoleMapping,
		"created_at":         cfg.CreatedAt,
		"updated_at":         cfg.UpdatedAt,
	}
}

// handleAdminIdPDiscover tests OIDC discovery for a given issuer URL.
// POST /api/admin/tenants/idps/discover  { "issuer": "https://..." }
func (s *Server) handleAdminIdPDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	issuer := strings.TrimSpace(body.Issuer)
	if issuer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "issuer is required"})
		return
	}

	disc, err := s.pa.Auth.Federation.Discover(issuer)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"ok":     false,
			"issuer": issuer,
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":                     true,
		"issuer":                 issuer,
		"authorization_endpoint": disc.AuthorizationEndpoint,
		"token_endpoint":         disc.TokenEndpoint,
		"userinfo_endpoint":      disc.UserinfoEndpoint,
		"jwks_uri":               disc.JWKSURI,
	})
}
