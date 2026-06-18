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
// Admin Identity Provider Config endpoints (per Organization)
// ──────────────────────────────────────────────────────────────────────

// handleAdminIdentityProviders handles GET/POST /api/admin/organizations/idps
// Query param: organization_id (required).
// GET  — list IdP configs for an organization
// POST — create a new IdP config
func (s *Server) handleAdminIdentityProviders(w http.ResponseWriter, r *http.Request) {
	organizationID := organizationIDFromQuery(r)
	if organizationID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "organization_id query parameter is required"})
		return
	}
	if !s.requireOrganizationAccess(w, r, organizationID) {
		return
	}
	organization, found := s.pa.Store.GetOrganization(organizationID)
	if !found || organization == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		cfgs := s.pa.Store.ListIdentityProviderConfigsForOrganization(organizationID)
		if cfgs == nil {
			cfgs = []*models.IdentityProviderConfig{}
		}
		// Strip secrets from response
		safe := make([]map[string]interface{}, 0, len(cfgs))
		for _, cfg := range cfgs {
			safe = append(safe, s.sanitizeIdPConfigForOrganization(cfg, organizationID))
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: safe})

	case http.MethodPost:
		appCfg := s.appConfig()
		existingConfigs := s.pa.Store.ListIdentityProviderConfigsForOrganization(organizationID)
		if len(existingConfigs) > 0 {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "organization already has an identity provider"})
			return
		}

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

		cfg.OrganizationID = organizationID
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
		scimToken, err := util.GenerateSecretToken("tc_scim", 32)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate SCIM token"})
			return
		}
		cfg.SCIMToken = scimToken
		cfg.CreatedAt = time.Now()
		cfg.UpdatedAt = cfg.CreatedAt

		s.pa.Store.SaveIdentityProviderConfig(&cfg)
		if makeDefault {
			if err := s.setOrganizationDefaultIdP(organizationID, cfg.ID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		} else {
			s.reconcileOrganizationDefaultIdP(organizationID)
		}
		log.Printf("[ADMIN] IdP config created: %s (%s) organization=%s", cfg.ID, cfg.Name, organizationID)

		safe := s.sanitizeIdPConfigForOrganization(&cfg, organizationID)
		safe["scim_token"] = scimToken

		writeJSON(w, http.StatusCreated, models.APIResponse{
			Success: true,
			Message: "Identity Provider configuration created",
			Data:    safe,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleAdminIdentityProviderByID handles GET/PUT/DELETE /api/admin/organizations/idps/{id}
func (s *Server) handleAdminIdentityProviderByID(w http.ResponseWriter, r *http.Request) {
	id := identityProviderIDFromAdminPath(r.URL.Path)
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
		if !s.requireOrganizationAccess(w, r, cfg.OrganizationID) {
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: s.sanitizeIdPConfigForOrganization(cfg, cfg.OrganizationID)})

	case http.MethodPut:
		existing, found := s.pa.Store.GetIdentityProviderConfig(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "IdP config not found"})
			return
		}
		if !s.requireOrganizationAccess(w, r, existing.OrganizationID) {
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
		regenerateSCIMToken := idpRegenerateSCIMTokenRequested(raw)
		var scimToken string

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
		if regenerateSCIMToken {
			generatedToken, err := util.GenerateSecretToken("tc_scim", 32)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate SCIM token"})
				return
			}
			scimToken = generatedToken
			existing.SCIMToken = generatedToken
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
			if err := s.setOrganizationDefaultIdP(existing.OrganizationID, existing.ID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		} else {
			s.reconcileOrganizationDefaultIdP(existing.OrganizationID)
		}
		log.Printf("[ADMIN] IdP config updated: %s (%s)", existing.ID, existing.Name)

		safe := s.sanitizeIdPConfigForOrganization(existing, existing.OrganizationID)
		if scimToken != "" {
			safe["scim_token"] = scimToken
		}

		writeJSON(w, http.StatusOK, models.APIResponse{
			Success: true,
			Message: "Identity Provider configuration updated",
			Data:    safe,
		})

	case http.MethodDelete:
		existing, found := s.pa.Store.GetIdentityProviderConfig(id)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "IdP config not found"})
			return
		}
		if !s.requireOrganizationAccess(w, r, existing.OrganizationID) {
			return
		}
		if !s.pa.Store.DeleteIdentityProviderConfig(id) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete IdP config"})
			return
		}
		s.reconcileOrganizationDefaultIdP(existing.OrganizationID)
		log.Printf("[ADMIN] IdP config deleted: %s (%s) organization=%s", id, existing.Name, existing.OrganizationID)

		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Identity Provider configuration deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) reconcileOrganizationDefaultIdP(organizationID string) {
	organization, found := s.pa.Store.GetOrganization(organizationID)
	if !found || organization == nil {
		return
	}
	if organization.DefaultIdPID != "" {
		if cfg, ok := s.pa.Store.GetIdentityProviderConfig(organization.DefaultIdPID); ok && cfg != nil && cfg.Enabled && strings.EqualFold(cfg.OrganizationID, organizationID) {
			return
		}
	}

	organization.DefaultIdPID = ""
	for _, cfg := range s.pa.Store.ListIdentityProviderConfigsForOrganization(organizationID) {
		if cfg != nil && cfg.Enabled {
			organization.DefaultIdPID = cfg.ID
			break
		}
	}
	organization.UpdatedAt = time.Now()
	s.pa.Store.SaveOrganization(organization)
}

func (s *Server) setOrganizationDefaultIdP(organizationID, idpID string) error {
	organization, found := s.pa.Store.GetOrganization(organizationID)
	if !found || organization == nil {
		return fmt.Errorf("organization not found")
	}
	cfg, found := s.pa.Store.GetIdentityProviderConfig(idpID)
	if !found || cfg == nil || !strings.EqualFold(cfg.OrganizationID, organizationID) {
		return fmt.Errorf("identity provider not found for organization")
	}
	if !cfg.Enabled {
		return fmt.Errorf("disabled identity provider cannot be default")
	}
	organization.DefaultIdPID = cfg.ID
	organization.UpdatedAt = time.Now()
	s.pa.Store.SaveOrganization(organization)
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

func idpRegenerateSCIMTokenRequested(raw map[string]json.RawMessage) bool {
	value, ok := raw["regenerate_scim_token"]
	if !ok {
		return false
	}
	var requested bool
	return json.Unmarshal(value, &requested) == nil && requested
}

func (s *Server) sanitizeIdPConfigForOrganization(cfg *models.IdentityProviderConfig, organizationID string) map[string]interface{} {
	safe := sanitizeIdPConfig(cfg)
	if safe == nil {
		return nil
	}
	organization, found := s.pa.Store.GetOrganization(organizationID)
	safe["is_default"] = found && organization != nil && organization.DefaultIdPID == cfg.ID
	return safe
}

// sanitizeIdPConfig returns a safe copy of an IdentityProviderConfig without secrets.
func sanitizeIdPConfig(cfg *models.IdentityProviderConfig) map[string]interface{} {
	if cfg == nil {
		return nil
	}
	return map[string]interface{}{
		"id":                 cfg.ID,
		"organization_id":    cfg.OrganizationID,
		"name":               cfg.Name,
		"type":               cfg.Type,
		"enabled":            cfg.Enabled,
		"domains":            cfg.Domains,
		"issuer":             cfg.Issuer,
		"client_id":          cfg.ClientID,
		"client_secret":      "",
		"has_client_secret":  cfg.ClientSecret != "",
		"scim_token":         "",
		"has_scim_token":     cfg.SCIMToken != "",
		"scopes":             cfg.Scopes,
		"auto_discovery":     cfg.AutoDiscovery,
		"claim_mapping":      cfg.ClaimMapping,
		"group_role_mapping": cfg.GroupRoleMapping,
		"created_at":         cfg.CreatedAt,
		"updated_at":         cfg.UpdatedAt,
	}
}

// handleAdminIdPDiscover tests OIDC discovery for a given issuer URL.
// POST /api/admin/organizations/idps/discover  { "issuer": "https://..." }
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

func organizationIDFromQuery(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("organization_id"))
}

func identityProviderIDFromAdminPath(path string) string {
	path = strings.TrimSpace(path)
	for _, prefix := range []string{"/api/admin/organizations/idps/"} {
		if strings.HasPrefix(path, prefix) {
			return strings.Trim(strings.TrimPrefix(path, prefix), "/")
		}
	}
	return ""
}
