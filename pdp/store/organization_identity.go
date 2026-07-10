package store

import (
	"database/sql"
	"log"
	"strings"

	"pdp/models"
	"pdp/util"
)

// Organization operations

func (s *Store) SaveOrganization(t *models.Organization) {
	t.Domain = normalizeDomain(t.Domain)
	t.Domains = normalizeDomainAliases(t.Domain, t.Domains)
	_, err := s.db.Exec(`INSERT INTO organizations
		(id, name, domain, description, enabled, default_idp_id, domains_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			domain = EXCLUDED.domain,
			description = EXCLUDED.description,
			enabled = EXCLUDED.enabled,
			default_idp_id = EXCLUDED.default_idp_id,
			domains_json = EXCLUDED.domains_json,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
		t.ID, t.Name, t.Domain, t.Description, b2i(t.Enabled),
		t.DefaultIdPID, toJSON(t.Domains),
		fmtTime(t.CreatedAt), fmtTime(t.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save organization %s: %v", t.ID, err)
	}
}

func (s *Store) GetOrganization(id string) (*models.Organization, bool) {
	row := s.db.QueryRow(`SELECT id, name, domain, description, enabled, default_idp_id, domains_json, created_at, updated_at
		FROM organizations WHERE id = ?`, id)
	return s.scanOrganization(row)
}

func (s *Store) ListOrganizations() []*models.Organization {
	rows, err := s.db.Query(`SELECT id, name, domain, description, enabled, default_idp_id, domains_json, created_at, updated_at
		FROM organizations ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("[STORE] Failed to list organizations: %v", err)
		return nil
	}
	defer rows.Close()

	var organizations []*models.Organization
	for rows.Next() {
		t := &models.Organization{}
		var createdAt, updatedAt, domainsJSON string
		var enabled int
		if err := rows.Scan(&t.ID, &t.Name, &t.Domain, &t.Description, &enabled, &t.DefaultIdPID, &domainsJSON, &createdAt, &updatedAt); err != nil {
			continue
		}
		t.Enabled = i2b(enabled)
		t.Domains = fromJSON[[]string](domainsJSON)
		if t.Domains == nil {
			t.Domains = []string{}
		}
		t.CreatedAt = parseTime(createdAt)
		t.UpdatedAt = parseTime(updatedAt)
		organizations = append(organizations, t)
	}
	return organizations
}

func (s *Store) DeleteOrganization(id string) bool {
	result, err := s.db.Exec("DELETE FROM organizations WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

// Identity Provider Config operations

// FindOrganizationByDomain searches an organization by primary domain or domain aliases.
func (s *Store) FindOrganizationByDomain(domain string) (*models.Organization, bool) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, false
	}
	for _, organization := range s.ListOrganizations() {
		if organization == nil {
			continue
		}
		if normalizeDomain(organization.Domain) == domain {
			return organization, true
		}
		for _, alias := range organization.Domains {
			if normalizeDomain(alias) == domain {
				return organization, true
			}
		}
	}
	return nil, false
}

func (s *Store) SaveIdentityProviderConfig(cfg *models.IdentityProviderConfig) {
	cfg.Domains = normalizeDomainAliases("", cfg.Domains)
	cfg.SCIMToken = util.HashSecretToken(cfg.SCIMToken)
	claimMapping := cfg.ClaimMapping
	if claimMapping == nil {
		claimMapping = map[string]string{}
	}
	groupRoleMapping := cfg.GroupRoleMapping
	if groupRoleMapping == nil {
		groupRoleMapping = []models.GroupRoleRule{}
	}

	_, err := s.db.Exec(`INSERT INTO identity_provider_configs
		(id, organization_id, name, type, enabled, domains_json, issuer, client_id, client_secret,
		 scim_token, scim_token_expires_at, scim_token_rotated_at, scopes, auto_discovery, claim_mapping_json, group_role_mapping_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			organization_id = EXCLUDED.organization_id,
			name = EXCLUDED.name,
			type = EXCLUDED.type,
			enabled = EXCLUDED.enabled,
			domains_json = EXCLUDED.domains_json,
			issuer = EXCLUDED.issuer,
			client_id = EXCLUDED.client_id,
			client_secret = EXCLUDED.client_secret,
			scim_token = EXCLUDED.scim_token,
			scim_token_expires_at = EXCLUDED.scim_token_expires_at,
			scim_token_rotated_at = EXCLUDED.scim_token_rotated_at,
			scopes = EXCLUDED.scopes,
			auto_discovery = EXCLUDED.auto_discovery,
			claim_mapping_json = EXCLUDED.claim_mapping_json,
			group_role_mapping_json = EXCLUDED.group_role_mapping_json,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
		cfg.ID, cfg.OrganizationID, cfg.Name, cfg.Type, b2i(cfg.Enabled),
		toJSON(cfg.Domains), cfg.Issuer, cfg.ClientID, cfg.ClientSecret,
		cfg.SCIMToken, fmtTime(cfg.SCIMTokenExpiresAt), fmtTime(cfg.SCIMTokenRotatedAt),
		cfg.Scopes, b2i(cfg.AutoDiscovery), toJSON(claimMapping), toJSON(groupRoleMapping),
		fmtTime(cfg.CreatedAt), fmtTime(cfg.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save IdP config %s: %v", cfg.ID, err)
	}
}

func (s *Store) GetIdentityProviderConfig(id string) (*models.IdentityProviderConfig, bool) {
	row := s.db.QueryRow(`SELECT id, organization_id, name, type, enabled, domains_json,
		issuer, client_id, client_secret, scim_token, scim_token_expires_at, scim_token_rotated_at, scopes, auto_discovery,
		claim_mapping_json, group_role_mapping_json, created_at, updated_at
		FROM identity_provider_configs WHERE id = ?`, id)
	return s.scanIdentityProviderConfig(row)
}

func (s *Store) ListIdentityProviderConfigsForOrganization(organizationID string) []*models.IdentityProviderConfig {
	rows, err := s.db.Query(`SELECT id, organization_id, name, type, enabled, domains_json,
		issuer, client_id, client_secret, scim_token, scim_token_expires_at, scim_token_rotated_at, scopes, auto_discovery,
		claim_mapping_json, group_role_mapping_json, created_at, updated_at
		FROM identity_provider_configs WHERE organization_id = ? ORDER BY created_at ASC`, organizationID)
	if err != nil {
		log.Printf("[STORE] Failed to list IdP configs for organization %s: %v", organizationID, err)
		return nil
	}
	defer rows.Close()

	return s.scanIdentityProviderConfigs(rows)
}

// FindIdentityProviderByDomain searches for an IdP whose domains list contains the given email domain.
func (s *Store) FindIdentityProviderByDomain(domain string) (*models.IdentityProviderConfig, bool) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, false
	}

	rows, err := s.db.Query(`SELECT id, organization_id, name, type, enabled, domains_json,
		issuer, client_id, client_secret, scim_token, scim_token_expires_at, scim_token_rotated_at, scopes, auto_discovery,
		claim_mapping_json, group_role_mapping_json, created_at, updated_at
		FROM identity_provider_configs WHERE enabled = 1`)
	if err != nil {
		log.Printf("[STORE] Failed to query IdP configs for domain search: %v", err)
		return nil, false
	}
	defer rows.Close()

	for rows.Next() {
		cfg, ok := s.scanIdentityProviderConfig(rows)
		if !ok || cfg == nil {
			continue
		}
		for _, d := range cfg.Domains {
			if strings.EqualFold(d, domain) {
				return cfg, true
			}
		}
	}
	return nil, false
}

func normalizeDomain(domain string) string {
	return strings.TrimSpace(strings.ToLower(domain))
}

func normalizeDomainAliases(primary string, aliases []string) []string {
	primary = normalizeDomain(primary)
	seen := map[string]bool{}
	if primary != "" {
		seen[primary] = true
	}
	normalized := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		alias = normalizeDomain(alias)
		if alias == "" || seen[alias] {
			continue
		}
		seen[alias] = true
		normalized = append(normalized, alias)
	}
	return normalized
}

// GetDefaultIdentityProviderForOrganization returns the default IdP for an organization.
func (s *Store) GetDefaultIdentityProviderForOrganization(organizationID string) (*models.IdentityProviderConfig, bool) {
	organization, found := s.GetOrganization(organizationID)
	if !found || organization.DefaultIdPID == "" {
		return nil, false
	}
	return s.GetIdentityProviderConfig(organization.DefaultIdPID)
}

func (s *Store) DeleteIdentityProviderConfig(id string) bool {
	result, err := s.db.Exec("DELETE FROM identity_provider_configs WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

func (s *Store) scanIdentityProviderConfig(row interface {
	Scan(dest ...interface{}) error
}) (*models.IdentityProviderConfig, bool) {
	cfg := &models.IdentityProviderConfig{}
	var enabled, autoDiscovery int
	var domainsJSON, claimMappingJSON, groupRoleMappingJSON, scimTokenExpiresAt, scimTokenRotatedAt, createdAt, updatedAt string

	err := row.Scan(&cfg.ID, &cfg.OrganizationID, &cfg.Name, &cfg.Type, &enabled,
		&domainsJSON, &cfg.Issuer, &cfg.ClientID, &cfg.ClientSecret, &cfg.SCIMToken,
		&scimTokenExpiresAt, &scimTokenRotatedAt, &cfg.Scopes, &autoDiscovery, &claimMappingJSON, &groupRoleMappingJSON,
		&createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}

	cfg.Enabled = i2b(enabled)
	cfg.AutoDiscovery = i2b(autoDiscovery)
	cfg.Domains = fromJSON[[]string](domainsJSON)
	if cfg.Domains == nil {
		cfg.Domains = []string{}
	}
	cfg.ClaimMapping = fromJSON[map[string]string](claimMappingJSON)
	if cfg.ClaimMapping == nil {
		cfg.ClaimMapping = map[string]string{}
	}
	cfg.GroupRoleMapping = fromJSON[[]models.GroupRoleRule](groupRoleMappingJSON)
	if cfg.GroupRoleMapping == nil {
		cfg.GroupRoleMapping = []models.GroupRoleRule{}
	}
	cfg.SCIMTokenExpiresAt = parseTime(scimTokenExpiresAt)
	cfg.SCIMTokenRotatedAt = parseTime(scimTokenRotatedAt)
	cfg.CreatedAt = parseTime(createdAt)
	cfg.UpdatedAt = parseTime(updatedAt)
	return cfg, true
}

func (s *Store) scanIdentityProviderConfigs(rows *sql.Rows) []*models.IdentityProviderConfig {
	var configs []*models.IdentityProviderConfig
	for rows.Next() {
		if cfg, ok := s.scanIdentityProviderConfig(rows); ok {
			configs = append(configs, cfg)
		}
	}
	return configs
}

func (s *Store) scanOrganization(row *sql.Row) (*models.Organization, bool) {
	t := &models.Organization{}
	var createdAt, updatedAt, domainsJSON string
	var enabled int
	err := row.Scan(&t.ID, &t.Name, &t.Domain, &t.Description, &enabled, &t.DefaultIdPID, &domainsJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}
	t.Enabled = i2b(enabled)
	t.Domains = fromJSON[[]string](domainsJSON)
	if t.Domains == nil {
		t.Domains = []string{}
	}
	t.CreatedAt = parseTime(createdAt)
	t.UpdatedAt = parseTime(updatedAt)
	return t, true
}
