package store

import (
	"database/sql"
	"log"
	"strings"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Tenant operations
// ─────────────────────────────────────────────

func (s *Store) SaveTenant(t *models.Tenant) {
	t.Domain = normalizeDomain(t.Domain)
	t.Domains = normalizeDomainAliases(t.Domain, t.Domains)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO tenants
		(id, name, domain, description, enabled, default_idp_id, domains_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Domain, t.Description, b2i(t.Enabled),
		t.DefaultIdPID, toJSON(t.Domains),
		fmtTime(t.CreatedAt), fmtTime(t.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save tenant %s: %v", t.ID, err)
	}
}

func (s *Store) GetTenant(id string) (*models.Tenant, bool) {
	row := s.db.QueryRow(`SELECT id, name, domain, description, enabled, default_idp_id, domains_json, created_at, updated_at
		FROM tenants WHERE id = ?`, id)
	return s.scanTenant(row)
}

func (s *Store) ListTenants() []*models.Tenant {
	rows, err := s.db.Query(`SELECT id, name, domain, description, enabled, default_idp_id, domains_json, created_at, updated_at
		FROM tenants ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("[STORE] Failed to list tenants: %v", err)
		return nil
	}
	defer rows.Close()

	var tenants []*models.Tenant
	for rows.Next() {
		t := &models.Tenant{}
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
		tenants = append(tenants, t)
	}
	return tenants
}

func (s *Store) DeleteTenant(id string) bool {
	result, err := s.db.Exec("DELETE FROM tenants WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

// ─────────────────────────────────────────────
// Identity Provider Config operations
// ─────────────────────────────────────────────

// FindTenantByDomain searches a tenant by primary domain or domain aliases.
func (s *Store) FindTenantByDomain(domain string) (*models.Tenant, bool) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, false
	}
	for _, tenant := range s.ListTenants() {
		if tenant == nil {
			continue
		}
		if normalizeDomain(tenant.Domain) == domain {
			return tenant, true
		}
		for _, alias := range tenant.Domains {
			if normalizeDomain(alias) == domain {
				return tenant, true
			}
		}
	}
	return nil, false
}

func (s *Store) SaveIdentityProviderConfig(cfg *models.IdentityProviderConfig) {
	cfg.Domains = normalizeDomainAliases("", cfg.Domains)
	claimMapping := cfg.ClaimMapping
	if claimMapping == nil {
		claimMapping = map[string]string{}
	}
	groupRoleMapping := cfg.GroupRoleMapping
	if groupRoleMapping == nil {
		groupRoleMapping = []models.GroupRoleRule{}
	}

	_, err := s.db.Exec(`INSERT OR REPLACE INTO identity_provider_configs
		(id, tenant_id, name, type, enabled, domains_json, issuer, client_id, client_secret,
		 scopes, auto_discovery, claim_mapping_json, group_role_mapping_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cfg.ID, cfg.TenantID, cfg.Name, cfg.Type, b2i(cfg.Enabled),
		toJSON(cfg.Domains), cfg.Issuer, cfg.ClientID, cfg.ClientSecret,
		cfg.Scopes, b2i(cfg.AutoDiscovery), toJSON(claimMapping), toJSON(groupRoleMapping),
		fmtTime(cfg.CreatedAt), fmtTime(cfg.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save IdP config %s: %v", cfg.ID, err)
	}
}

func (s *Store) GetIdentityProviderConfig(id string) (*models.IdentityProviderConfig, bool) {
	row := s.db.QueryRow(`SELECT id, tenant_id, name, type, enabled, domains_json,
		issuer, client_id, client_secret, scopes, auto_discovery,
		claim_mapping_json, group_role_mapping_json, created_at, updated_at
		FROM identity_provider_configs WHERE id = ?`, id)
	return s.scanIdentityProviderConfig(row)
}

func (s *Store) ListIdentityProviderConfigsForTenant(tenantID string) []*models.IdentityProviderConfig {
	rows, err := s.db.Query(`SELECT id, tenant_id, name, type, enabled, domains_json,
		issuer, client_id, client_secret, scopes, auto_discovery,
		claim_mapping_json, group_role_mapping_json, created_at, updated_at
		FROM identity_provider_configs WHERE tenant_id = ? ORDER BY created_at ASC`, tenantID)
	if err != nil {
		log.Printf("[STORE] Failed to list IdP configs for tenant %s: %v", tenantID, err)
		return nil
	}
	defer rows.Close()

	return s.scanIdentityProviderConfigs(rows)
}

// FindIdentityProviderByDomain searches for an IdP whose domains list contains
// the given email domain. Used by Home Realm Discovery (HRD).
func (s *Store) FindIdentityProviderByDomain(domain string) (*models.IdentityProviderConfig, bool) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, false
	}

	rows, err := s.db.Query(`SELECT id, tenant_id, name, type, enabled, domains_json,
		issuer, client_id, client_secret, scopes, auto_discovery,
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

// GetDefaultIdentityProviderForTenant returns the default IdP for a tenant,
// by looking up the tenant's DefaultIdPID field. Returns nil if not set.
func (s *Store) GetDefaultIdentityProviderForTenant(tenantID string) (*models.IdentityProviderConfig, bool) {
	tenant, found := s.GetTenant(tenantID)
	if !found || tenant.DefaultIdPID == "" {
		return nil, false
	}
	return s.GetIdentityProviderConfig(tenant.DefaultIdPID)
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
	var domainsJSON, claimMappingJSON, groupRoleMappingJSON, createdAt, updatedAt string

	err := row.Scan(&cfg.ID, &cfg.TenantID, &cfg.Name, &cfg.Type, &enabled,
		&domainsJSON, &cfg.Issuer, &cfg.ClientID, &cfg.ClientSecret,
		&cfg.Scopes, &autoDiscovery, &claimMappingJSON, &groupRoleMappingJSON,
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

func (s *Store) scanTenant(row *sql.Row) (*models.Tenant, bool) {
	t := &models.Tenant{}
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
