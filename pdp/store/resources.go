package store

import (
	"database/sql"
	"log"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Resource operations
// ─────────────────────────────────────────────

func (s *Store) GetResource(id string) (*models.Resource, bool) {
	row := s.db.QueryRow(`SELECT id, name, description, type, host, port, external_url, enabled,
		tags_json, metadata_json, tenant_id, gateway_id, client_id, client_secret,
		allowed_roles_json, created_at, updated_at
		FROM resources WHERE id = ?`, id)
	return s.scanResource(row)
}

func (s *Store) scanResource(row *sql.Row) (*models.Resource, bool) {
	r := &models.Resource{}
	var enabled int
	var tagsJSON, metaJSON, rolesJSON, createdAt, updatedAt string

	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Type, &r.Host, &r.Port, &r.ExternalURL,
		&enabled, &tagsJSON, &metaJSON, &r.TenantID, &r.GatewayID, &r.ClientID, &r.ClientSecret,
		&rolesJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}

	r.Enabled = i2b(enabled)
	r.Tags = fromJSON[[]string](tagsJSON)
	r.Metadata = fromJSON[map[string]string](metaJSON)
	r.AllowedRoles = fromJSON[[]string](rolesJSON)
	r.CreatedAt = parseTime(createdAt)
	r.UpdatedAt = parseTime(updatedAt)
	return r, true
}

func (s *Store) SaveResource(res *models.Resource) {
	tags := res.Tags
	if tags == nil {
		tags = []string{}
	}
	meta := res.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	roles := res.AllowedRoles
	if roles == nil {
		roles = []string{}
	}

	_, err := s.db.Exec(`INSERT OR REPLACE INTO resources
		(id, name, description, type, host, port, external_url, enabled,
		 tags_json, metadata_json, tenant_id, gateway_id, client_id, client_secret,
		 allowed_roles_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		res.ID, res.Name, res.Description, res.Type, res.Host, res.Port, res.ExternalURL,
		b2i(res.Enabled), toJSON(tags), toJSON(meta), res.TenantID, res.GatewayID, res.ClientID, res.ClientSecret,
		toJSON(roles), fmtTime(res.CreatedAt), fmtTime(res.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save resource %s: %v", res.ID, err)
	}
}

func (s *Store) ListResources() []*models.Resource {
	rows, err := s.db.Query(`SELECT id, name, description, type, host, port, external_url, enabled,
		tags_json, metadata_json, tenant_id, gateway_id, client_id, client_secret,
		allowed_roles_json, created_at, updated_at FROM resources`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var resources []*models.Resource
	for rows.Next() {
		r := &models.Resource{}
		var enabled int
		var tagsJSON, metaJSON, rolesJSON, createdAt, updatedAt string

		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Type, &r.Host, &r.Port, &r.ExternalURL,
			&enabled, &tagsJSON, &metaJSON, &r.TenantID, &r.GatewayID, &r.ClientID, &r.ClientSecret,
			&rolesJSON, &createdAt, &updatedAt); err != nil {
			continue
		}

		r.Enabled = i2b(enabled)
		r.Tags = fromJSON[[]string](tagsJSON)
		r.Metadata = fromJSON[map[string]string](metaJSON)
		r.AllowedRoles = fromJSON[[]string](rolesJSON)
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		resources = append(resources, r)
	}
	return resources
}

func (s *Store) ListResourcesByTenant(tenantID string) []*models.Resource {
	rows, err := s.db.Query(`SELECT id, name, description, type, host, port, external_url, enabled,
		tags_json, metadata_json, tenant_id, gateway_id, client_id, client_secret,
		allowed_roles_json, created_at, updated_at FROM resources
		WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanResources(rows)
}

func (s *Store) scanResources(rows *sql.Rows) []*models.Resource {
	var resources []*models.Resource
	for rows.Next() {
		r := &models.Resource{}
		var enabled int
		var tagsJSON, metaJSON, rolesJSON, createdAt, updatedAt string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Type, &r.Host, &r.Port, &r.ExternalURL,
			&enabled, &tagsJSON, &metaJSON, &r.TenantID, &r.GatewayID, &r.ClientID, &r.ClientSecret,
			&rolesJSON, &createdAt, &updatedAt); err != nil {
			continue
		}
		r.Enabled = i2b(enabled)
		r.Tags = fromJSON[[]string](tagsJSON)
		r.Metadata = fromJSON[map[string]string](metaJSON)
		r.AllowedRoles = fromJSON[[]string](rolesJSON)
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		resources = append(resources, r)
	}
	return resources
}

// GetResourceByClientID is retained for legacy databases where protected
// resources briefly carried OIDC-style client IDs.
func (s *Store) GetResourceByClientID(clientID string) (*models.Resource, bool) {
	row := s.db.QueryRow(`SELECT id, name, description, type, host, port, external_url, enabled,
		tags_json, metadata_json, tenant_id, gateway_id, client_id, client_secret,
		allowed_roles_json, created_at, updated_at
		FROM resources WHERE client_id = ?`, clientID)
	return s.scanResource(row)
}

func (s *Store) DeleteResource(id string) bool {
	result, err := s.db.Exec("DELETE FROM resources WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}
