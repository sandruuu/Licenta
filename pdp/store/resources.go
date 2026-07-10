package store

import (
	"database/sql"

	"pdp/models"
)

// Resource operations

func (s *Store) GetResource(id string) (*models.Resource, bool) {
	row := s.db.QueryRow(`SELECT id, name, description, type, host, external_port, internal_port, external_url, enabled,
		tags_json, metadata_json, organization_id, gateway_id, created_at, updated_at
		FROM resources WHERE id = ?`, id)
	return s.scanResource(row)
}

func (s *Store) scanResource(row *sql.Row) (*models.Resource, bool) {
	r := &models.Resource{}
	var enabled int
	var tagsJSON, metaJSON, createdAt, updatedAt string

	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Type, &r.Host, &r.ExternalPort, &r.InternalPort, &r.ExternalURL,
		&enabled, &tagsJSON, &metaJSON, &r.OrganizationID, &r.GatewayID, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}

	r.Enabled = i2b(enabled)
	r.Tags = fromJSON[[]string](tagsJSON)
	r.Metadata = fromJSON[map[string]string](metaJSON)
	r.CreatedAt = parseTime(createdAt)
	r.UpdatedAt = parseTime(updatedAt)
	return r, true
}

func (s *Store) SaveResource(res *models.Resource) error {
	tags := res.Tags
	if tags == nil {
		tags = []string{}
	}
	meta := res.Metadata
	if meta == nil {
		meta = map[string]string{}
	}

	_, err := s.db.Exec(`INSERT INTO resources
		(id, name, description, type, host, external_port, internal_port, external_url, enabled,
		 tags_json, metadata_json, organization_id, gateway_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			type = EXCLUDED.type,
			host = EXCLUDED.host,
			external_port = EXCLUDED.external_port,
			internal_port = EXCLUDED.internal_port,
			external_url = EXCLUDED.external_url,
			enabled = EXCLUDED.enabled,
			tags_json = EXCLUDED.tags_json,
			metadata_json = EXCLUDED.metadata_json,
			organization_id = EXCLUDED.organization_id,
			gateway_id = EXCLUDED.gateway_id,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
		res.ID, res.Name, res.Description, res.Type, res.Host, res.ExternalPort, res.InternalPort, res.ExternalURL,
		b2i(res.Enabled), toJSON(tags), toJSON(meta), res.OrganizationID, res.GatewayID,
		fmtTime(res.CreatedAt), fmtTime(res.UpdatedAt))
	return err
}

func (s *Store) ListResources() []*models.Resource {
	rows, err := s.db.Query(`SELECT id, name, description, type, host, external_port, internal_port, external_url, enabled,
		tags_json, metadata_json, organization_id, gateway_id, created_at, updated_at FROM resources`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanResources(rows)
}

func (s *Store) ListResourcesByOrganization(organizationID string) []*models.Resource {
	rows, err := s.db.Query(`SELECT id, name, description, type, host, external_port, internal_port, external_url, enabled,
		tags_json, metadata_json, organization_id, gateway_id, created_at, updated_at FROM resources
		WHERE organization_id = ?`, organizationID)
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
		var tagsJSON, metaJSON, createdAt, updatedAt string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Type, &r.Host, &r.ExternalPort, &r.InternalPort, &r.ExternalURL,
			&enabled, &tagsJSON, &metaJSON, &r.OrganizationID, &r.GatewayID, &createdAt, &updatedAt); err != nil {
			continue
		}
		r.Enabled = i2b(enabled)
		r.Tags = fromJSON[[]string](tagsJSON)
		r.Metadata = fromJSON[map[string]string](metaJSON)
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		resources = append(resources, r)
	}
	return resources
}

func (s *Store) DeleteResource(id string) bool {
	result, err := s.db.Exec("DELETE FROM resources WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}
