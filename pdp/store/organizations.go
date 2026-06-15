package store

import (
	"database/sql"
	"log"
	"strings"
	"time"

	"pdp/models"
)

func (s *Store) SaveOrganizationMembership(membership *models.OrganizationMembership) {
	if membership == nil {
		return
	}
	userID := strings.TrimSpace(membership.UserID)
	organizationID := strings.TrimSpace(membership.OrganizationID)
	if userID == "" || organizationID == "" {
		return
	}
	role := strings.TrimSpace(membership.Role)
	if role == "" {
		role = "platform_admin"
	}
	createdAt := membership.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO organization_memberships
		(user_id, organization_id, role, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id, organization_id) DO UPDATE SET
			role = EXCLUDED.role,
			created_at = EXCLUDED.created_at`,
		userID, organizationID, role, fmtTime(createdAt))
	if err != nil {
		log.Printf("[STORE] Failed to save organization membership user=%s organization=%s: %v", userID, organizationID, err)
	}
}

func (s *Store) UserHasOrganizationAccess(userID, organizationID string) bool {
	userID = strings.TrimSpace(userID)
	organizationID = strings.TrimSpace(organizationID)
	if userID == "" || organizationID == "" {
		return false
	}
	var count int
	err := s.db.QueryRow(`SELECT COUNT(1)
		FROM organization_memberships
		WHERE user_id = ? AND organization_id = ?`, userID, organizationID).Scan(&count)
	return err == nil && count > 0
}

func (s *Store) ListOrganizationsForUser(userID string) []*models.Organization {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	rows, err := s.db.Query(`SELECT o.id, o.name, o.domain, o.description, o.enabled,
			o.default_idp_id, o.domains_json, o.created_at, o.updated_at
		FROM organizations o
		INNER JOIN organization_memberships m ON m.organization_id = o.id
		WHERE m.user_id = ?
		ORDER BY o.created_at DESC`, userID)
	if err != nil {
		log.Printf("[STORE] Failed to list organizations for user %s: %v", userID, err)
		return nil
	}
	defer rows.Close()
	return scanOrganizations(rows)
}

func (s *Store) ListOrganizationIDsForUser(userID string) map[string]bool {
	userID = strings.TrimSpace(userID)
	ids := map[string]bool{}
	if userID == "" {
		return ids
	}
	rows, err := s.db.Query(`SELECT organization_id FROM organization_memberships WHERE user_id = ?`, userID)
	if err != nil {
		log.Printf("[STORE] Failed to list organization ids for user %s: %v", userID, err)
		return ids
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil && strings.TrimSpace(id) != "" {
			ids[strings.TrimSpace(id)] = true
		}
	}
	return ids
}

func (s *Store) DeleteOrganizationMemberships(organizationID string) {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return
	}
	if _, err := s.db.Exec(`DELETE FROM organization_memberships WHERE organization_id = ?`, organizationID); err != nil {
		log.Printf("[STORE] Failed to delete memberships for organization %s: %v", organizationID, err)
	}
}

func scanOrganizations(rows *sql.Rows) []*models.Organization {
	var organizations []*models.Organization
	for rows.Next() {
		org := &models.Organization{}
		var enabled int
		var createdAt, updatedAt, domainsJSON string
		if err := rows.Scan(&org.ID, &org.Name, &org.Domain, &org.Description, &enabled,
			&org.DefaultIdPID, &domainsJSON, &createdAt, &updatedAt); err != nil {
			continue
		}
		org.Enabled = i2b(enabled)
		org.Domains = fromJSON[[]string](domainsJSON)
		if org.Domains == nil {
			org.Domains = []string{}
		}
		org.CreatedAt = parseTime(createdAt)
		org.UpdatedAt = parseTime(updatedAt)
		organizations = append(organizations, org)
	}
	return organizations
}
