package store

import (
	"log"
	"strings"
	"time"

	"pdp/models"
)

// SaveDirectoryUser upserts a user mirrored from an external directory.
func (s *Store) SaveDirectoryUser(user *models.DirectoryUser) {
	if user == nil {
		return
	}
	user.OrganizationID = strings.TrimSpace(user.OrganizationID)
	user.IdPID = strings.TrimSpace(user.IdPID)
	user.ID = strings.TrimSpace(user.ID)
	user.ExternalID = strings.TrimSpace(user.ExternalID)
	user.UserName = strings.TrimSpace(user.UserName)
	user.Email = strings.TrimSpace(user.Email)
	if user.Attributes == nil {
		user.Attributes = map[string]string{}
	}

	_, err := s.db.Exec(`INSERT INTO directory_users
		(id, organization_id, idp_id, external_id, user_name, display_name, email, active,
		 attributes_json, raw_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			organization_id = EXCLUDED.organization_id,
			idp_id = EXCLUDED.idp_id,
			external_id = EXCLUDED.external_id,
			user_name = EXCLUDED.user_name,
			display_name = EXCLUDED.display_name,
			email = EXCLUDED.email,
			active = EXCLUDED.active,
			attributes_json = EXCLUDED.attributes_json,
			raw_json = EXCLUDED.raw_json,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
		user.ID, user.OrganizationID, user.IdPID, user.ExternalID, user.UserName, user.DisplayName,
		user.Email, b2i(user.Active), toJSON(user.Attributes), user.RawJSON,
		fmtTime(user.CreatedAt), fmtTime(user.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save directory user %s: %v", user.ID, err)
	}
}

func (s *Store) GetDirectoryUser(organizationID, idpID, id string) (*models.DirectoryUser, bool) {
	row := s.db.QueryRow(`SELECT id, organization_id, idp_id, external_id, user_name, display_name,
		email, active, attributes_json, raw_json, created_at, updated_at
		FROM directory_users WHERE organization_id = ? AND idp_id = ? AND id = ?`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID), strings.TrimSpace(id))
	return s.scanDirectoryUser(row)
}

func (s *Store) FindDirectoryUserByExternalID(organizationID, idpID, externalID string) (*models.DirectoryUser, bool) {
	externalID = strings.TrimSpace(externalID)
	if externalID == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, organization_id, idp_id, external_id, user_name, display_name,
		email, active, attributes_json, raw_json, created_at, updated_at
		FROM directory_users WHERE organization_id = ? AND idp_id = ? AND external_id = ?`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID), externalID)
	return s.scanDirectoryUser(row)
}

func (s *Store) FindDirectoryUserByUserName(organizationID, idpID, userName string) (*models.DirectoryUser, bool) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, organization_id, idp_id, external_id, user_name, display_name,
		email, active, attributes_json, raw_json, created_at, updated_at
		FROM directory_users WHERE organization_id = ? AND idp_id = ? AND user_name = ?`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID), userName)
	return s.scanDirectoryUser(row)
}

func (s *Store) FindDirectoryUserByEmail(organizationID, idpID, email string) (*models.DirectoryUser, bool) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, organization_id, idp_id, external_id, user_name, display_name,
		email, active, attributes_json, raw_json, created_at, updated_at
		FROM directory_users WHERE organization_id = ? AND idp_id = ? AND lower(email) = lower(?)`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID), email)
	return s.scanDirectoryUser(row)
}

func (s *Store) ListDirectoryUsers(organizationID, idpID string) []*models.DirectoryUser {
	rows, err := s.db.Query(`SELECT id, organization_id, idp_id, external_id, user_name, display_name,
		email, active, attributes_json, raw_json, created_at, updated_at
		FROM directory_users WHERE organization_id = ? AND idp_id = ? ORDER BY user_name ASC`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID))
	if err != nil {
		log.Printf("[STORE] Failed to list directory users: %v", err)
		return nil
	}
	defer rows.Close()

	var users []*models.DirectoryUser
	for rows.Next() {
		if user, ok := s.scanDirectoryUser(rows); ok {
			users = append(users, user)
		}
	}
	return users
}

func (s *Store) ListDirectoryUsersFiltered(organizationID, idpID string) []*models.DirectoryUser {
	organizationID = strings.TrimSpace(organizationID)
	idpID = strings.TrimSpace(idpID)
	rows, err := s.db.Query(`SELECT id, organization_id, idp_id, external_id, user_name, display_name,
		email, active, attributes_json, raw_json, created_at, updated_at
		FROM directory_users
		WHERE (? = '' OR organization_id = ?) AND (? = '' OR idp_id = ?)
		ORDER BY organization_id ASC, idp_id ASC, user_name ASC`,
		organizationID, organizationID, idpID, idpID)
	if err != nil {
		log.Printf("[STORE] Failed to list filtered directory users: %v", err)
		return nil
	}
	defer rows.Close()

	var users []*models.DirectoryUser
	for rows.Next() {
		if user, ok := s.scanDirectoryUser(rows); ok {
			users = append(users, user)
		}
	}
	return users
}

// SaveDirectoryGroup upserts a group mirrored from an external directory.
func (s *Store) SaveDirectoryGroup(group *models.DirectoryGroup) {
	if group == nil {
		return
	}
	group.OrganizationID = strings.TrimSpace(group.OrganizationID)
	group.IdPID = strings.TrimSpace(group.IdPID)
	group.ID = strings.TrimSpace(group.ID)
	group.ExternalID = strings.TrimSpace(group.ExternalID)
	group.DisplayName = strings.TrimSpace(group.DisplayName)

	_, err := s.db.Exec(`INSERT INTO directory_groups
		(id, organization_id, idp_id, external_id, display_name, raw_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			organization_id = EXCLUDED.organization_id,
			idp_id = EXCLUDED.idp_id,
			external_id = EXCLUDED.external_id,
			display_name = EXCLUDED.display_name,
			raw_json = EXCLUDED.raw_json,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
		group.ID, group.OrganizationID, group.IdPID, group.ExternalID, group.DisplayName,
		group.RawJSON, fmtTime(group.CreatedAt), fmtTime(group.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save directory group %s: %v", group.ID, err)
	}
}

func (s *Store) GetDirectoryGroup(organizationID, idpID, id string) (*models.DirectoryGroup, bool) {
	row := s.db.QueryRow(`SELECT id, organization_id, idp_id, external_id, display_name,
		raw_json, created_at, updated_at
		FROM directory_groups WHERE organization_id = ? AND idp_id = ? AND id = ?`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID), strings.TrimSpace(id))
	return s.scanDirectoryGroup(row)
}

func (s *Store) FindDirectoryGroupByExternalID(organizationID, idpID, externalID string) (*models.DirectoryGroup, bool) {
	externalID = strings.TrimSpace(externalID)
	if externalID == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, organization_id, idp_id, external_id, display_name,
		raw_json, created_at, updated_at
		FROM directory_groups WHERE organization_id = ? AND idp_id = ? AND external_id = ?`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID), externalID)
	return s.scanDirectoryGroup(row)
}

func (s *Store) FindDirectoryGroupByDisplayName(organizationID, idpID, displayName string) (*models.DirectoryGroup, bool) {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, organization_id, idp_id, external_id, display_name,
		raw_json, created_at, updated_at
		FROM directory_groups WHERE organization_id = ? AND idp_id = ? AND display_name = ?`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID), displayName)
	return s.scanDirectoryGroup(row)
}

func (s *Store) ListDirectoryGroups(organizationID, idpID string) []*models.DirectoryGroup {
	rows, err := s.db.Query(`SELECT id, organization_id, idp_id, external_id, display_name,
		raw_json, created_at, updated_at
		FROM directory_groups WHERE organization_id = ? AND idp_id = ? ORDER BY display_name ASC`,
		strings.TrimSpace(organizationID), strings.TrimSpace(idpID))
	if err != nil {
		log.Printf("[STORE] Failed to list directory groups: %v", err)
		return nil
	}
	defer rows.Close()

	var groups []*models.DirectoryGroup
	for rows.Next() {
		if group, ok := s.scanDirectoryGroup(rows); ok {
			groups = append(groups, group)
		}
	}
	return groups
}

func (s *Store) ListDirectoryGroupsFiltered(organizationID, idpID string) []*models.DirectoryGroup {
	organizationID = strings.TrimSpace(organizationID)
	idpID = strings.TrimSpace(idpID)
	rows, err := s.db.Query(`SELECT id, organization_id, idp_id, external_id, display_name,
		raw_json, created_at, updated_at
		FROM directory_groups
		WHERE (? = '' OR organization_id = ?) AND (? = '' OR idp_id = ?)
		ORDER BY organization_id ASC, idp_id ASC, display_name ASC`,
		organizationID, organizationID, idpID, idpID)
	if err != nil {
		log.Printf("[STORE] Failed to list filtered directory groups: %v", err)
		return nil
	}
	defer rows.Close()

	var groups []*models.DirectoryGroup
	for rows.Next() {
		if group, ok := s.scanDirectoryGroup(rows); ok {
			groups = append(groups, group)
		}
	}
	return groups
}

func (s *Store) DeleteDirectoryGroup(organizationID, idpID, groupID string) bool {
	organizationID = strings.TrimSpace(organizationID)
	idpID = strings.TrimSpace(idpID)
	groupID = strings.TrimSpace(groupID)
	tx, err := s.db.Begin()
	if err != nil {
		return false
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM directory_group_members WHERE organization_id = ? AND idp_id = ? AND group_id = ?`,
		organizationID, idpID, groupID); err != nil {
		return false
	}
	result, err := tx.Exec(`DELETE FROM directory_groups WHERE organization_id = ? AND idp_id = ? AND id = ?`,
		organizationID, idpID, groupID)
	if err != nil {
		return false
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return false
	}
	return tx.Commit() == nil
}

func (s *Store) ReplaceDirectoryGroupMembers(organizationID, idpID, groupID string, userIDs []string, createdAt time.Time) error {
	organizationID = strings.TrimSpace(organizationID)
	idpID = strings.TrimSpace(idpID)
	groupID = strings.TrimSpace(groupID)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM directory_group_members WHERE organization_id = ? AND idp_id = ? AND group_id = ?`,
		organizationID, idpID, groupID); err != nil {
		return err
	}
	for _, userID := range normalizeStringSet(userIDs) {
		if _, err := tx.Exec(`INSERT INTO directory_group_members
			(organization_id, idp_id, group_id, user_id, created_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (organization_id, idp_id, group_id, user_id) DO NOTHING`, organizationID, idpID, groupID, userID, fmtTime(createdAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AddDirectoryGroupMembers(organizationID, idpID, groupID string, userIDs []string, createdAt time.Time) error {
	organizationID = strings.TrimSpace(organizationID)
	idpID = strings.TrimSpace(idpID)
	groupID = strings.TrimSpace(groupID)
	for _, userID := range normalizeStringSet(userIDs) {
		if _, err := s.db.Exec(`INSERT INTO directory_group_members
			(organization_id, idp_id, group_id, user_id, created_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (organization_id, idp_id, group_id, user_id) DO NOTHING`, organizationID, idpID, groupID, userID, fmtTime(createdAt)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RemoveDirectoryGroupMembers(organizationID, idpID, groupID string, userIDs []string) error {
	organizationID = strings.TrimSpace(organizationID)
	idpID = strings.TrimSpace(idpID)
	groupID = strings.TrimSpace(groupID)
	for _, userID := range normalizeStringSet(userIDs) {
		if _, err := s.db.Exec(`DELETE FROM directory_group_members
			WHERE organization_id = ? AND idp_id = ? AND group_id = ? AND user_id = ?`,
			organizationID, idpID, groupID, userID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListDirectoryGroupMembers(organizationID, idpID, groupID string) []*models.DirectoryGroupMember {
	rows, err := s.db.Query(`SELECT organization_id, idp_id, group_id, user_id, created_at
		FROM directory_group_members WHERE organization_id = ? AND idp_id = ? AND group_id = ?
		ORDER BY user_id ASC`, strings.TrimSpace(organizationID), strings.TrimSpace(idpID), strings.TrimSpace(groupID))
	if err != nil {
		log.Printf("[STORE] Failed to list directory group members: %v", err)
		return nil
	}
	defer rows.Close()

	var members []*models.DirectoryGroupMember
	for rows.Next() {
		member := &models.DirectoryGroupMember{}
		var createdAt string
		if err := rows.Scan(&member.OrganizationID, &member.IdPID, &member.GroupID, &member.UserID, &createdAt); err != nil {
			continue
		}
		member.CreatedAt = parseTime(createdAt)
		members = append(members, member)
	}
	return members
}

func (s *Store) ListDirectoryGroupsForUser(organizationID, idpID, userID string) []*models.DirectoryGroup {
	rows, err := s.db.Query(`SELECT g.id, g.organization_id, g.idp_id, g.external_id, g.display_name,
		g.raw_json, g.created_at, g.updated_at
		FROM directory_groups g
		INNER JOIN directory_group_members m
			ON m.organization_id = g.organization_id AND m.idp_id = g.idp_id AND m.group_id = g.id
		WHERE m.organization_id = ? AND m.idp_id = ? AND m.user_id = ?
		ORDER BY g.display_name ASC`, strings.TrimSpace(organizationID), strings.TrimSpace(idpID), strings.TrimSpace(userID))
	if err != nil {
		log.Printf("[STORE] Failed to list directory groups for user: %v", err)
		return nil
	}
	defer rows.Close()

	var groups []*models.DirectoryGroup
	for rows.Next() {
		if group, ok := s.scanDirectoryGroup(rows); ok {
			groups = append(groups, group)
		}
	}
	return groups
}

func (s *Store) scanDirectoryUser(row interface {
	Scan(dest ...interface{}) error
}) (*models.DirectoryUser, bool) {
	user := &models.DirectoryUser{}
	var active int
	var attributesJSON, createdAt, updatedAt string
	err := row.Scan(&user.ID, &user.OrganizationID, &user.IdPID, &user.ExternalID,
		&user.UserName, &user.DisplayName, &user.Email, &active,
		&attributesJSON, &user.RawJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}
	user.Active = i2b(active)
	user.Attributes = fromJSON[map[string]string](attributesJSON)
	if user.Attributes == nil {
		user.Attributes = map[string]string{}
	}
	user.CreatedAt = parseTime(createdAt)
	user.UpdatedAt = parseTime(updatedAt)
	return user, true
}

func (s *Store) scanDirectoryGroup(row interface {
	Scan(dest ...interface{}) error
}) (*models.DirectoryGroup, bool) {
	group := &models.DirectoryGroup{}
	var createdAt, updatedAt string
	err := row.Scan(&group.ID, &group.OrganizationID, &group.IdPID, &group.ExternalID,
		&group.DisplayName, &group.RawJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}
	group.CreatedAt = parseTime(createdAt)
	group.UpdatedAt = parseTime(updatedAt)
	return group, true
}

func normalizeStringSet(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
