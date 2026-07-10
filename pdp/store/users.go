package store

import (
	"database/sql"
	"log"
	"strings"

	"pdp/models"
)

// User operations

const userSelectColumns = `id, username, email, password_hash, password_change_required, password_changed_at, totp_secret, mfa_methods_json,
		last_totp_counter, role, disabled, organization_id, external_subject, auth_source, created_at, updated_at, last_login_at`

func (s *Store) GetUser(id string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT `+userSelectColumns+` FROM users WHERE id = ?`, id)
	return s.scanUser(row)
}

func (s *Store) GetUserByUsername(username string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT `+userSelectColumns+` FROM users WHERE username = ?`, username)
	return s.scanUser(row)
}

func (s *Store) GetUserByEmail(email string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT `+userSelectColumns+` FROM users WHERE lower(email) = lower(?)`, strings.TrimSpace(email))
	return s.scanUser(row)
}

func (s *Store) scanUser(row *sql.Row) (*models.User, bool) {
	u := &models.User{}
	var disabled, passwordChangeRequired int
	var createdAt, updatedAt, lastLoginAt, passwordChangedAt, mfaMethodsJSON string

	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &passwordChangeRequired, &passwordChangedAt, &u.TOTPSecret,
		&mfaMethodsJSON, &u.LastTOTPCounter, &u.Role, &disabled, &u.OrganizationID, &u.ExternalSubject, &u.AuthSource, &createdAt, &updatedAt, &lastLoginAt)
	if err != nil {
		return nil, false
	}

	u.MFAMethods = fromJSON[[]string](mfaMethodsJSON)
	if u.MFAMethods == nil {
		u.MFAMethods = []string{}
	}
	u.PasswordChangeRequired = i2b(passwordChangeRequired)
	u.PasswordChangedAt = parseTime(passwordChangedAt)
	u.Disabled = i2b(disabled)
	u.CreatedAt = parseTime(createdAt)
	u.UpdatedAt = parseTime(updatedAt)
	u.LastLoginAt = parseTime(lastLoginAt)
	return u, true
}

func (s *Store) SaveUser(user *models.User) {
	methods := user.MFAMethods
	if methods == nil {
		methods = []string{}
	}
	_, err := s.db.Exec(`INSERT INTO users
		(id, username, email, password_hash, password_change_required, password_changed_at, totp_secret, mfa_methods_json, last_totp_counter, role, disabled,
		 organization_id, external_subject, auth_source, created_at, updated_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			username = EXCLUDED.username,
			email = EXCLUDED.email,
			password_hash = EXCLUDED.password_hash,
			password_change_required = EXCLUDED.password_change_required,
			password_changed_at = EXCLUDED.password_changed_at,
			totp_secret = EXCLUDED.totp_secret,
			mfa_methods_json = EXCLUDED.mfa_methods_json,
			last_totp_counter = EXCLUDED.last_totp_counter,
			role = EXCLUDED.role,
			disabled = EXCLUDED.disabled,
			organization_id = EXCLUDED.organization_id,
			external_subject = EXCLUDED.external_subject,
			auth_source = EXCLUDED.auth_source,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at,
			last_login_at = EXCLUDED.last_login_at`,
		user.ID, user.Username, user.Email, user.PasswordHash, b2i(user.PasswordChangeRequired), fmtTime(user.PasswordChangedAt), user.TOTPSecret,
		toJSON(methods), user.LastTOTPCounter, user.Role, b2i(user.Disabled),
		user.OrganizationID, user.ExternalSubject, user.AuthSource,
		fmtTime(user.CreatedAt), fmtTime(user.UpdatedAt), fmtTime(user.LastLoginAt))
	if err != nil {
		log.Printf("[STORE] Failed to save user %s: %v", user.ID, err)
	}
}

func (s *Store) ListUsers() []*models.User {
	rows, err := s.db.Query(`SELECT ` + userSelectColumns + ` FROM users`)
	if err != nil {
		log.Printf("[STORE] Failed to list users: %v", err)
		return nil
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		u := &models.User{}
		var disabled, passwordChangeRequired int
		var createdAt, updatedAt, lastLoginAt, passwordChangedAt, mfaMethodsJSON string

		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &passwordChangeRequired, &passwordChangedAt, &u.TOTPSecret,
			&mfaMethodsJSON, &u.LastTOTPCounter, &u.Role, &disabled, &u.OrganizationID, &u.ExternalSubject, &u.AuthSource, &createdAt, &updatedAt, &lastLoginAt); err != nil {
			continue
		}

		u.PasswordChangeRequired = i2b(passwordChangeRequired)
		u.PasswordChangedAt = parseTime(passwordChangedAt)
		u.MFAMethods = fromJSON[[]string](mfaMethodsJSON)
		if u.MFAMethods == nil {
			u.MFAMethods = []string{}
		}
		u.Disabled = i2b(disabled)
		u.CreatedAt = parseTime(createdAt)
		u.UpdatedAt = parseTime(updatedAt)
		u.LastLoginAt = parseTime(lastLoginAt)
		users = append(users, u)
	}
	return users
}

func (s *Store) DeleteUser(id string) {
	s.db.Exec("DELETE FROM users WHERE id = ?", id)
}

// Login attempt tracking
