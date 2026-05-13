package store

import (
	"database/sql"
	"log"
	"time"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// User operations
// ─────────────────────────────────────────────

func (s *Store) GetUser(id string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT id, username, email, password_hash, totp_secret, mfa_methods_json,
		role, disabled, tenant_id, external_subject, auth_source, created_at, updated_at, last_login_at FROM users WHERE id = ?`, id)
	return s.scanUser(row)
}

func (s *Store) GetUserByUsername(username string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT id, username, email, password_hash, totp_secret, mfa_methods_json,
		role, disabled, tenant_id, external_subject, auth_source, created_at, updated_at, last_login_at FROM users WHERE username = ?`, username)
	return s.scanUser(row)
}

func (s *Store) scanUser(row *sql.Row) (*models.User, bool) {
	u := &models.User{}
	var disabled int
	var createdAt, updatedAt, lastLoginAt, mfaMethodsJSON string

	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.TOTPSecret,
		&mfaMethodsJSON, &u.Role, &disabled, &u.TenantID, &u.ExternalSubject, &u.AuthSource, &createdAt, &updatedAt, &lastLoginAt)
	if err != nil {
		return nil, false
	}

	u.MFAMethods = fromJSON[[]string](mfaMethodsJSON)
	if u.MFAMethods == nil {
		u.MFAMethods = []string{}
	}
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
	_, err := s.db.Exec(`INSERT OR REPLACE INTO users
		(id, username, email, password_hash, totp_secret, mfa_methods_json, role, disabled,
		 tenant_id, external_subject, auth_source, created_at, updated_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Username, user.Email, user.PasswordHash, user.TOTPSecret,
		toJSON(methods), user.Role, b2i(user.Disabled),
		user.TenantID, user.ExternalSubject, user.AuthSource,
		fmtTime(user.CreatedAt), fmtTime(user.UpdatedAt), fmtTime(user.LastLoginAt))
	if err != nil {
		log.Printf("[STORE] Failed to save user %s: %v", user.ID, err)
	}
}

func (s *Store) ListUsers() []*models.User {
	rows, err := s.db.Query(`SELECT id, username, email, password_hash, totp_secret, mfa_methods_json,
		role, disabled, tenant_id, external_subject, auth_source, created_at, updated_at, last_login_at FROM users`)
	if err != nil {
		log.Printf("[STORE] Failed to list users: %v", err)
		return nil
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		u := &models.User{}
		var disabled int
		var createdAt, updatedAt, lastLoginAt, mfaMethodsJSON string

		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.TOTPSecret,
			&mfaMethodsJSON, &u.Role, &disabled, &u.TenantID, &u.ExternalSubject, &u.AuthSource, &createdAt, &updatedAt, &lastLoginAt); err != nil {
			continue
		}

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

// ─────────────────────────────────────────────
// Login attempt tracking
// ─────────────────────────────────────────────

func (s *Store) RecordFailedLogin(username string, maxAttempts int, lockoutDuration time.Duration) {
	var failedCount int
	row := s.db.QueryRow("SELECT failed_count FROM login_attempts WHERE username = ?", username)
	if err := row.Scan(&failedCount); err != nil {
		failedCount = 0
	}

	failedCount++
	lockedUntil := ""
	if failedCount >= maxAttempts {
		lockedUntil = fmtTime(time.Now().Add(lockoutDuration))
	}

	s.db.Exec(`INSERT OR REPLACE INTO login_attempts (username, failed_count, last_attempt, locked_until)
		VALUES (?, ?, ?, ?)`, username, failedCount, fmtTime(time.Now()), lockedUntil)
}

func (s *Store) ResetLoginAttempts(username string) {
	s.db.Exec("DELETE FROM login_attempts WHERE username = ?", username)
}

func (s *Store) IsLockedOut(username string) (bool, time.Time) {
	var lockedUntil string
	row := s.db.QueryRow("SELECT locked_until FROM login_attempts WHERE username = ?", username)
	if err := row.Scan(&lockedUntil); err != nil || lockedUntil == "" {
		return false, time.Time{}
	}

	t := parseTime(lockedUntil)
	if t.After(time.Now()) {
		return true, t
	}
	return false, time.Time{}
}

func (s *Store) GetFailedAttempts(username string) int {
	var count int
	row := s.db.QueryRow("SELECT failed_count FROM login_attempts WHERE username = ?", username)
	if err := row.Scan(&count); err != nil {
		return 0
	}
	return count
}
