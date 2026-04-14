package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cloud/models"

	_ "modernc.org/sqlite"
)

// Store provides thread-safe data storage backed by SQLite.
// Replaces the previous in-memory maps + JSON file persistence.
type Store struct {
	db      *sql.DB
	dataDir string

	// PendingAuth is ephemeral (browser auth sessions, 5-min TTL) — kept in memory
	pendingMu   sync.RWMutex
	PendingAuth map[string]*models.PendingAuthSession

	// PendingEnroll is ephemeral (browser enrollment sessions, 5-min TTL) — kept in memory
	enrollMu      sync.RWMutex
	PendingEnroll map[string]*models.PendingEnrollSession
}

// New creates a new Store with the specified data directory.
func New(dataDir string) *Store {
	s := &Store{
		dataDir:       dataDir,
		PendingAuth:   make(map[string]*models.PendingAuthSession),
		PendingEnroll: make(map[string]*models.PendingEnrollSession),
	}
	if dataDir != "" {
		os.MkdirAll(dataDir, 0755)
	}
	return s
}

// InitDB opens the SQLite database and creates tables.
func (s *Store) InitDB() error {
	dbPath := filepath.Join(s.dataDir, "ztna.db")
	if s.dataDir == "" {
		dbPath = "ztna.db"
	}

	var err error
	s.db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	// SQLite performance tuning
	s.db.Exec("PRAGMA journal_mode=WAL")
	s.db.Exec("PRAGMA synchronous=NORMAL")
	s.db.Exec("PRAGMA cache_size=5000")
	s.db.Exec("PRAGMA busy_timeout=5000")
	s.db.SetMaxOpenConns(1)

	if err := s.createTables(); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	log.Printf("[STORE] SQLite database initialized: %s", dbPath)
	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping() error {
	if s.db == nil {
		return fmt.Errorf("database not initialized")
	}
	return s.db.Ping()
}

func (s *Store) createTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT DEFAULT '',
			mfa_methods_json TEXT DEFAULT '[]',
			role TEXT DEFAULT 'user',
			disabled INTEGER DEFAULT 0,
			external_subject TEXT DEFAULT '',
			auth_source TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			last_login_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS policy_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			priority INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			conditions_json TEXT DEFAULT '{}',
			action TEXT NOT NULL,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT DEFAULT '',
			username TEXT DEFAULT '',
			device_id TEXT DEFAULT '',
			source_ip TEXT DEFAULT '',
			resource TEXT DEFAULT '',
			protocol TEXT DEFAULT '',
			risk_score INTEGER DEFAULT 0,
			created_at TEXT DEFAULT '',
			expires_at TEXT DEFAULT '',
			last_activity TEXT DEFAULT '',
			revoked INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS resources (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			type TEXT DEFAULT '',
			host TEXT DEFAULT '',
			port INTEGER DEFAULT 0,
			external_url TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			tags_json TEXT DEFAULT '[]',
			metadata_json TEXT DEFAULT '{}',
			client_id TEXT DEFAULT '',
			client_secret TEXT DEFAULT '',
			cert_mode TEXT DEFAULT '',
			cert_pem TEXT DEFAULT '',
			key_pem TEXT DEFAULT '',
			cert_expiry TEXT DEFAULT '',
			cert_domain TEXT DEFAULT '',
			allowed_roles_json TEXT DEFAULT '[]',
			require_mfa INTEGER DEFAULT 0,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			timestamp TEXT DEFAULT '',
			event_type TEXT DEFAULT '',
			user_id TEXT DEFAULT '',
			username TEXT DEFAULT '',
			source_ip TEXT DEFAULT '',
			resource TEXT DEFAULT '',
			decision TEXT DEFAULT '',
			details TEXT DEFAULT '',
			success INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS device_health (
			device_id TEXT PRIMARY KEY,
			hostname TEXT DEFAULT '',
			os TEXT DEFAULT '',
			checks_json TEXT DEFAULT '[]',
			overall_score INTEGER DEFAULT 0,
			reported_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS login_attempts (
			username TEXT PRIMARY KEY,
			failed_count INTEGER DEFAULT 0,
			last_attempt TEXT DEFAULT '',
			locked_until TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS revoked_tokens (
			jti TEXT PRIMARY KEY,
			revoked_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS device_enrollments (
			id TEXT PRIMARY KEY,
			device_id TEXT NOT NULL,
			component TEXT DEFAULT '',
			hostname TEXT DEFAULT '',
			public_key_fingerprint TEXT DEFAULT '',
			cert_fingerprint TEXT DEFAULT '',
			cert_serial TEXT DEFAULT '',
			status TEXT DEFAULT 'pending',
			csr_pem TEXT DEFAULT '',
			cert_pem TEXT DEFAULT '',
			enrolled_at TEXT DEFAULT '',
			expires_at TEXT DEFAULT '',
			approved_by TEXT DEFAULT '',
			user_id TEXT DEFAULT '',
			username TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS revoked_certs (
			cert_serial TEXT PRIMARY KEY,
			device_id TEXT NOT NULL,
			revoked_at TEXT NOT NULL,
			expires_on TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS device_users (
			device_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			username TEXT DEFAULT '',
			role TEXT DEFAULT 'user',
			bound_at TEXT NOT NULL,
			PRIMARY KEY (device_id, user_id, role)
		)`,
		`CREATE TABLE IF NOT EXISTS gateways (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			fqdn TEXT DEFAULT '',
			enrollment_token TEXT DEFAULT '',
			token_expires_at TEXT DEFAULT '',
			status TEXT DEFAULT 'pending',
			cert_pem TEXT DEFAULT '',
			cert_fingerprint TEXT DEFAULT '',
			cert_serial TEXT DEFAULT '',
			cert_expires_at TEXT DEFAULT '',
			oidc_client_id TEXT DEFAULT '',
			oidc_client_secret TEXT DEFAULT '',
			listen_addr TEXT DEFAULT '',
			public_ip TEXT DEFAULT '',
			assigned_resources_json TEXT DEFAULT '[]',
			auth_mode TEXT DEFAULT 'builtin',
			federation_config_json TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			last_seen_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS login_locations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			latitude REAL NOT NULL,
			longitude REAL NOT NULL,
			city TEXT DEFAULT '',
			country TEXT DEFAULT '',
			timestamp TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id TEXT NOT NULL,
			credential_json TEXT NOT NULL,
			name TEXT DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id)`,
		`CREATE TABLE IF NOT EXISTS push_challenges (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			username TEXT DEFAULT '',
			device_id TEXT NOT NULL,
			source_ip TEXT DEFAULT '',
			status TEXT DEFAULT 'pending',
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			responded_at TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_push_device ON push_challenges(device_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_push_user ON push_challenges(user_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_gateways_token ON gateways(enrollment_token)`,
		`CREATE INDEX IF NOT EXISTS idx_gateways_oidc_client ON gateways(oidc_client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_login_locations_user ON login_locations(user_id, timestamp)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("exec: %w\nSQL: %s", err, stmt)
		}
	}

	// Migrations for existing databases
	migrations := []string{
		`ALTER TABLE resources ADD COLUMN client_id TEXT DEFAULT ''`,
		`ALTER TABLE resources ADD COLUMN client_secret TEXT DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN mfa_methods_json TEXT DEFAULT '[]'`,
	}
	for _, m := range migrations {
		s.db.Exec(m) // ignore "duplicate column" errors
	}

	// Create indexes that depend on migrated columns
	postMigrationIndexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_resources_client_id ON resources(client_id)`,
	}
	for _, stmt := range postMigrationIndexes {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("exec: %w\nSQL: %s", err, stmt)
		}
	}

	return nil
}

// ─────────────────────────────────────────────
// Time / JSON helpers
// ─────────────────────────────────────────────

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339, s)
	}
	return t
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func i2b(i int) bool { return i != 0 }

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fromJSON[T any](s string) T {
	var v T
	json.Unmarshal([]byte(s), &v)
	return v
}

func fromJSONPtr[T any](s string) *T {
	if s == "" {
		return nil
	}
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return &v
}

// ─────────────────────────────────────────────
// User operations
// ─────────────────────────────────────────────

func (s *Store) GetUser(id string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT id, username, email, password_hash, totp_secret, mfa_methods_json,
		role, disabled, external_subject, auth_source, created_at, updated_at, last_login_at FROM users WHERE id = ?`, id)
	return s.scanUser(row)
}

func (s *Store) GetUserByUsername(username string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT id, username, email, password_hash, totp_secret, mfa_methods_json,
		role, disabled, external_subject, auth_source, created_at, updated_at, last_login_at FROM users WHERE username = ?`, username)
	return s.scanUser(row)
}

func (s *Store) scanUser(row *sql.Row) (*models.User, bool) {
	u := &models.User{}
	var disabled int
	var createdAt, updatedAt, lastLoginAt, mfaMethodsJSON string

	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.TOTPSecret,
		&mfaMethodsJSON, &u.Role, &disabled, &u.ExternalSubject, &u.AuthSource, &createdAt, &updatedAt, &lastLoginAt)
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
		 external_subject, auth_source, created_at, updated_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Username, user.Email, user.PasswordHash, user.TOTPSecret,
		toJSON(methods), user.Role, b2i(user.Disabled),
		user.ExternalSubject, user.AuthSource,
		fmtTime(user.CreatedAt), fmtTime(user.UpdatedAt), fmtTime(user.LastLoginAt))
	if err != nil {
		log.Printf("[STORE] Failed to save user %s: %v", user.ID, err)
	}
}

func (s *Store) ListUsers() []*models.User {
	rows, err := s.db.Query(`SELECT id, username, email, password_hash, totp_secret, mfa_methods_json,
		role, disabled, external_subject, auth_source, created_at, updated_at, last_login_at FROM users`)
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
			&mfaMethodsJSON, &u.Role, &disabled, &u.ExternalSubject, &u.AuthSource, &createdAt, &updatedAt, &lastLoginAt); err != nil {
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

// ─────────────────────────────────────────────
// Policy Rule operations
// ─────────────────────────────────────────────

func (s *Store) GetPolicyRule(id string) (*models.PolicyRule, bool) {
	row := s.db.QueryRow(`SELECT id, name, description, priority, enabled, conditions_json,
		action, created_at, updated_at FROM policy_rules WHERE id = ?`, id)

	r := &models.PolicyRule{}
	var enabled int
	var condJSON, createdAt, updatedAt string

	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Priority, &enabled, &condJSON,
		&r.Action, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}

	r.Enabled = i2b(enabled)
	r.Conditions = fromJSON[models.RuleConditions](condJSON)
	r.CreatedAt = parseTime(createdAt)
	r.UpdatedAt = parseTime(updatedAt)
	return r, true
}

func (s *Store) SavePolicyRule(rule *models.PolicyRule) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO policy_rules
		(id, name, description, priority, enabled, conditions_json, action, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.Name, rule.Description, rule.Priority, b2i(rule.Enabled),
		toJSON(rule.Conditions), rule.Action, fmtTime(rule.CreatedAt), fmtTime(rule.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save policy rule %s: %v", rule.ID, err)
	}
}

func (s *Store) ListPolicyRules() []*models.PolicyRule {
	rows, err := s.db.Query(`SELECT id, name, description, priority, enabled, conditions_json,
		action, created_at, updated_at FROM policy_rules ORDER BY priority ASC`)
	if err != nil {
		log.Printf("[STORE] Failed to list policy rules: %v", err)
		return nil
	}
	defer rows.Close()

	var rules []*models.PolicyRule
	for rows.Next() {
		r := &models.PolicyRule{}
		var enabled int
		var condJSON, createdAt, updatedAt string

		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Priority, &enabled, &condJSON,
			&r.Action, &createdAt, &updatedAt); err != nil {
			continue
		}

		r.Enabled = i2b(enabled)
		r.Conditions = fromJSON[models.RuleConditions](condJSON)
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		rules = append(rules, r)
	}
	return rules
}

func (s *Store) DeletePolicyRule(id string) {
	s.db.Exec("DELETE FROM policy_rules WHERE id = ?", id)
}

// ─────────────────────────────────────────────
// Session operations
// ─────────────────────────────────────────────

func (s *Store) GetSession(id string) (*models.Session, bool) {
	row := s.db.QueryRow(`SELECT id, user_id, username, device_id, source_ip, resource,
		protocol, risk_score, created_at, expires_at, last_activity, revoked
		FROM sessions WHERE id = ?`, id)

	sess := &models.Session{}
	var revoked int
	var createdAt, expiresAt, lastActivity string

	err := row.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
		&sess.Resource, &sess.Protocol, &sess.RiskScore, &createdAt, &expiresAt, &lastActivity, &revoked)
	if err != nil {
		return nil, false
	}

	sess.Revoked = i2b(revoked)
	sess.CreatedAt = parseTime(createdAt)
	sess.ExpiresAt = parseTime(expiresAt)
	sess.LastActivity = parseTime(lastActivity)
	return sess, true
}

func (s *Store) SaveSession(session *models.Session) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO sessions
		(id, user_id, username, device_id, source_ip, resource, protocol, risk_score,
		 created_at, expires_at, last_activity, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.Username, session.DeviceID, session.SourceIP,
		session.Resource, session.Protocol, session.RiskScore,
		fmtTime(session.CreatedAt), fmtTime(session.ExpiresAt),
		fmtTime(session.LastActivity), b2i(session.Revoked))
	if err != nil {
		log.Printf("[STORE] Failed to save session %s: %v", session.ID, err)
	}
}

func (s *Store) ListSessions() []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		protocol, risk_score, created_at, expires_at, last_activity, revoked
		FROM sessions WHERE revoked = 0 AND expires_at > ?`, fmtTime(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanSessions(rows)
}

func (s *Store) ListUserSessions(userID string) []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		protocol, risk_score, created_at, expires_at, last_activity, revoked
		FROM sessions WHERE user_id = ? AND revoked = 0 AND expires_at > ?`, userID, fmtTime(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanSessions(rows)
}

func (s *Store) scanSessions(rows *sql.Rows) []*models.Session {
	var sessions []*models.Session
	for rows.Next() {
		sess := &models.Session{}
		var revoked int
		var createdAt, expiresAt, lastActivity string

		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
			&sess.Resource, &sess.Protocol, &sess.RiskScore, &createdAt, &expiresAt, &lastActivity, &revoked); err != nil {
			continue
		}

		sess.Revoked = i2b(revoked)
		sess.CreatedAt = parseTime(createdAt)
		sess.ExpiresAt = parseTime(expiresAt)
		sess.LastActivity = parseTime(lastActivity)
		sessions = append(sessions, sess)
	}
	return sessions
}

func (s *Store) RevokeSession(id string) bool {
	result, err := s.db.Exec("UPDATE sessions SET revoked = 1 WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

func (s *Store) CleanExpiredSessions() int {
	result, err := s.db.Exec("DELETE FROM sessions WHERE expires_at < ? OR revoked = 1", fmtTime(time.Now()))
	if err != nil {
		return 0
	}
	n, _ := result.RowsAffected()
	return int(n)
}

// ─────────────────────────────────────────────
// Audit Log operations
// ─────────────────────────────────────────────

func (s *Store) AddAuditEntry(entry *models.AuditEntry) {
	_, err := s.db.Exec(`INSERT INTO audit_log
		(id, timestamp, event_type, user_id, username, source_ip, resource, decision, details, success)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, fmtTime(entry.Timestamp), entry.EventType, entry.UserID, entry.Username,
		entry.SourceIP, entry.Resource, entry.Decision, entry.Details, b2i(entry.Success))
	if err != nil {
		log.Printf("[STORE] Failed to add audit entry: %v", err)
	}

	// Cap audit log at 10000 entries
	s.db.Exec(`DELETE FROM audit_log WHERE id NOT IN (
		SELECT id FROM audit_log ORDER BY timestamp DESC LIMIT 10000)`)
}

func (s *Store) GetAuditLog(limit int) []*models.AuditEntry {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(`SELECT id, timestamp, event_type, user_id, username, source_ip,
		resource, decision, details, success FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []*models.AuditEntry
	for rows.Next() {
		e := &models.AuditEntry{}
		var ts string
		var success int

		if err := rows.Scan(&e.ID, &ts, &e.EventType, &e.UserID, &e.Username, &e.SourceIP,
			&e.Resource, &e.Decision, &e.Details, &success); err != nil {
			continue
		}

		e.Timestamp = parseTime(ts)
		e.Success = i2b(success)
		entries = append(entries, e)
	}
	return entries
}

// ─────────────────────────────────────────────
// Device Health operations
// ─────────────────────────────────────────────

func (s *Store) SaveDeviceHealth(report *models.DeviceHealthReport) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO device_health
		(device_id, hostname, os, checks_json, overall_score, reported_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		report.DeviceID, report.Hostname, report.OS, toJSON(report.Checks),
		report.OverallScore, fmtTime(report.ReportedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save device health for %s: %v", report.DeviceID, err)
	}
}

func (s *Store) GetDeviceHealth(deviceID string) (*models.DeviceHealthReport, bool) {
	row := s.db.QueryRow(`SELECT device_id, hostname, os, checks_json, overall_score, reported_at
		FROM device_health WHERE device_id = ?`, deviceID)

	r := &models.DeviceHealthReport{}
	var checksJSON, reportedAt string

	err := row.Scan(&r.DeviceID, &r.Hostname, &r.OS, &checksJSON, &r.OverallScore, &reportedAt)
	if err != nil {
		return nil, false
	}

	r.Checks = fromJSON[[]models.HealthCheck](checksJSON)
	r.ReportedAt = parseTime(reportedAt)
	return r, true
}

func (s *Store) ListDeviceHealth() []*models.DeviceHealthReport {
	rows, err := s.db.Query("SELECT device_id, hostname, os, checks_json, overall_score, reported_at FROM device_health")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reports []*models.DeviceHealthReport
	for rows.Next() {
		r := &models.DeviceHealthReport{}
		var checksJSON, reportedAt string

		if err := rows.Scan(&r.DeviceID, &r.Hostname, &r.OS, &checksJSON, &r.OverallScore, &reportedAt); err != nil {
			continue
		}

		r.Checks = fromJSON[[]models.HealthCheck](checksJSON)
		r.ReportedAt = parseTime(reportedAt)
		reports = append(reports, r)
	}
	return reports
}

// ─────────────────────────────────────────────
// Resource operations
// ─────────────────────────────────────────────

func (s *Store) GetResource(id string) (*models.Resource, bool) {
	row := s.db.QueryRow(`SELECT id, name, description, type, host, port, external_url, enabled,
		tags_json, metadata_json, client_id, client_secret,
		cert_mode, cert_pem, key_pem, cert_expiry, cert_domain,
		allowed_roles_json, require_mfa, created_at, updated_at
		FROM resources WHERE id = ?`, id)
	return s.scanResource(row)
}

func (s *Store) scanResource(row *sql.Row) (*models.Resource, bool) {
	r := &models.Resource{}
	var enabled, requireMFA int
	var tagsJSON, metaJSON, rolesJSON, createdAt, updatedAt string

	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Type, &r.Host, &r.Port, &r.ExternalURL,
		&enabled, &tagsJSON, &metaJSON, &r.ClientID, &r.ClientSecret,
		&r.CertMode, &r.CertPEM, &r.KeyPEM, &r.CertExpiry,
		&r.CertDomain, &rolesJSON, &requireMFA, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}

	r.Enabled = i2b(enabled)
	r.RequireMFA = i2b(requireMFA)
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
		 tags_json, metadata_json, client_id, client_secret,
		 cert_mode, cert_pem, key_pem, cert_expiry, cert_domain,
		 allowed_roles_json, require_mfa, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		res.ID, res.Name, res.Description, res.Type, res.Host, res.Port, res.ExternalURL,
		b2i(res.Enabled), toJSON(tags), toJSON(meta), res.ClientID, res.ClientSecret,
		res.CertMode, res.CertPEM, res.KeyPEM,
		res.CertExpiry, res.CertDomain, toJSON(roles), b2i(res.RequireMFA),
		fmtTime(res.CreatedAt), fmtTime(res.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save resource %s: %v", res.ID, err)
	}
}

func (s *Store) ListResources() []*models.Resource {
	rows, err := s.db.Query(`SELECT id, name, description, type, host, port, external_url, enabled,
		tags_json, metadata_json, client_id, client_secret,
		cert_mode, cert_pem, key_pem, cert_expiry, cert_domain,
		allowed_roles_json, require_mfa, created_at, updated_at FROM resources`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var resources []*models.Resource
	for rows.Next() {
		r := &models.Resource{}
		var enabled, requireMFA int
		var tagsJSON, metaJSON, rolesJSON, createdAt, updatedAt string

		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Type, &r.Host, &r.Port, &r.ExternalURL,
			&enabled, &tagsJSON, &metaJSON, &r.ClientID, &r.ClientSecret,
			&r.CertMode, &r.CertPEM, &r.KeyPEM, &r.CertExpiry,
			&r.CertDomain, &rolesJSON, &requireMFA, &createdAt, &updatedAt); err != nil {
			continue
		}

		r.Enabled = i2b(enabled)
		r.RequireMFA = i2b(requireMFA)
		r.Tags = fromJSON[[]string](tagsJSON)
		r.Metadata = fromJSON[map[string]string](metaJSON)
		r.AllowedRoles = fromJSON[[]string](rolesJSON)
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		resources = append(resources, r)
	}
	return resources
}

// GetResourceByClientID finds a resource by its per-app ClientID.
func (s *Store) GetResourceByClientID(clientID string) (*models.Resource, bool) {
	row := s.db.QueryRow(`SELECT id, name, description, type, host, port, external_url, enabled,
		tags_json, metadata_json, client_id, client_secret,
		cert_mode, cert_pem, key_pem, cert_expiry, cert_domain,
		allowed_roles_json, require_mfa, created_at, updated_at
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

// ─────────────────────────────────────────────
// Pending Auth Session operations (in-memory, ephemeral)
// ─────────────────────────────────────────────

func (s *Store) SavePendingAuth(session *models.PendingAuthSession) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.PendingAuth[session.ID] = session
}

func (s *Store) GetPendingAuth(id string) (*models.PendingAuthSession, bool) {
	s.pendingMu.RLock()
	defer s.pendingMu.RUnlock()
	sess, ok := s.PendingAuth[id]
	return sess, ok
}

func (s *Store) DeletePendingAuth(id string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	delete(s.PendingAuth, id)
}

func (s *Store) CleanExpiredPendingAuth() int {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	count := 0
	now := time.Now()
	for id, sess := range s.PendingAuth {
		if sess.ExpiresAt.Before(now) {
			delete(s.PendingAuth, id)
			count++
		}
	}
	return count
}

// ─────────────────────────────────────────────
// Pending Enroll Session operations (in-memory, ephemeral)
// ─────────────────────────────────────────────

func (s *Store) SavePendingEnroll(session *models.PendingEnrollSession) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.PendingEnroll[session.ID] = session
}

func (s *Store) GetPendingEnroll(id string) (*models.PendingEnrollSession, bool) {
	s.enrollMu.RLock()
	defer s.enrollMu.RUnlock()
	sess, ok := s.PendingEnroll[id]
	return sess, ok
}

func (s *Store) DeletePendingEnroll(id string) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	delete(s.PendingEnroll, id)
}

func (s *Store) CleanExpiredPendingEnroll() int {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	count := 0
	now := time.Now()
	for id, sess := range s.PendingEnroll {
		if sess.ExpiresAt.Before(now) {
			delete(s.PendingEnroll, id)
			count++
		}
	}
	return count
}

// ─────────────────────────────────────────────
// Compatibility methods (replace old JSON persistence)
// ─────────────────────────────────────────────

// SaveToDisk is a no-op for SQLite (data is always persisted).
func (s *Store) SaveToDisk() error {
	return nil
}

// LoadFromDisk migrates data from legacy store.json if the database is empty.
// Legacy migration — safe to remove after thesis defense.
func (s *Store) LoadFromDisk() error {
	// Check if DB already has data
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		log.Printf("[STORE] Database already has data (%d users), skipping JSON import", count)
		return nil
	}

	// Try to import from legacy store.json
	jsonPath := filepath.Join(s.dataDir, "store.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[STORE] No legacy store.json found, starting with empty database")
			return nil
		}
		return err
	}

	log.Println("[STORE] Importing legacy store.json data into SQLite...")
	return s.importJSON(data)
}

// importJSON reads legacy JSON data and inserts it into SQLite tables.
func (s *Store) importJSON(data []byte) error {
	var legacy struct {
		Users        map[string]*models.User               `json:"users"`
		PolicyRules  map[string]*models.PolicyRule         `json:"policy_rules"`
		Sessions     map[string]*models.Session            `json:"sessions"`
		Resources    map[string]*models.Resource           `json:"resources"`
		AuditLog     []*models.AuditEntry                  `json:"audit_log"`
		DeviceHealth map[string]*models.DeviceHealthReport `json:"device_health"`
	}

	if err := json.Unmarshal(data, &legacy); err != nil {
		return fmt.Errorf("unmarshal legacy data: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, u := range legacy.Users {
		mfaMethods := []string{}
		if u.MFAEnabled() {
			mfaMethods = u.MFAMethods
		}
		if len(mfaMethods) == 0 && u.TOTPSecret != "" {
			mfaMethods = []string{"totp"}
		}
		tx.Exec(`INSERT OR IGNORE INTO users (id, username, email, password_hash, totp_secret, mfa_methods_json,
			role, disabled, created_at, updated_at, last_login_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			u.ID, u.Username, u.Email, u.PasswordHash, u.TOTPSecret, toJSON(mfaMethods), u.Role,
			b2i(u.Disabled), fmtTime(u.CreatedAt), fmtTime(u.UpdatedAt), fmtTime(u.LastLoginAt))
	}

	for _, r := range legacy.PolicyRules {
		tx.Exec(`INSERT OR IGNORE INTO policy_rules (id, name, description, priority, enabled,
			conditions_json, action, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Name, r.Description, r.Priority, b2i(r.Enabled), toJSON(r.Conditions),
			r.Action, fmtTime(r.CreatedAt), fmtTime(r.UpdatedAt))
	}

	for _, sess := range legacy.Sessions {
		tx.Exec(`INSERT OR IGNORE INTO sessions (id, user_id, username, device_id, source_ip,
			resource, protocol, risk_score, created_at, expires_at, last_activity, revoked)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			sess.ID, sess.UserID, sess.Username, sess.DeviceID, sess.SourceIP, sess.Resource,
			sess.Protocol, sess.RiskScore, fmtTime(sess.CreatedAt), fmtTime(sess.ExpiresAt),
			fmtTime(sess.LastActivity), b2i(sess.Revoked))
	}

	for _, res := range legacy.Resources {
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
		tx.Exec(`INSERT OR IGNORE INTO resources (id, name, description, type, host, port,
			external_url, enabled, tags_json, metadata_json, cert_mode, cert_pem, key_pem,
			cert_expiry, cert_domain, allowed_roles_json, require_mfa, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			res.ID, res.Name, res.Description, res.Type, res.Host, res.Port, res.ExternalURL,
			b2i(res.Enabled), toJSON(tags), toJSON(meta), res.CertMode, res.CertPEM, res.KeyPEM,
			res.CertExpiry, res.CertDomain, toJSON(roles), b2i(res.RequireMFA),
			fmtTime(res.CreatedAt), fmtTime(res.UpdatedAt))
	}

	for _, e := range legacy.AuditLog {
		tx.Exec(`INSERT OR IGNORE INTO audit_log (id, timestamp, event_type, user_id, username,
			source_ip, resource, decision, details, success) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			e.ID, fmtTime(e.Timestamp), e.EventType, e.UserID, e.Username, e.SourceIP,
			e.Resource, e.Decision, e.Details, b2i(e.Success))
	}

	for _, d := range legacy.DeviceHealth {
		tx.Exec(`INSERT OR IGNORE INTO device_health (device_id, hostname, os, checks_json,
			overall_score, reported_at) VALUES (?,?,?,?,?,?)`,
			d.DeviceID, d.Hostname, d.OS, toJSON(d.Checks), d.OverallScore, fmtTime(d.ReportedAt))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit import: %w", err)
	}

	imported := len(legacy.Users) + len(legacy.PolicyRules) + len(legacy.Resources)
	log.Printf("[STORE] Imported legacy data: %d users, %d rules, %d resources, %d audit entries",
		len(legacy.Users), len(legacy.PolicyRules), len(legacy.Resources), len(legacy.AuditLog))

	_ = imported
	return nil
}

// StartAutoSave is a no-op for SQLite (data is always persisted).
// Kept for API compatibility.
func (s *Store) StartAutoSave(interval time.Duration, stopChan <-chan struct{}) {
	// SQLite auto-persists — no periodic save needed.
	// Run periodic cleanup of pending auth sessions instead.
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				s.CleanExpiredPendingAuth()
				s.CleanExpiredPendingEnroll()
				s.CleanExpiredRevokedTokens()
			}
		}
	}()
}

// ─────────────────────────────────────────────
// Token Revocation
// ─────────────────────────────────────────────

// RevokeToken adds a JTI to the revocation blacklist
func (s *Store) RevokeToken(jti string, expiresAt time.Time) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)`,
		jti, fmtTime(time.Now()), fmtTime(expiresAt))
	if err != nil {
		log.Printf("[STORE] Failed to revoke token %s: %v", jti, err)
	}
}

// IsTokenRevoked checks if a JTI has been revoked
func (s *Store) IsTokenRevoked(jti string) bool {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE jti = ?", jti).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

// CleanExpiredRevokedTokens removes revoked tokens that have passed their original expiry
func (s *Store) CleanExpiredRevokedTokens() {
	result, err := s.db.Exec("DELETE FROM revoked_tokens WHERE expires_at < ?", fmtTime(time.Now()))
	if err != nil {
		log.Printf("[STORE] Failed to clean expired revoked tokens: %v", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("[STORE] Cleaned %d expired revoked tokens", n)
	}
}

// ─────────────────────────────────────────────
// Device Enrollment
// ─────────────────────────────────────────────

// SaveDeviceEnrollment creates or updates a device enrollment record
func (s *Store) SaveDeviceEnrollment(e *models.DeviceEnrollment) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO device_enrollments
		(id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial, status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.DeviceID, e.Component, e.Hostname, e.PublicKeyFingerprint, e.CertFingerprint, e.CertSerial,
		e.Status, e.CSRPEM, e.CertPEM, fmtTime(e.EnrolledAt), fmtTime(e.ExpiresAt), e.ApprovedBy, e.UserID, e.Username)
	if err != nil {
		log.Printf("[STORE] Failed to save device enrollment %s: %v", e.ID, err)
	}
}

// GetDeviceEnrollment retrieves an enrollment by ID
func (s *Store) GetDeviceEnrollment(id string) (*models.DeviceEnrollment, bool) {
	row := s.db.QueryRow(`SELECT id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial,
		status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username
		FROM device_enrollments WHERE id = ?`, id)
	return s.scanEnrollment(row)
}

// GetDeviceEnrollmentByDeviceID retrieves an enrollment by device_id
func (s *Store) GetDeviceEnrollmentByDeviceID(deviceID string) (*models.DeviceEnrollment, bool) {
	row := s.db.QueryRow(`SELECT id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial,
		status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username
		FROM device_enrollments WHERE device_id = ? ORDER BY enrolled_at DESC LIMIT 1`, deviceID)
	return s.scanEnrollment(row)
}

// GetDeviceEnrollmentByComponent retrieves an enrollment by device_id and component
func (s *Store) GetDeviceEnrollmentByComponent(deviceID, component string) (*models.DeviceEnrollment, bool) {
	row := s.db.QueryRow(`SELECT id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial,
		status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username
		FROM device_enrollments WHERE device_id = ? AND component = ? ORDER BY enrolled_at DESC LIMIT 1`, deviceID, component)
	return s.scanEnrollment(row)
}

// ListDeviceEnrollments returns all enrollments
func (s *Store) ListDeviceEnrollments() []*models.DeviceEnrollment {
	rows, err := s.db.Query(`SELECT id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial,
		status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username
		FROM device_enrollments ORDER BY enrolled_at DESC`)
	if err != nil {
		log.Printf("[STORE] Failed to list enrollments: %v", err)
		return nil
	}
	defer rows.Close()

	var enrollments []*models.DeviceEnrollment
	for rows.Next() {
		e := &models.DeviceEnrollment{}
		var enrolledAt, expiresAt string
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.Component, &e.Hostname, &e.PublicKeyFingerprint, &e.CertFingerprint, &e.CertSerial,
			&e.Status, &e.CSRPEM, &e.CertPEM, &enrolledAt, &expiresAt, &e.ApprovedBy, &e.UserID, &e.Username); err != nil {
			continue
		}
		e.EnrolledAt = parseTime(enrolledAt)
		e.ExpiresAt = parseTime(expiresAt)
		enrollments = append(enrollments, e)
	}
	return enrollments
}

func (s *Store) scanEnrollment(row *sql.Row) (*models.DeviceEnrollment, bool) {
	e := &models.DeviceEnrollment{}
	var enrolledAt, expiresAt string
	err := row.Scan(&e.ID, &e.DeviceID, &e.Component, &e.Hostname, &e.PublicKeyFingerprint, &e.CertFingerprint, &e.CertSerial,
		&e.Status, &e.CSRPEM, &e.CertPEM, &enrolledAt, &expiresAt, &e.ApprovedBy, &e.UserID, &e.Username)
	if err != nil {
		return nil, false
	}
	e.EnrolledAt = parseTime(enrolledAt)
	e.ExpiresAt = parseTime(expiresAt)
	return e, true
}

// ─────────────────────────────────────────────
// Revoked certificate serial tracking
// ─────────────────────────────────────────────

// RevokeCertSerial records a revoked certificate serial for gateway cache sync
func (s *Store) RevokeCertSerial(serial, deviceID string, expiresOn time.Time) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO revoked_certs (cert_serial, device_id, revoked_at, expires_on)
		VALUES (?, ?, ?, ?)`, serial, deviceID, fmtTime(time.Now()), fmtTime(expiresOn))
	if err != nil {
		log.Printf("[STORE] Failed to revoke cert serial %s: %v", serial, err)
	}
}

// GetRevokedSerials returns all revoked cert serials that haven't expired yet
func (s *Store) GetRevokedSerials() []string {
	rows, err := s.db.Query(`SELECT cert_serial FROM revoked_certs WHERE expires_on > ?`, fmtTime(time.Now()))
	if err != nil {
		log.Printf("[STORE] Failed to get revoked serials: %v", err)
		return nil
	}
	defer rows.Close()

	var serials []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err == nil {
			serials = append(serials, s)
		}
	}
	return serials
}

// ─────────────────────────────────────────────
// Device-User Binding
// ─────────────────────────────────────────────

// SaveDeviceUser creates or updates a device-user binding
func (s *Store) SaveDeviceUser(du *models.DeviceUser) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO device_users (device_id, user_id, username, role, bound_at)
		VALUES (?, ?, ?, ?, ?)`,
		du.DeviceID, du.UserID, du.Username, du.Role, fmtTime(du.BoundAt))
	if err != nil {
		log.Printf("[STORE] Failed to save device-user binding %s/%s: %v", du.DeviceID, du.UserID, err)
	}
}

// ─────────────────────────────────────────────
// Gateway operations
// ─────────────────────────────────────────────

func (s *Store) SaveGateway(gw *models.Gateway) {
	resources := gw.AssignedResources
	if resources == nil {
		resources = []string{}
	}
	authMode := gw.AuthMode
	if authMode == "" {
		authMode = "builtin"
	}
	fedConfigJSON := ""
	if gw.FederationConfig != nil {
		fedConfigJSON = toJSON(gw.FederationConfig)
	}

	_, err := s.db.Exec(`INSERT OR REPLACE INTO gateways
		(id, name, fqdn, enrollment_token, token_expires_at, status,
		 cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		 oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		 assigned_resources_json, auth_mode, federation_config_json,
		 created_at, updated_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gw.ID, gw.Name, gw.FQDN, gw.EnrollmentToken, gw.TokenExpiresAt, gw.Status,
		gw.CertPEM, gw.CertFingerprint, gw.CertSerial, gw.CertExpiresAt,
		gw.OIDCClientID, gw.OIDCClientSecret, gw.ListenAddr, gw.PublicIP,
		toJSON(resources), authMode, fedConfigJSON,
		fmtTime(gw.CreatedAt), fmtTime(gw.UpdatedAt), fmtTime(gw.LastSeenAt))
	if err != nil {
		log.Printf("[STORE] Failed to save gateway %s: %v", gw.ID, err)
	}
}

func (s *Store) GetGateway(id string) (*models.Gateway, bool) {
	row := s.db.QueryRow(`SELECT id, name, fqdn, enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE id = ?`, id)
	return s.scanGateway(row)
}

func (s *Store) GetGatewayByToken(token string) (*models.Gateway, bool) {
	if token == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, name, fqdn, enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE enrollment_token = ?`, token)
	return s.scanGateway(row)
}

func (s *Store) GetGatewayByFQDN(fqdn string) (*models.Gateway, bool) {
	if fqdn == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, name, fqdn, enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE fqdn = ?`, fqdn)
	return s.scanGateway(row)
}

func (s *Store) ListGateways() []*models.Gateway {
	rows, err := s.db.Query(`SELECT id, name, fqdn, enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("[STORE] Failed to list gateways: %v", err)
		return nil
	}
	defer rows.Close()

	var gateways []*models.Gateway
	for rows.Next() {
		gw := &models.Gateway{}
		var resourcesJSON, fedConfigJSON, createdAt, updatedAt, lastSeenAt string
		if err := rows.Scan(&gw.ID, &gw.Name, &gw.FQDN, &gw.EnrollmentToken, &gw.TokenExpiresAt, &gw.Status,
			&gw.CertPEM, &gw.CertFingerprint, &gw.CertSerial, &gw.CertExpiresAt,
			&gw.OIDCClientID, &gw.OIDCClientSecret, &gw.ListenAddr, &gw.PublicIP,
			&resourcesJSON, &gw.AuthMode, &fedConfigJSON, &createdAt, &updatedAt, &lastSeenAt); err != nil {
			continue
		}
		gw.AssignedResources = fromJSON[[]string](resourcesJSON)
		if fedConfigJSON != "" {
			gw.FederationConfig = fromJSONPtr[models.FederationConfig](fedConfigJSON)
		}
		if gw.AuthMode == "" {
			gw.AuthMode = "builtin"
		}
		gw.CreatedAt = parseTime(createdAt)
		gw.UpdatedAt = parseTime(updatedAt)
		gw.LastSeenAt = parseTime(lastSeenAt)
		gateways = append(gateways, gw)
	}
	return gateways
}

func (s *Store) DeleteGateway(id string) bool {
	result, err := s.db.Exec("DELETE FROM gateways WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

func (s *Store) scanGateway(row *sql.Row) (*models.Gateway, bool) {
	gw := &models.Gateway{}
	var resourcesJSON, fedConfigJSON, createdAt, updatedAt, lastSeenAt string
	err := row.Scan(&gw.ID, &gw.Name, &gw.FQDN, &gw.EnrollmentToken, &gw.TokenExpiresAt, &gw.Status,
		&gw.CertPEM, &gw.CertFingerprint, &gw.CertSerial, &gw.CertExpiresAt,
		&gw.OIDCClientID, &gw.OIDCClientSecret, &gw.ListenAddr, &gw.PublicIP,
		&resourcesJSON, &gw.AuthMode, &fedConfigJSON, &createdAt, &updatedAt, &lastSeenAt)
	if err != nil {
		return nil, false
	}
	gw.AssignedResources = fromJSON[[]string](resourcesJSON)
	if fedConfigJSON != "" {
		gw.FederationConfig = fromJSONPtr[models.FederationConfig](fedConfigJSON)
	}
	if gw.AuthMode == "" {
		gw.AuthMode = "builtin"
	}
	gw.CreatedAt = parseTime(createdAt)
	gw.UpdatedAt = parseTime(updatedAt)
	gw.LastSeenAt = parseTime(lastSeenAt)
	return gw, true
}

// GetGatewayByOIDCClientID looks up a gateway by its OIDC client_id.
func (s *Store) GetGatewayByOIDCClientID(clientID string) (*models.Gateway, bool) {
	if clientID == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, name, fqdn, enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE oidc_client_id = ?`, clientID)
	return s.scanGateway(row)
}

// GetUserByExternalSubject finds a federated user by their external IdP subject+source.
func (s *Store) GetUserByExternalSubject(externalSubject, authSource string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT id, username, email, password_hash, totp_secret, mfa_methods_json,
		role, disabled, external_subject, auth_source, created_at, updated_at, last_login_at
		FROM users WHERE external_subject = ? AND auth_source = ?`, externalSubject, authSource)
	return s.scanUser(row)
}

// ─────────────────────────────────────────────
// Login Locations (geo-velocity tracking)
// ─────────────────────────────────────────────

// SaveLoginLocation stores a geolocation record for a user login event.
// Keeps at most 50 records per user; older entries are pruned automatically.
func (s *Store) SaveLoginLocation(userID, sourceIP string, lat, lon float64, city, country string) error {
	_, err := s.db.Exec(
		`INSERT INTO login_locations (user_id, source_ip, latitude, longitude, city, country, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, sourceIP, lat, lon, city, country, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return err
	}

	// Prune old entries — keep last 50 per user
	s.db.Exec(
		`DELETE FROM login_locations WHERE user_id = ? AND id NOT IN (
			SELECT id FROM login_locations WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50
		)`, userID, userID,
	)
	return nil
}

// GetLastLoginLocation returns the most recent login location for a user.
// Returns nil if no previous location exists.
func (s *Store) GetLastLoginLocation(userID string) (*models.LoginLocation, error) {
	row := s.db.QueryRow(
		`SELECT user_id, source_ip, latitude, longitude, city, country, timestamp
		 FROM login_locations WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1`, userID,
	)

	loc := &models.LoginLocation{}
	var ts string
	err := row.Scan(&loc.UserID, &loc.SourceIP, &loc.Latitude, &loc.Longitude, &loc.City, &loc.Country, &ts)
	if err != nil {
		return nil, err
	}
	loc.Timestamp = parseTime(ts)
	return loc, nil
}

// GetRecentLoginLocations returns the N most recent login locations for a user.
func (s *Store) GetRecentLoginLocations(userID string, limit int) ([]*models.LoginLocation, error) {
	rows, err := s.db.Query(
		`SELECT user_id, source_ip, latitude, longitude, city, country, timestamp
		 FROM login_locations WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?`, userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var locs []*models.LoginLocation
	for rows.Next() {
		loc := &models.LoginLocation{}
		var ts string
		if err := rows.Scan(&loc.UserID, &loc.SourceIP, &loc.Latitude, &loc.Longitude, &loc.City, &loc.Country, &ts); err != nil {
			continue
		}
		loc.Timestamp = parseTime(ts)
		locs = append(locs, loc)
	}
	return locs, nil
}

// ─────────────────────────────────────────────
// WebAuthn Credentials
// ─────────────────────────────────────────────

// SaveWebAuthnCredential persists a new WebAuthn credential for a user.
func (s *Store) SaveWebAuthnCredential(cred *models.WebAuthnCredential) error {
	_, err := s.db.Exec(
		`INSERT INTO webauthn_credentials (id, user_id, credential_id, credential_json, name, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		cred.ID, cred.UserID, cred.CredentialID, cred.CredentialJSON,
		cred.Name, fmtTime(cred.CreatedAt),
	)
	return err
}

// GetWebAuthnCredentials returns all WebAuthn credentials for a user.
func (s *Store) GetWebAuthnCredentials(userID string) ([]*models.WebAuthnCredential, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, credential_id, credential_json, name, created_at
		 FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*models.WebAuthnCredential
	for rows.Next() {
		c := &models.WebAuthnCredential{}
		var createdAt string
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.CredentialJSON, &c.Name, &createdAt); err != nil {
			continue
		}
		c.CreatedAt = parseTime(createdAt)
		creds = append(creds, c)
	}
	return creds, nil
}

// UpdateWebAuthnCredentialJSON updates the JSON blob for a credential (e.g. after sign count bump).
func (s *Store) UpdateWebAuthnCredentialJSON(credID, credJSON string) error {
	_, err := s.db.Exec(
		`UPDATE webauthn_credentials SET credential_json = ? WHERE credential_id = ?`,
		credJSON, credID,
	)
	return err
}

// DeleteWebAuthnCredential removes a WebAuthn credential by row ID.
func (s *Store) DeleteWebAuthnCredential(id string) error {
	_, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE id = ?`, id)
	return err
}

// ─────────────────────────────────────────────
// Push Challenges
// ─────────────────────────────────────────────

// SavePushChallenge persists a push MFA challenge.
func (s *Store) SavePushChallenge(ch *models.PushChallenge) error {
	_, err := s.db.Exec(
		`INSERT INTO push_challenges (id, user_id, username, device_id, source_ip, status, created_at, expires_at, responded_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ch.ID, ch.UserID, ch.Username, ch.DeviceID, ch.SourceIP, ch.Status,
		fmtTime(ch.CreatedAt), fmtTime(ch.ExpiresAt), fmtTime(ch.RespondedAt),
	)
	return err
}

// GetPushChallenge retrieves a push challenge by ID.
func (s *Store) GetPushChallenge(id string) (*models.PushChallenge, error) {
	row := s.db.QueryRow(
		`SELECT id, user_id, username, device_id, source_ip, status, created_at, expires_at, responded_at
		 FROM push_challenges WHERE id = ?`, id,
	)
	ch := &models.PushChallenge{}
	var createdAt, expiresAt, respondedAt string
	err := row.Scan(&ch.ID, &ch.UserID, &ch.Username, &ch.DeviceID, &ch.SourceIP,
		&ch.Status, &createdAt, &expiresAt, &respondedAt)
	if err != nil {
		return nil, err
	}
	ch.CreatedAt = parseTime(createdAt)
	ch.ExpiresAt = parseTime(expiresAt)
	ch.RespondedAt = parseTime(respondedAt)
	return ch, nil
}

// UpdatePushChallengeStatus updates the status and responded_at timestamp.
func (s *Store) UpdatePushChallengeStatus(id, status string) error {
	_, err := s.db.Exec(
		`UPDATE push_challenges SET status = ?, responded_at = ? WHERE id = ?`,
		status, fmtTime(time.Now()), id,
	)
	return err
}

// GetPendingPushChallenges returns all pending, non-expired challenges for a device.
func (s *Store) GetPendingPushChallenges(deviceID string) ([]*models.PushChallenge, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, username, device_id, source_ip, status, created_at, expires_at, responded_at
		 FROM push_challenges WHERE device_id = ? AND status = 'pending' AND expires_at > ?
		 ORDER BY created_at DESC`,
		deviceID, fmtTime(time.Now()),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var challenges []*models.PushChallenge
	for rows.Next() {
		ch := &models.PushChallenge{}
		var createdAt, expiresAt, respondedAt string
		if err := rows.Scan(&ch.ID, &ch.UserID, &ch.Username, &ch.DeviceID, &ch.SourceIP,
			&ch.Status, &createdAt, &expiresAt, &respondedAt); err != nil {
			continue
		}
		ch.CreatedAt = parseTime(createdAt)
		ch.ExpiresAt = parseTime(expiresAt)
		ch.RespondedAt = parseTime(respondedAt)
		challenges = append(challenges, ch)
	}
	return challenges, nil
}

// CleanupExpiredPushChallenges deletes challenges older than 10 minutes.
func (s *Store) CleanupExpiredPushChallenges() {
	cutoff := time.Now().Add(-10 * time.Minute)
	s.db.Exec(`DELETE FROM push_challenges WHERE expires_at < ?`, fmtTime(cutoff))
}

// GetUserDevices returns device IDs bound to a user, most recently bound first.
func (s *Store) GetUserDevices(userID string) []string {
	rows, err := s.db.Query(
		`SELECT device_id FROM device_users WHERE user_id = ? ORDER BY bound_at DESC`, userID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var devices []string
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			devices = append(devices, d)
		}
	}
	return devices
}
