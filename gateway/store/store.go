// Package store implements persistent storage for the gateway using SQLite.
// It mirrors the pattern from cloud/store/store.go using modernc.org/sqlite
// (pure Go, no CGO). A single gateway.db file stores resources, sessions,
// and admin logs with WAL mode for concurrent read/write safety.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gateway/internal/config"
	"gateway/internal/models"

	_ "modernc.org/sqlite"
)

// Store is the persistent SQLite store for the gateway.
type Store struct {
	db      *sql.DB
	dataDir string
}

// New creates a new Store. Call InitDB() to open and initialize the database.
func New(dataDir string) *Store {
	s := &Store{dataDir: dataDir}
	if dataDir != "" {
		os.MkdirAll(dataDir, 0755)
	}
	return s
}

// InitDB opens the SQLite database and creates tables.
func (s *Store) InitDB() error {
	dbPath := filepath.Join(s.dataDir, "gateway.db")
	if s.dataDir == "" {
		dbPath = "gateway.db"
	}

	var err error
	s.db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	// PRAGMA settings — same as cloud/store/store.go
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

func (s *Store) createTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS resources (
			name TEXT PRIMARY KEY,
			type TEXT DEFAULT '',
			protocol TEXT DEFAULT '',
			internal_ip TEXT DEFAULT '',
			tunnel_ip TEXT DEFAULT '',
			port INTEGER DEFAULT 0,
			mfa_required INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			cloud_app_id TEXT DEFAULT '',
			cloud_client_id TEXT DEFAULT '',
			cloud_secret TEXT DEFAULT '',
			description TEXT DEFAULT '',
			external_url TEXT DEFAULT '',
			internal_url TEXT DEFAULT '',
			internal_hosts_json TEXT DEFAULT '[]',
			session_duration INTEGER DEFAULT 480,
			cert_source TEXT DEFAULT '',
			cert_pem TEXT DEFAULT '',
			key_pem TEXT DEFAULT '',
			pass_headers INTEGER DEFAULT 0,
			created_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT DEFAULT '',
			username TEXT DEFAULT '',
			device_id TEXT DEFAULT '',
			source_ip TEXT DEFAULT '',
			auth_token TEXT DEFAULT '',
			cloud_session TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			expires_at TEXT DEFAULT '',
			last_activity TEXT DEFAULT '',
			active INTEGER DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS admin_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT DEFAULT '',
			service TEXT DEFAULT '',
			level TEXT DEFAULT '',
			event TEXT DEFAULT '',
			message TEXT DEFAULT '',
			fields_json TEXT DEFAULT '{}'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(active)`,
		`CREATE INDEX IF NOT EXISTS idx_resources_tunnel_ip ON resources(tunnel_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_resources_cloud_client_id ON resources(cloud_client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_logs_timestamp ON admin_logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_logs_level ON admin_logs(level)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("exec %q: %w", stmt[:40], err)
		}
	}
	return nil
}

// ── Resource CRUD ─────────────────────────────────────────────

// CreateResource inserts a new resource.
func (s *Store) CreateResource(r *config.Resource) error {
	hostsJSON, _ := json.Marshal(r.InternalHosts)
	_, err := s.db.Exec(`INSERT INTO resources
		(name, type, protocol, internal_ip, tunnel_ip, port, mfa_required, enabled,
		 cloud_app_id, cloud_client_id, cloud_secret, description,
		 external_url, internal_url, internal_hosts_json, session_duration,
		 cert_source, cert_pem, key_pem, pass_headers, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Type, r.Protocol, r.InternalIP, r.TunnelIP, r.Port,
		b2i(r.MFARequired), b2i(r.Enabled),
		r.CloudAppID, r.CloudClientID, r.CloudSecret, r.Description,
		r.ExternalURL, r.InternalURL, string(hostsJSON), r.SessionDuration,
		r.CertSource, r.CertPEM, r.KeyPEM, b2i(r.PassHeaders), r.CreatedAt,
	)
	return err
}

// UpdateResource updates an existing resource by name.
func (s *Store) UpdateResource(name string, r *config.Resource) error {
	hostsJSON, _ := json.Marshal(r.InternalHosts)
	result, err := s.db.Exec(`UPDATE resources SET
		type=?, protocol=?, internal_ip=?, tunnel_ip=?, port=?, mfa_required=?, enabled=?,
		cloud_app_id=?, cloud_client_id=?, cloud_secret=?, description=?,
		external_url=?, internal_url=?, internal_hosts_json=?, session_duration=?,
		cert_source=?, cert_pem=?, key_pem=?, pass_headers=?, created_at=?
		WHERE name=?`,
		r.Type, r.Protocol, r.InternalIP, r.TunnelIP, r.Port,
		b2i(r.MFARequired), b2i(r.Enabled),
		r.CloudAppID, r.CloudClientID, r.CloudSecret, r.Description,
		r.ExternalURL, r.InternalURL, string(hostsJSON), r.SessionDuration,
		r.CertSource, r.CertPEM, r.KeyPEM, b2i(r.PassHeaders), r.CreatedAt,
		name,
	)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("resource %q not found", name)
	}
	return nil
}

// DeleteResource removes a resource by name.
func (s *Store) DeleteResource(name string) error {
	result, err := s.db.Exec("DELETE FROM resources WHERE name=?", name)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("resource %q not found", name)
	}
	return nil
}

// ToggleResource sets the enabled flag for a resource.
func (s *Store) ToggleResource(name string, enabled bool) error {
	result, err := s.db.Exec("UPDATE resources SET enabled=? WHERE name=?", b2i(enabled), name)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("resource %q not found", name)
	}
	return nil
}

// SetMFARequired updates the MFA policy for a resource.
func (s *Store) SetMFARequired(name string, mfa bool) error {
	result, err := s.db.Exec("UPDATE resources SET mfa_required=? WHERE name=?", b2i(mfa), name)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("resource %q not found", name)
	}
	return nil
}

// GetResource retrieves a single resource by name.
func (s *Store) GetResource(name string) (*config.Resource, error) {
	row := s.db.QueryRow(`SELECT name, type, protocol, internal_ip, tunnel_ip, port,
		mfa_required, enabled, cloud_app_id, cloud_client_id, cloud_secret, description,
		external_url, internal_url, internal_hosts_json, session_duration,
		cert_source, cert_pem, key_pem, pass_headers, created_at
		FROM resources WHERE name=?`, name)
	return scanResourceFromRow(row)
}

// ListResources returns all resources.
func (s *Store) ListResources() ([]config.Resource, error) {
	rows, err := s.db.Query(`SELECT name, type, protocol, internal_ip, tunnel_ip, port,
		mfa_required, enabled, cloud_app_id, cloud_client_id, cloud_secret, description,
		external_url, internal_url, internal_hosts_json, session_duration,
		cert_source, cert_pem, key_pem, pass_headers, created_at
		FROM resources`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var resources []config.Resource
	for rows.Next() {
		r, err := scanResourceRow(rows)
		if err != nil {
			return nil, err
		}
		resources = append(resources, *r)
	}
	if resources == nil {
		resources = []config.Resource{}
	}
	return resources, rows.Err()
}

// CountResources returns the number of resources.
func (s *Store) CountResources() int {
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM resources").Scan(&n)
	return n
}

// FindResourceByIP looks up a resource by internal IP and port.
func (s *Store) FindResourceByIP(ip string, port int) (*config.Resource, error) {
	row := s.db.QueryRow(`SELECT name, type, protocol, internal_ip, tunnel_ip, port,
		mfa_required, enabled, cloud_app_id, cloud_client_id, cloud_secret, description,
		external_url, internal_url, internal_hosts_json, session_duration,
		cert_source, cert_pem, key_pem, pass_headers, created_at
		FROM resources WHERE internal_ip=? AND port=?`, ip, port)
	return scanResourceFromRow(row)
}

// FindResourceByTunnelIP looks up a resource by CGNAT tunnel IP and port.
func (s *Store) FindResourceByTunnelIP(tunnelIP string, port int) (*config.Resource, error) {
	row := s.db.QueryRow(`SELECT name, type, protocol, internal_ip, tunnel_ip, port,
		mfa_required, enabled, cloud_app_id, cloud_client_id, cloud_secret, description,
		external_url, internal_url, internal_hosts_json, session_duration,
		cert_source, cert_pem, key_pem, pass_headers, created_at
		FROM resources WHERE tunnel_ip=? AND port=?`, tunnelIP, port)
	return scanResourceFromRow(row)
}

// FindResourceByDomain locates a resource from a DNS domain name.
// Replicates the multi-strategy matching from config.FindResourceByDomainSafe.
func (s *Store) FindResourceByDomain(domain string) (*config.Resource, error) {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")

	resources, err := s.ListResources()
	if err != nil {
		return nil, err
	}

	for i := range resources {
		res := &resources[i]
		resName := strings.ToLower(res.Name)

		// Strategy 1: first label matches resource name
		if len(parts) > 0 && parts[0] == resName {
			return res, nil
		}
		// Strategy 2: two-label hyphenated match
		if len(parts) > 1 && (parts[0]+"-"+parts[1]) == resName {
			return res, nil
		}
		// Strategy 3: domain contains resource name
		if strings.Contains(domain, resName) {
			return res, nil
		}
		// Strategy 4: ExternalURL hostname match
		if externalHost := normalizeHost(res.ExternalURL); externalHost != "" {
			if domain == externalHost || strings.HasSuffix(domain, "."+externalHost) {
				return res, nil
			}
		}
		// Strategy 5: TunnelIP match
		if res.TunnelIP != "" && domain == strings.ToLower(res.TunnelIP) {
			return res, nil
		}
	}
	return nil, nil
}

// NextTunnelIP generates the next available CGNAT IP.
func (s *Store) NextTunnelIP() string {
	rows, err := s.db.Query("SELECT tunnel_ip FROM resources WHERE tunnel_ip != ''")
	if err != nil {
		return "100.64.1.1"
	}
	defer rows.Close()

	highest := [4]byte{100, 64, 1, 0}
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		parts := parseIPv4(ip)
		if parts == nil {
			continue
		}
		if ipGreater(parts, highest) {
			highest = *parts
		}
	}

	// Increment
	highest[3]++
	if highest[3] == 0 {
		highest[2]++
		if highest[2] == 0 {
			highest[1]++
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d", highest[0], highest[1], highest[2], highest[3])
}

// HasResourceWithClientID checks for duplicate cloud client ID.
func (s *Store) HasResourceWithClientID(clientID string) bool {
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM resources WHERE cloud_client_id=?", clientID).Scan(&n)
	return n > 0
}

// MigrateResourcesFromConfig imports resources from a config file (one-time migration).
func (s *Store) MigrateResourcesFromConfig(resources []config.Resource) (int, error) {
	if s.CountResources() > 0 {
		return 0, nil // already has resources, skip
	}
	count := 0
	for _, r := range resources {
		if err := s.CreateResource(&r); err != nil {
			log.Printf("[STORE] Migration skip %s: %v", r.Name, err)
			continue
		}
		count++
	}
	if count > 0 {
		log.Printf("[STORE] Migrated %d resources from config file", count)
	}
	return count, nil
}

// ── Session CRUD ──────────────────────────────────────────────

// hashToken returns the SHA-256 hex digest of a token.
// Tokens are hashed before storage so a database compromise does not
// expose raw session credentials (OWASP Session Management).
func hashToken(token string) string {
	if token == "" {
		return ""
	}
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// CreateSession stores a new session.
// The auth_token is SHA-256 hashed before persistence.
func (s *Store) CreateSession(sess *models.Session) error {
	tokenHash := hashToken(sess.AuthToken)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO sessions
		(id, user_id, username, device_id, source_ip, auth_token, cloud_session,
		 created_at, expires_at, last_activity, active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.Username, sess.DeviceID, sess.SourceIP,
		tokenHash, sess.CloudSession,
		fmtTime(sess.CreatedAt), fmtTime(sess.ExpiresAt), fmtTime(sess.LastActivity),
		b2i(sess.Active),
	)
	return err
}

// GetSession retrieves a session by ID (must be active and not expired).
func (s *Store) GetSession(id string) (*models.Session, bool) {
	row := s.db.QueryRow(`SELECT id, user_id, username, device_id, source_ip,
		auth_token, cloud_session, created_at, expires_at, last_activity, active
		FROM sessions WHERE id=? AND active=1 AND expires_at > ?`, id, fmtTime(time.Now()))
	sess, err := scanSession(row)
	if err != nil {
		return nil, false
	}
	return sess, true
}

// ListActiveSessions returns all active, non-expired sessions.
func (s *Store) ListActiveSessions() []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip,
		auth_token, cloud_session, created_at, expires_at, last_activity, active
		FROM sessions WHERE active=1 AND expires_at > ?`, fmtTime(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()

	var sessions []*models.Session
	for rows.Next() {
		sess, err := scanSessionRow(rows)
		if err != nil {
			continue
		}
		sessions = append(sessions, sess)
	}
	return sessions
}

// TouchSession updates the last activity timestamp.
func (s *Store) TouchSession(id string) bool {
	result, _ := s.db.Exec("UPDATE sessions SET last_activity=? WHERE id=? AND active=1",
		fmtTime(time.Now()), id)
	n, _ := result.RowsAffected()
	return n > 0
}

// RevokeSession marks a session as inactive.
func (s *Store) RevokeSession(id string) bool {
	result, _ := s.db.Exec("UPDATE sessions SET active=0 WHERE id=?", id)
	n, _ := result.RowsAffected()
	return n > 0
}

// CountSessions returns the number of active, non-expired sessions.
func (s *Store) CountSessions() int {
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE active=1 AND expires_at > ?",
		fmtTime(time.Now())).Scan(&n)
	return n
}

// CleanExpiredSessions removes expired or revoked sessions.
func (s *Store) CleanExpiredSessions() int {
	result, _ := s.db.Exec("DELETE FROM sessions WHERE active=0 OR expires_at < ?",
		fmtTime(time.Now()))
	n, _ := result.RowsAffected()
	return int(n)
}

// ── Admin Logs ────────────────────────────────────────────────

// InsertLog stores an admin log entry.
func (s *Store) InsertLog(entry models.LogEntry) error {
	fieldsJSON, _ := json.Marshal(entry.Fields)
	_, err := s.db.Exec(`INSERT INTO admin_logs (timestamp, service, level, event, message, fields_json)
		VALUES (?, ?, ?, ?, ?, ?)`,
		fmtTime(entry.Timestamp), entry.Service, entry.Level, entry.Event, entry.Message,
		string(fieldsJSON),
	)
	return err
}

// ListLogs returns admin log entries with optional filtering.
// Results are ordered newest-first. Use limit=0 for no limit.
func (s *Store) ListLogs(level, event string, limit int) ([]models.LogEntry, error) {
	query := "SELECT timestamp, service, level, event, message, fields_json FROM admin_logs WHERE 1=1"
	var args []interface{}

	if level != "" {
		query += " AND level=?"
		args = append(args, level)
	}
	if event != "" {
		query += " AND event=?"
		args = append(args, event)
	}
	query += " ORDER BY id DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.LogEntry
	for rows.Next() {
		var e models.LogEntry
		var ts, fieldsJSON string
		if err := rows.Scan(&ts, &e.Service, &e.Level, &e.Event, &e.Message, &fieldsJSON); err != nil {
			continue
		}
		e.Timestamp = parseTime(ts)
		if fieldsJSON != "" && fieldsJSON != "{}" {
			json.Unmarshal([]byte(fieldsJSON), &e.Fields)
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []models.LogEntry{}
	}
	return entries, rows.Err()
}

// CleanOldLogs keeps the most recent maxEntries logs, deleting older ones.
func (s *Store) CleanOldLogs(maxEntries int) int {
	result, _ := s.db.Exec(`DELETE FROM admin_logs WHERE id NOT IN
		(SELECT id FROM admin_logs ORDER BY id DESC LIMIT ?)`, maxEntries)
	n, _ := result.RowsAffected()
	return int(n)
}

// ── Helpers ───────────────────────────────────────────────────

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scanResourceFromRow(row *sql.Row) (*config.Resource, error) {
	var r config.Resource
	var mfa, enabled, passHeaders int
	var hostsJSON string
	err := row.Scan(
		&r.Name, &r.Type, &r.Protocol, &r.InternalIP, &r.TunnelIP, &r.Port,
		&mfa, &enabled, &r.CloudAppID, &r.CloudClientID, &r.CloudSecret, &r.Description,
		&r.ExternalURL, &r.InternalURL, &hostsJSON, &r.SessionDuration,
		&r.CertSource, &r.CertPEM, &r.KeyPEM, &passHeaders, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.MFARequired = mfa == 1
	r.Enabled = enabled == 1
	r.PassHeaders = passHeaders == 1
	if hostsJSON != "" && hostsJSON != "[]" {
		json.Unmarshal([]byte(hostsJSON), &r.InternalHosts)
	}
	return &r, nil
}

func scanResourceRow(rows *sql.Rows) (*config.Resource, error) {
	var r config.Resource
	var mfa, enabled, passHeaders int
	var hostsJSON string
	err := rows.Scan(
		&r.Name, &r.Type, &r.Protocol, &r.InternalIP, &r.TunnelIP, &r.Port,
		&mfa, &enabled, &r.CloudAppID, &r.CloudClientID, &r.CloudSecret, &r.Description,
		&r.ExternalURL, &r.InternalURL, &hostsJSON, &r.SessionDuration,
		&r.CertSource, &r.CertPEM, &r.KeyPEM, &passHeaders, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.MFARequired = mfa == 1
	r.Enabled = enabled == 1
	r.PassHeaders = passHeaders == 1
	if hostsJSON != "" && hostsJSON != "[]" {
		json.Unmarshal([]byte(hostsJSON), &r.InternalHosts)
	}
	return &r, nil
}

func scanSession(row *sql.Row) (*models.Session, error) {
	var sess models.Session
	var createdAt, expiresAt, lastActivity string
	var active int
	err := row.Scan(
		&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
		&sess.AuthToken, &sess.CloudSession,
		&createdAt, &expiresAt, &lastActivity, &active,
	)
	if err != nil {
		return nil, err
	}
	sess.CreatedAt = parseTime(createdAt)
	sess.ExpiresAt = parseTime(expiresAt)
	sess.LastActivity = parseTime(lastActivity)
	sess.Active = active == 1
	return &sess, nil
}

func scanSessionRow(rows *sql.Rows) (*models.Session, error) {
	var sess models.Session
	var createdAt, expiresAt, lastActivity string
	var active int
	err := rows.Scan(
		&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
		&sess.AuthToken, &sess.CloudSession,
		&createdAt, &expiresAt, &lastActivity, &active,
	)
	if err != nil {
		return nil, err
	}
	sess.CreatedAt = parseTime(createdAt)
	sess.ExpiresAt = parseTime(expiresAt)
	sess.LastActivity = parseTime(lastActivity)
	sess.Active = active == 1
	return &sess, nil
}

func parseIPv4(ip string) *[4]byte {
	var a, b, c, d byte
	n, _ := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	if n != 4 {
		return nil
	}
	return &[4]byte{a, b, c, d}
}

func ipGreater(a *[4]byte, b [4]byte) bool {
	for i := 0; i < 4; i++ {
		if a[i] > b[i] {
			return true
		} else if a[i] < b[i] {
			return false
		}
	}
	return false
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	parsed := value
	if !strings.Contains(parsed, "://") {
		parsed = "https://" + parsed
	}
	u, err := url.Parse(parsed)
	if err == nil && u.Host != "" {
		return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.TrimSuffix(strings.ToLower(host), ".")
	}
	return strings.TrimSuffix(value, ".")
}
