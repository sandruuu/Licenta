package store

import (
	"fmt"

	_ "modernc.org/sqlite"
)

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
			tenant_id TEXT DEFAULT '',
			external_subject TEXT DEFAULT '',
			auth_source TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			last_login_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS tenants (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			domain TEXT DEFAULT '',
			description TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS policy_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			priority INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			tenant_id TEXT DEFAULT '',
			scope TEXT DEFAULT 'global',
			gateway_id TEXT DEFAULT '',
			resource_id TEXT DEFAULT '',
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
			gateway_id TEXT DEFAULT '',
			protocol TEXT DEFAULT '',
			risk_score INTEGER DEFAULT 0,
			tenant_id TEXT DEFAULT '',
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
			tenant_id TEXT DEFAULT '',
			gateway_id TEXT DEFAULT '',
			client_id TEXT DEFAULT '',
			client_secret TEXT DEFAULT '',
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
			success INTEGER DEFAULT 0,
			tenant_id TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS device_health (
			device_id TEXT PRIMARY KEY,
			hostname TEXT DEFAULT '',
			os TEXT DEFAULT '',
			checks_json TEXT DEFAULT '[]',
			overall_score INTEGER DEFAULT 0,
			reported_at TEXT DEFAULT '',
			tenant_id TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS device_posture (
			device_id TEXT PRIMARY KEY,
			hostname TEXT DEFAULT '',
			os TEXT DEFAULT '',
			checks_json TEXT DEFAULT '[]',
			collected_at TEXT DEFAULT '',
			reported_at TEXT DEFAULT '',
			tenant_id TEXT DEFAULT ''
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
			username TEXT DEFAULT '',
			tenant_id TEXT DEFAULT ''
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
			tenant_id TEXT DEFAULT '',
			tenant_ids_json TEXT DEFAULT '[]',
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
		`CREATE TABLE IF NOT EXISTS rate_limits (
			ip TEXT NOT NULL,
			window_start TEXT NOT NULL,
			request_count INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (ip, window_start)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_gateways_token ON gateways(enrollment_token)`,
		`CREATE INDEX IF NOT EXISTS idx_gateways_oidc_client ON gateways(oidc_client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_login_locations_user ON login_locations(user_id, timestamp)`,

		// Identity Provider Configuration (per Tenant)
		`CREATE TABLE IF NOT EXISTS identity_provider_configs (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			name TEXT DEFAULT '',
			type TEXT DEFAULT 'oidc',
			enabled INTEGER DEFAULT 1,
			domains_json TEXT DEFAULT '[]',
			issuer TEXT DEFAULT '',
			client_id TEXT DEFAULT '',
			client_secret TEXT DEFAULT '',
			scopes TEXT DEFAULT '',
			auto_discovery INTEGER DEFAULT 1,
			claim_mapping_json TEXT DEFAULT '{}',
			group_role_mapping_json TEXT DEFAULT '[]',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_idp_tenant ON identity_provider_configs(tenant_id)`,
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
		// S4.2 — tamper-evident audit log hash chain
		`ALTER TABLE audit_log ADD COLUMN prev_hash TEXT DEFAULT ''`,
		`ALTER TABLE audit_log ADD COLUMN entry_hash TEXT DEFAULT ''`,
		// Multi-tenant: add tenant_id to existing tables
		`ALTER TABLE users ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE policy_rules ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE policy_rules ADD COLUMN scope TEXT DEFAULT 'global'`,
		`ALTER TABLE policy_rules ADD COLUMN gateway_id TEXT DEFAULT ''`,
		`ALTER TABLE policy_rules ADD COLUMN resource_id TEXT DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN gateway_id TEXT DEFAULT ''`,
		`ALTER TABLE resources ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE resources ADD COLUMN gateway_id TEXT DEFAULT ''`,
		`ALTER TABLE audit_log ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE device_health ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE device_posture ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE device_enrollments ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE gateways ADD COLUMN tenant_id TEXT DEFAULT ''`,
		// Tenant HRD fields
		`ALTER TABLE tenants ADD COLUMN default_idp_id TEXT DEFAULT ''`,
		`ALTER TABLE tenants ADD COLUMN domains_json TEXT DEFAULT '[]'`,
		// Gateway multi-tenant field
		`ALTER TABLE gateways ADD COLUMN tenant_ids_json TEXT DEFAULT '[]'`,
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
