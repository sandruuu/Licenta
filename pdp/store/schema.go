package store

import (
	"database/sql"
	"fmt"
	"log"

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
		`CREATE TABLE IF NOT EXISTS schema_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
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
		`CREATE TABLE IF NOT EXISTS policy_assignments (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			level TEXT DEFAULT 'organization',
			tenant_id TEXT NOT NULL,
			gateway_id TEXT DEFAULT '',
			resource_id TEXT DEFAULT '',
			group_id TEXT DEFAULT '',
			group_name TEXT DEFAULT '',
			priority INTEGER NOT NULL DEFAULT 100,
			enabled INTEGER DEFAULT 1,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy ON policy_assignments(policy_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_tenant ON policy_assignments(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_resource ON policy_assignments(resource_id)`,
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
		`CREATE TABLE IF NOT EXISTS device_data (
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
			scim_token TEXT DEFAULT '',
			scopes TEXT DEFAULT '',
			auto_discovery INTEGER DEFAULT 1,
			claim_mapping_json TEXT DEFAULT '{}',
			group_role_mapping_json TEXT DEFAULT '[]',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_idp_tenant ON identity_provider_configs(tenant_id)`,
		`CREATE TABLE IF NOT EXISTS directory_users (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			idp_id TEXT NOT NULL,
			external_id TEXT DEFAULT '',
			user_name TEXT NOT NULL,
			display_name TEXT DEFAULT '',
			email TEXT DEFAULT '',
			active INTEGER DEFAULT 1,
			attributes_json TEXT DEFAULT '{}',
			raw_json TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			UNIQUE(tenant_id, idp_id, user_name)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_users_tenant_idp ON directory_users(tenant_id, idp_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_directory_users_external_id ON directory_users(tenant_id, idp_id, external_id) WHERE external_id <> ''`,
		`CREATE TABLE IF NOT EXISTS directory_groups (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			idp_id TEXT NOT NULL,
			external_id TEXT DEFAULT '',
			display_name TEXT NOT NULL,
			raw_json TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			UNIQUE(tenant_id, idp_id, display_name)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_groups_tenant_idp ON directory_groups(tenant_id, idp_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_directory_groups_external_id ON directory_groups(tenant_id, idp_id, external_id) WHERE external_id <> ''`,
		`CREATE TABLE IF NOT EXISTS directory_group_members (
			tenant_id TEXT NOT NULL,
			idp_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			created_at TEXT DEFAULT '',
			PRIMARY KEY (tenant_id, idp_id, group_id, user_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_group_members_group ON directory_group_members(tenant_id, idp_id, group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_group_members_user ON directory_group_members(tenant_id, idp_id, user_id)`,
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
		`ALTER TABLE policy_assignments ADD COLUMN level TEXT DEFAULT 'organization'`,
		`ALTER TABLE policy_assignments ADD COLUMN group_id TEXT DEFAULT ''`,
		`ALTER TABLE policy_assignments ADD COLUMN group_name TEXT DEFAULT ''`,
		`ALTER TABLE policy_assignments ADD COLUMN priority INTEGER NOT NULL DEFAULT 100`,
		`ALTER TABLE sessions ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN gateway_id TEXT DEFAULT ''`,
		`ALTER TABLE resources ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE resources ADD COLUMN gateway_id TEXT DEFAULT ''`,
		`ALTER TABLE audit_log ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE device_health ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE device_data ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE device_enrollments ADD COLUMN tenant_id TEXT DEFAULT ''`,
		`ALTER TABLE gateways ADD COLUMN tenant_id TEXT DEFAULT ''`,
		// Tenant HRD fields
		`ALTER TABLE tenants ADD COLUMN default_idp_id TEXT DEFAULT ''`,
		`ALTER TABLE tenants ADD COLUMN domains_json TEXT DEFAULT '[]'`,
		// Gateway multi-tenant field
		`ALTER TABLE gateways ADD COLUMN tenant_ids_json TEXT DEFAULT '[]'`,
		// SCIM provisioning token for tenant-level IdP configs
		`ALTER TABLE identity_provider_configs ADD COLUMN scim_token TEXT DEFAULT ''`,
	}
	for _, m := range migrations {
		s.db.Exec(m) // ignore "duplicate column" errors
	}

	if err := s.migrateDeviceDataFromOldTable(); err != nil {
		return err
	}
	if err := s.enforceSingleIdentityProviderPerTenant(); err != nil {
		return err
	}
	if err := s.reconcileSingleIdentityProviderDefaults(); err != nil {
		return err
	}

	// Create indexes that depend on migrated columns
	postMigrationIndexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_resources_client_id ON resources(client_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_idp_single_tenant ON identity_provider_configs(tenant_id) WHERE tenant_id <> ''`,
		`CREATE TABLE IF NOT EXISTS policy_assignments (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			level TEXT DEFAULT 'organization',
			tenant_id TEXT NOT NULL,
			gateway_id TEXT DEFAULT '',
			resource_id TEXT DEFAULT '',
			group_id TEXT DEFAULT '',
			group_name TEXT DEFAULT '',
			priority INTEGER NOT NULL DEFAULT 100,
			enabled INTEGER DEFAULT 1,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy ON policy_assignments(policy_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_level ON policy_assignments(level)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_tenant ON policy_assignments(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_resource ON policy_assignments(resource_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_group ON policy_assignments(group_id)`,
	}
	for _, stmt := range postMigrationIndexes {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("exec: %w\nSQL: %s", err, stmt)
		}
	}

	if err := s.cleanupLegacyPolicyDataOnce(); err != nil {
		return err
	}

	return nil
}

func (s *Store) migrateDeviceDataFromOldTable() error {
	exists, err := s.tableExists("device_posture")
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	hasTenantID, err := s.tableHasColumn("device_posture", "tenant_id")
	if err != nil {
		return err
	}
	tenantExpr := "''"
	if hasTenantID {
		tenantExpr = "tenant_id"
	}
	_, err = s.db.Exec(fmt.Sprintf(`INSERT OR IGNORE INTO device_data
		(device_id, hostname, os, checks_json, collected_at, reported_at, tenant_id)
		SELECT device_id, hostname, os, checks_json, collected_at, reported_at, %s
		FROM device_posture`, tenantExpr))
	if err != nil {
		return fmt.Errorf("migrate old device data table: %w", err)
	}
	return nil
}

func (s *Store) tableExists(name string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("query table %s existence: %w", name, err)
	}
	return count > 0, nil
}

func (s *Store) tableHasColumn(tableName, columnName string) (bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(` + tableName + `)`)
	if err != nil {
		return false, fmt.Errorf("query %s columns: %w", tableName, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return false, fmt.Errorf("scan %s columns: %w", tableName, err)
		}
		if name == columnName {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate %s columns: %w", tableName, err)
	}
	return false, nil
}

func (s *Store) cleanupLegacyPolicyDataOnce() error {
	const marker = "legacy_policy_cleanup_v1"

	var value string
	err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key = ?`, marker).Scan(&value)
	if err == nil && value == "done" {
		return nil
	}
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("query legacy policy cleanup marker: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin legacy policy cleanup: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM policy_assignments`); err != nil {
		return fmt.Errorf("delete legacy policy assignments: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM policy_rules`); err != nil {
		return fmt.Errorf("delete legacy policy rules: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO schema_meta(key, value) VALUES (?, 'done')`, marker); err != nil {
		return fmt.Errorf("write legacy policy cleanup marker: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy policy cleanup: %w", err)
	}

	log.Printf("[STORE] Removed legacy policy rules and assignments")
	return nil
}

func (s *Store) enforceSingleIdentityProviderPerTenant() error {
	rows, err := s.db.Query(`SELECT tenant_id
		FROM identity_provider_configs
		WHERE tenant_id <> ''
		GROUP BY tenant_id
		HAVING COUNT(*) > 1`)
	if err != nil {
		return fmt.Errorf("query duplicate tenant IdPs: %w", err)
	}

	var tenantIDs []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return fmt.Errorf("scan duplicate tenant IdP: %w", err)
		}
		tenantIDs = append(tenantIDs, tenantID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate duplicate tenant IdPs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close duplicate tenant IdPs: %w", err)
	}

	for _, tenantID := range tenantIDs {
		keepID, err := s.identityProviderToKeep(tenantID)
		if err != nil {
			return err
		}
		if keepID == "" {
			continue
		}
		removed, err := s.deleteIdentityProvidersExcept(tenantID, keepID)
		if err != nil {
			return err
		}
		if removed > 0 {
			log.Printf("[STORE] Kept IdP %s for tenant %s and removed %d extra IdP config(s)", keepID, tenantID, removed)
		}
	}
	return nil
}

func (s *Store) identityProviderToKeep(tenantID string) (string, error) {
	var keepID string
	err := s.db.QueryRow(`SELECT cfg.id
		FROM identity_provider_configs cfg
		JOIN tenants t ON t.id = cfg.tenant_id
		WHERE cfg.tenant_id = ? AND cfg.id = t.default_idp_id AND cfg.enabled = 1
		LIMIT 1`, tenantID).Scan(&keepID)
	if err == nil {
		return keepID, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("query default tenant IdP: %w", err)
	}

	err = s.db.QueryRow(`SELECT id
		FROM identity_provider_configs
		WHERE tenant_id = ? AND enabled = 1
		ORDER BY created_at ASC, id ASC
		LIMIT 1`, tenantID).Scan(&keepID)
	if err == nil {
		return keepID, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("query first enabled tenant IdP: %w", err)
	}

	err = s.db.QueryRow(`SELECT id
		FROM identity_provider_configs
		WHERE tenant_id = ?
		ORDER BY created_at ASC, id ASC
		LIMIT 1`, tenantID).Scan(&keepID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query first tenant IdP: %w", err)
	}
	return keepID, nil
}

func (s *Store) reconcileSingleIdentityProviderDefaults() error {
	_, err := s.db.Exec(`UPDATE tenants
		SET default_idp_id = COALESCE((
			SELECT cfg.id
			FROM identity_provider_configs cfg
			WHERE cfg.tenant_id = tenants.id AND cfg.enabled = 1
			ORDER BY cfg.created_at ASC, cfg.id ASC
			LIMIT 1
		), '')
		WHERE EXISTS (
			SELECT 1 FROM identity_provider_configs cfg
			WHERE cfg.tenant_id = tenants.id
		)
		AND (
			default_idp_id = ''
			OR NOT EXISTS (
				SELECT 1 FROM identity_provider_configs cfg
				WHERE cfg.tenant_id = tenants.id
					AND cfg.id = tenants.default_idp_id
					AND cfg.enabled = 1
			)
		)`)
	if err != nil {
		return fmt.Errorf("reconcile tenant default IdP: %w", err)
	}
	return nil
}

func (s *Store) deleteIdentityProvidersExcept(tenantID, keepID string) (int, error) {
	rows, err := s.db.Query(`SELECT id
		FROM identity_provider_configs
		WHERE tenant_id = ? AND id <> ?`, tenantID, keepID)
	if err != nil {
		return 0, fmt.Errorf("query extra tenant IdPs: %w", err)
	}

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan extra tenant IdP: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate extra tenant IdPs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close extra tenant IdPs: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin tenant IdP cleanup: %w", err)
	}
	defer tx.Rollback()

	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM directory_group_members WHERE tenant_id = ? AND idp_id = ?`, tenantID, id); err != nil {
			return 0, fmt.Errorf("delete directory group members for IdP %s: %w", id, err)
		}
		if _, err := tx.Exec(`DELETE FROM directory_groups WHERE tenant_id = ? AND idp_id = ?`, tenantID, id); err != nil {
			return 0, fmt.Errorf("delete directory groups for IdP %s: %w", id, err)
		}
		if _, err := tx.Exec(`DELETE FROM directory_users WHERE tenant_id = ? AND idp_id = ?`, tenantID, id); err != nil {
			return 0, fmt.Errorf("delete directory users for IdP %s: %w", id, err)
		}
		if _, err := tx.Exec(`DELETE FROM identity_provider_configs WHERE tenant_id = ? AND id = ?`, tenantID, id); err != nil {
			return 0, fmt.Errorf("delete IdP %s: %w", id, err)
		}
	}

	if _, err := tx.Exec(`UPDATE tenants SET default_idp_id = ? WHERE id = ?`, keepID, tenantID); err != nil {
		return 0, fmt.Errorf("update tenant default IdP: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tenant IdP cleanup: %w", err)
	}
	return len(ids), nil
}
