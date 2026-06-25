package store

import "fmt"

func (s *Store) createTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			password_change_required INTEGER DEFAULT 0,
			password_changed_at TEXT DEFAULT '',
			totp_secret TEXT DEFAULT '',
			mfa_methods_json TEXT DEFAULT '[]',
			last_totp_counter INTEGER DEFAULT -1,
			role TEXT DEFAULT 'platform_admin',
			disabled INTEGER DEFAULT 0,
			organization_id TEXT DEFAULT '',
			external_subject TEXT DEFAULT '',
			auth_source TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			last_login_at TEXT DEFAULT ''
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_change_required INTEGER DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TEXT DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(lower(email))`,

		`CREATE TABLE IF NOT EXISTS organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			domain TEXT DEFAULT '',
			description TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			default_idp_id TEXT DEFAULT '',
			domains_json TEXT DEFAULT '[]',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,

		`CREATE TABLE IF NOT EXISTS organization_memberships (
			user_id TEXT NOT NULL,
			organization_id TEXT NOT NULL,
			role TEXT DEFAULT 'platform_admin',
			created_at TEXT DEFAULT '',
			PRIMARY KEY (user_id, organization_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_organization_memberships_user ON organization_memberships(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_organization_memberships_org ON organization_memberships(organization_id)`,

		`CREATE TABLE IF NOT EXISTS policy_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			conditions_json TEXT DEFAULT '{}',
			action TEXT NOT NULL,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,

		`CREATE TABLE IF NOT EXISTS policy_assignments (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			level TEXT DEFAULT 'organization',
			organization_id TEXT NOT NULL,
			resource_id TEXT DEFAULT '',
			group_id TEXT DEFAULT '',
			group_name TEXT DEFAULT '',
			order_index INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy ON policy_assignments(policy_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_level ON policy_assignments(level)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_organization ON policy_assignments(organization_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_resource ON policy_assignments(resource_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_group ON policy_assignments(group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_policy_assignments_order ON policy_assignments(organization_id, level, order_index)`,

		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT DEFAULT '',
			username TEXT DEFAULT '',
			device_id TEXT DEFAULT '',
			source_ip TEXT DEFAULT '',
			resource TEXT DEFAULT '',
			gateway_id TEXT DEFAULT '',
			protocol TEXT DEFAULT '',
			risk_signals_json TEXT DEFAULT '[]',
			organization_id TEXT DEFAULT '',
			policy_id TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			expires_at TEXT DEFAULT '',
			last_activity TEXT DEFAULT '',
			revalidate_after TEXT DEFAULT '',
			step_up_acr TEXT DEFAULT '',
			step_up_method TEXT DEFAULT '',
			step_up_strength TEXT DEFAULT '',
			step_up_aaguid TEXT DEFAULT '',
			step_up_attachment TEXT DEFAULT '',
			step_up_verified_at TEXT DEFAULT '',
			step_up_expires_at TEXT DEFAULT '',
			session_max_age_seconds INTEGER DEFAULT 0,
			revalidate_every_seconds INTEGER DEFAULT 0,
			revoke_on_posture_change INTEGER DEFAULT 0,
			revoked INTEGER DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,

		`CREATE TABLE IF NOT EXISTS resources (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			type TEXT DEFAULT '',
			host TEXT DEFAULT '',
			external_port INTEGER DEFAULT 0,
			internal_port INTEGER DEFAULT 0,
			external_url TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			tags_json TEXT DEFAULT '[]',
			metadata_json TEXT DEFAULT '{}',
			organization_id TEXT DEFAULT '',
			gateway_id TEXT DEFAULT '',
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
			organization_id TEXT DEFAULT '',
			prev_hash TEXT DEFAULT '',
			entry_hash TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)`,

		`CREATE TABLE IF NOT EXISTS device_data (
			device_id TEXT PRIMARY KEY,
			user_id TEXT DEFAULT '',
			username TEXT DEFAULT '',
			agent_session_id TEXT DEFAULT '',
			hostname TEXT DEFAULT '',
			os TEXT DEFAULT '',
			checks_json TEXT DEFAULT '[]',
			collected_at TEXT DEFAULT '',
			reported_at TEXT DEFAULT '',
			organization_id TEXT DEFAULT ''
		)`,
		`ALTER TABLE device_data ADD COLUMN IF NOT EXISTS user_id TEXT DEFAULT ''`,
		`ALTER TABLE device_data ADD COLUMN IF NOT EXISTS username TEXT DEFAULT ''`,
		`ALTER TABLE device_data ADD COLUMN IF NOT EXISTS agent_session_id TEXT DEFAULT ''`,

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
			organization_id TEXT DEFAULT ''
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
			organization_id TEXT DEFAULT '',
			organization_ids_json TEXT DEFAULT '[]',
			enrollment_token TEXT DEFAULT '',
			token_expires_at TEXT DEFAULT '',
			status TEXT DEFAULT 'pending',
			cert_pem TEXT DEFAULT '',
			cert_fingerprint TEXT DEFAULT '',
			cert_serial TEXT DEFAULT '',
			cert_expires_at TEXT DEFAULT '',
			listen_addr TEXT DEFAULT '',
			public_ip TEXT DEFAULT '',
			assigned_resources_json TEXT DEFAULT '[]',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			last_seen_at TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_gateways_token ON gateways(enrollment_token)`,

		`CREATE TABLE IF NOT EXISTS oidc_clients (
			client_id TEXT PRIMARY KEY,
			client_secret TEXT DEFAULT '',
			redirect_uris_json TEXT DEFAULT '[]',
			name TEXT DEFAULT '',
			public INTEGER DEFAULT 1,
			require_pkce INTEGER DEFAULT 1,
			require_device_id INTEGER DEFAULT 0,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,

		`CREATE TABLE IF NOT EXISTS login_locations (
			id BIGSERIAL PRIMARY KEY,
			user_id TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			latitude DOUBLE PRECISION NOT NULL,
			longitude DOUBLE PRECISION NOT NULL,
			city TEXT DEFAULT '',
			country TEXT DEFAULT '',
			timestamp TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_login_locations_user ON login_locations(user_id, timestamp)`,

		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id TEXT NOT NULL,
			credential_json TEXT NOT NULL,
			name TEXT DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credential_id ON webauthn_credentials(credential_id)`,

		`CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			created_at TEXT NOT NULL,
			used_at TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user ON mfa_recovery_codes(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_active ON mfa_recovery_codes(user_id, used_at)`,

		`CREATE TABLE IF NOT EXISTS identity_provider_configs (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL,
			name TEXT DEFAULT '',
			type TEXT DEFAULT 'oidc',
			enabled INTEGER DEFAULT 1,
			domains_json TEXT DEFAULT '[]',
			issuer TEXT DEFAULT '',
			client_id TEXT DEFAULT '',
			client_secret TEXT DEFAULT '',
			scim_token TEXT DEFAULT '',
			scim_token_expires_at TEXT DEFAULT '',
			scim_token_rotated_at TEXT DEFAULT '',
			scopes TEXT DEFAULT '',
			auto_discovery INTEGER DEFAULT 1,
			claim_mapping_json TEXT DEFAULT '{}',
			group_role_mapping_json TEXT DEFAULT '[]',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		)`,
		`ALTER TABLE identity_provider_configs ADD COLUMN IF NOT EXISTS scim_token_expires_at TEXT DEFAULT ''`,
		`ALTER TABLE identity_provider_configs ADD COLUMN IF NOT EXISTS scim_token_rotated_at TEXT DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_idp_organization ON identity_provider_configs(organization_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_idp_single_organization ON identity_provider_configs(organization_id) WHERE organization_id <> ''`,

		`CREATE TABLE IF NOT EXISTS directory_users (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL,
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
			UNIQUE(organization_id, idp_id, user_name)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_users_organization_idp ON directory_users(organization_id, idp_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_directory_users_external_id ON directory_users(organization_id, idp_id, external_id) WHERE external_id <> ''`,

		`CREATE TABLE IF NOT EXISTS directory_groups (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL,
			idp_id TEXT NOT NULL,
			external_id TEXT DEFAULT '',
			display_name TEXT NOT NULL,
			raw_json TEXT DEFAULT '',
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT '',
			UNIQUE(organization_id, idp_id, display_name)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_groups_organization_idp ON directory_groups(organization_id, idp_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_directory_groups_external_id ON directory_groups(organization_id, idp_id, external_id) WHERE external_id <> ''`,

		`CREATE TABLE IF NOT EXISTS directory_group_members (
			organization_id TEXT NOT NULL,
			idp_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			created_at TEXT DEFAULT '',
			PRIMARY KEY (organization_id, idp_id, group_id, user_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_group_members_group ON directory_group_members(organization_id, idp_id, group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_directory_group_members_user ON directory_group_members(organization_id, idp_id, user_id)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("exec: %w\nSQL: %s", err, stmt)
		}
	}
	return nil
}
