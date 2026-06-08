package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"pdp/models"
)

func TestConsumeTokenOnceIsAtomicReplayGuard(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	expiresAt := time.Now().Add(5 * time.Minute)
	if !s.ConsumeTokenOnce("jti-1", expiresAt) {
		t.Fatalf("first ConsumeTokenOnce returned false")
	}
	if s.ConsumeTokenOnce("jti-1", expiresAt) {
		t.Fatalf("second ConsumeTokenOnce returned true")
	}
	if !s.IsTokenRevoked("jti-1") {
		t.Fatalf("consumed token was not recorded")
	}
}

func TestAddAuditEntrySuppressesOIDCProtocolEvents(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	s.AddAuditEntry(&models.AuditEntry{
		ID:        "aud-oidc",
		Timestamp: time.Now(),
		EventType: "oidc_token_exchange",
		Username:  "alice",
		Details:   "Token exchange",
		Success:   true,
	})
	s.AddAuditEntry(&models.AuditEntry{
		ID:        "aud-admin",
		Timestamp: time.Now(),
		EventType: "admin_login",
		Username:  "alice",
		Details:   "Admin login",
		Success:   true,
	})

	entries := s.GetAuditLog(10)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].EventType != "admin_login" {
		t.Fatalf("event type = %q, want admin_login", entries[0].EventType)
	}
}

func TestInitDBRemovesSuppressedAuditEntriesAndRechains(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "trustcloud.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE audit_log (
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
	)`)
	if err != nil {
		t.Fatalf("create audit table: %v", err)
	}
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, entry := range []models.AuditEntry{
		{ID: "aud-before", Timestamp: base, EventType: "admin_login", Username: "alice", Details: "Admin login", Success: true},
		{ID: "aud-oidc", Timestamp: base.Add(time.Second), EventType: "oidc_token_refresh", Username: "alice", Details: "Refresh", Success: true},
		{ID: "aud-after", Timestamp: base.Add(2 * time.Second), EventType: "session_revoked", Username: "alice", Details: "Session revoked", Success: true},
	} {
		if _, err := db.Exec(`INSERT INTO audit_log
			(id, timestamp, event_type, user_id, username, source_ip, resource, decision, details, success, tenant_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.ID, fmtTime(entry.Timestamp), entry.EventType, entry.UserID, entry.Username,
			entry.SourceIP, entry.Resource, entry.Decision, entry.Details, b2i(entry.Success), entry.TenantID); err != nil {
			t.Fatalf("insert audit entry %s: %v", entry.ID, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close audit db: %v", err)
	}

	s := NewWithDatabasePath(dataDir, dbPath)
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	entries := s.GetAuditLog(10)
	if len(entries) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if isSuppressedAuditEvent(entry.EventType) {
			t.Fatalf("suppressed audit event still present: %s", entry.EventType)
		}
	}
	if err := s.VerifyAuditChain(); err != nil {
		t.Fatalf("VerifyAuditChain returned error: %v", err)
	}
}

func TestIdentityProviderConfigsAreUniquePerTenant(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	s.SaveTenant(&models.Tenant{ID: "tenant-1", Name: "Tenant 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	s.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:        "idp-1",
		TenantID:  "tenant-1",
		Name:      "IdP 1",
		Type:      "oidc",
		Enabled:   true,
		Issuer:    "https://idp1.example.test",
		ClientID:  "client-1",
		CreatedAt: now,
		UpdatedAt: now,
	})
	s.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:        "idp-2",
		TenantID:  "tenant-1",
		Name:      "IdP 2",
		Type:      "oidc",
		Enabled:   true,
		Issuer:    "https://idp2.example.test",
		ClientID:  "client-2",
		CreatedAt: now.Add(time.Second),
		UpdatedAt: now.Add(time.Second),
	})

	cfgs := s.ListIdentityProviderConfigsForTenant("tenant-1")
	if len(cfgs) != 1 {
		t.Fatalf("IdP count = %d, want 1", len(cfgs))
	}
}

func TestEnsureDefaultGlobalPolicyForTenantCreatesBaseline(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	s.SaveTenant(&models.Tenant{ID: "tenant-1", Name: "Tenant 1", Enabled: true, CreatedAt: now, UpdatedAt: now})

	rule, assignment := s.EnsureDefaultGlobalPolicyForTenant("tenant-1")
	if rule == nil || assignment == nil {
		t.Fatalf("EnsureDefaultGlobalPolicyForTenant returned rule=%v assignment=%v", rule, assignment)
	}
	if rule.ID != DefaultGlobalPolicyID("tenant-1") || rule.Name != "Global Policy" || rule.Action != models.DecisionStepUpRequired {
		t.Fatalf("default rule = %+v", rule)
	}
	if rule.Conditions.User.NewUserPolicy != models.NewUserPolicyRequireEnrollment {
		t.Fatalf("new user policy = %q, want %q", rule.Conditions.User.NewUserPolicy, models.NewUserPolicyRequireEnrollment)
	}
	if rule.Conditions.Authentication.Policy != models.AuthenticationPolicyEnforceMFA {
		t.Fatalf("authentication policy = %q, want %q", rule.Conditions.Authentication.Policy, models.AuthenticationPolicyEnforceMFA)
	}
	if !sameStrings(rule.Conditions.Authentication.StepUpMethods, []string{"totp", "webauthn"}) {
		t.Fatalf("step-up methods = %v, want totp/webauthn", rule.Conditions.Authentication.StepUpMethods)
	}
	if assignment.ID != DefaultGlobalAssignmentID("tenant-1") ||
		assignment.PolicyID != rule.ID ||
		assignment.TenantID != "tenant-1" ||
		assignment.Level != "organization" ||
		assignment.OrderIndex != defaultGlobalOrderIndex ||
		!assignment.Enabled {
		t.Fatalf("default assignment = %+v", assignment)
	}

	s.EnsureDefaultGlobalPolicyForTenant("tenant-1")
	if got := s.ListPolicyAssignmentsForPolicy(rule.ID); len(got) != 1 {
		t.Fatalf("default assignment count after second ensure = %d, want 1", len(got))
	}
}

func TestInitDBDropsLegacyPolicyPriorityColumns(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "trustcloud.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE policy_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			priority INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			conditions_json TEXT DEFAULT '{}',
			action TEXT NOT NULL,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		);
		CREATE TABLE policy_assignments (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			level TEXT DEFAULT 'organization',
			tenant_id TEXT NOT NULL,
			resource_id TEXT DEFAULT '',
			group_id TEXT DEFAULT '',
			group_name TEXT DEFAULT '',
			priority INTEGER NOT NULL DEFAULT 100,
			enabled INTEGER DEFAULT 1,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		);
	`)
	if closeErr := db.Close(); closeErr != nil {
		t.Fatalf("close legacy db: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("create legacy policy tables: %v", err)
	}

	s := NewWithDatabasePath(dataDir, dbPath)
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	for _, tableName := range []string{"policy_rules", "policy_assignments"} {
		hasPriority, err := s.tableHasColumn(tableName, "priority")
		if err != nil {
			t.Fatalf("tableHasColumn(%s): %v", tableName, err)
		}
		if hasPriority {
			t.Fatalf("%s still has priority column", tableName)
		}
	}
	hasOrderIndex, err := s.tableHasColumn("policy_assignments", "order_index")
	if err != nil {
		t.Fatalf("tableHasColumn(policy_assignments, order_index): %v", err)
	}
	if !hasOrderIndex {
		t.Fatalf("policy_assignments missing order_index column")
	}
}

func TestInitDBDisablesNonCanonicalPolicyActions(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "trustcloud.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE schema_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		INSERT INTO schema_meta(key, value) VALUES
			('legacy_policy_cleanup_v1', 'done'),
			('duo_policy_model_reset_v1', 'done');
		CREATE TABLE policy_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			conditions_json TEXT DEFAULT '{}',
			action TEXT NOT NULL,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		);
		INSERT INTO policy_rules(id, name, action) VALUES
			('policy-canonical', 'Canonical', 'step_up_required'),
			('policy-invalid', 'Invalid', 'custom_action');
	`)
	if closeErr := db.Close(); closeErr != nil {
		t.Fatalf("close legacy db: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("create legacy policy actions: %v", err)
	}

	s := NewWithDatabasePath(dataDir, dbPath)
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	got := map[string]struct {
		action  string
		enabled int
	}{}
	rows, err := s.db.Query(`SELECT id, action, enabled FROM policy_rules`)
	if err != nil {
		t.Fatalf("query policy actions: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, action string
		var enabled int
		if err := rows.Scan(&id, &action, &enabled); err != nil {
			t.Fatalf("scan policy action: %v", err)
		}
		got[id] = struct {
			action  string
			enabled int
		}{action: action, enabled: enabled}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate policy actions: %v", err)
	}

	if got["policy-canonical"].action != models.DecisionStepUpRequired || got["policy-canonical"].enabled != 1 {
		t.Fatalf("canonical policy = %+v, want enabled %q", got["policy-canonical"], models.DecisionStepUpRequired)
	}
	if got["policy-invalid"].action != models.DecisionDeny || got["policy-invalid"].enabled != 0 {
		t.Fatalf("invalid policy = %+v, want disabled deny", got["policy-invalid"])
	}
}

func TestInitDBKeepsExistingPoliciesForDuoModel(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "trustcloud.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open existing policy db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE schema_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		INSERT INTO schema_meta(key, value) VALUES ('legacy_policy_cleanup_v1', 'done');
		CREATE TABLE policy_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			conditions_json TEXT DEFAULT '{}',
			action TEXT NOT NULL,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		);
		CREATE TABLE policy_assignments (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			level TEXT DEFAULT 'organization',
			tenant_id TEXT NOT NULL,
			resource_id TEXT DEFAULT '',
			group_id TEXT DEFAULT '',
			group_name TEXT DEFAULT '',
			order_index INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			created_at TEXT DEFAULT '',
			updated_at TEXT DEFAULT ''
		);
		INSERT INTO policy_rules(id, name, action) VALUES ('policy-old', 'Old policy', 'allow');
		INSERT INTO policy_assignments(id, policy_id, tenant_id) VALUES ('assign-old', 'policy-old', 'tenant-1');
	`)
	if closeErr := db.Close(); closeErr != nil {
		t.Fatalf("close existing policy db: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("create existing policy data: %v", err)
	}

	s := NewWithDatabasePath(dataDir, dbPath)
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	for _, tc := range []struct {
		table string
		want  int
	}{
		{table: "policy_rules", want: 1},
		{table: "policy_assignments", want: 1},
	} {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + tc.table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", tc.table, err)
		}
		if count != tc.want {
			t.Fatalf("%s count = %d, want %d", tc.table, count, tc.want)
		}
	}

	var marker string
	if err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key = 'duo_policy_model_reset_v1'`).Scan(&marker); err != nil {
		t.Fatalf("query Duo reset marker: %v", err)
	}
	if marker != "done" {
		t.Fatalf("Duo reset marker = %q, want done", marker)
	}
}

func TestPolicyAssignmentsUseDuoStyleLevelsForAccess(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	for _, rule := range []*models.PolicyRule{
		{ID: "policy-org", Name: "Org", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-group", Name: "Group", Enabled: true, Action: "step_up_required", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-resource", Name: "Resource", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-resource-group", Name: "Resource Group", Enabled: true, Action: "deny", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-legacy-gateway", Name: "Legacy Gateway", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
	} {
		s.SavePolicyRule(rule)
	}
	for _, assignment := range []*models.PolicyAssignment{
		{ID: "assign-org", PolicyID: "policy-org", Level: "organization", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-group", PolicyID: "policy-group", Level: "group", TenantID: "tenant-1", GroupID: "grp-finance", GroupName: "Finance", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-resource", PolicyID: "policy-resource", Level: "resource", TenantID: "tenant-1", ResourceID: "res-payroll", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-resource-group", PolicyID: "policy-resource-group", Level: "resource_group", TenantID: "tenant-1", ResourceID: "res-payroll", GroupID: "grp-finance", GroupName: "Finance", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-legacy-gateway", PolicyID: "policy-legacy-gateway", Level: "legacy_gateway", TenantID: "tenant-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		s.SavePolicyAssignment(assignment)
	}

	rules := s.ListPolicyRulesForAccessGroups("tenant-1", "res-payroll", []string{"grp-finance"}, []string{"Finance"})
	got := policyRuleIDs(rules)
	want := []string{"policy-resource-group", "policy-resource", "policy-group", "policy-org"}
	if !sameStrings(got, want) {
		t.Fatalf("policy order = %v, want %v", got, want)
	}

	rules = s.ListPolicyRulesForAccessGroups("tenant-1", "res-payroll", []string{"grp-sales"}, []string{"Sales"})
	got = policyRuleIDs(rules)
	want = []string{"policy-resource", "policy-org"}
	if !sameStrings(got, want) {
		t.Fatalf("policy order without group match = %v, want %v", got, want)
	}
}

func TestPolicyAssignmentPlacementOrdersPoliciesWithinScope(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	for _, rule := range []*models.PolicyRule{
		{ID: "policy-first", Name: "First", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-second", Name: "Second", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-top", Name: "Top", Enabled: true, Action: "step_up_required", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-bottom", Name: "Bottom", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-replace", Name: "Replace", Enabled: true, Action: "deny", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-other", Name: "Other", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
	} {
		s.SavePolicyRule(rule)
	}

	s.SavePolicyAssignment(&models.PolicyAssignment{
		ID: "assign-first", PolicyID: "policy-first", Level: "resource", TenantID: "tenant-1",
		ResourceID: "res-payroll", OrderIndex: 0, Enabled: true, CreatedAt: now, UpdatedAt: now,
	})
	s.SavePolicyAssignment(&models.PolicyAssignment{
		ID: "assign-second", PolicyID: "policy-second", Level: "resource", TenantID: "tenant-1",
		ResourceID: "res-payroll", OrderIndex: 100, Enabled: true, CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second),
	})
	s.SavePolicyAssignment(&models.PolicyAssignment{
		ID: "assign-other", PolicyID: "policy-other", Level: "resource", TenantID: "tenant-1",
		ResourceID: "res-expenses", OrderIndex: 0, Enabled: true, CreatedAt: now, UpdatedAt: now,
	})

	s.SavePolicyAssignmentWithPlacement(&models.PolicyAssignment{
		ID: "assign-top", PolicyID: "policy-top", Level: "resource", TenantID: "tenant-1",
		ResourceID: "res-payroll", Enabled: true, CreatedAt: now.Add(2 * time.Second), UpdatedAt: now.Add(2 * time.Second),
	}, "top")
	s.SavePolicyAssignmentWithPlacement(&models.PolicyAssignment{
		ID: "assign-bottom", PolicyID: "policy-bottom", Level: "resource", TenantID: "tenant-1",
		ResourceID: "res-payroll", Enabled: true, CreatedAt: now.Add(3 * time.Second), UpdatedAt: now.Add(3 * time.Second),
	}, "bottom")

	rules := s.ListPolicyRulesForAccessGroups("tenant-1", "res-payroll", nil, nil)
	got := policyRuleIDs(rules)
	want := []string{"policy-top", "policy-first", "policy-second", "policy-bottom"}
	if !sameStrings(got, want) {
		t.Fatalf("ordered policies = %v, want %v", got, want)
	}

	deleted := s.SavePolicyAssignmentWithPlacement(&models.PolicyAssignment{
		ID: "assign-replace", PolicyID: "policy-replace", Level: "resource", TenantID: "tenant-1",
		ResourceID: "res-payroll", Enabled: true, CreatedAt: now.Add(4 * time.Second), UpdatedAt: now.Add(4 * time.Second),
	}, "replace")
	if len(deleted) != 4 {
		t.Fatalf("replace deleted %d assignments, want 4", len(deleted))
	}

	rules = s.ListPolicyRulesForAccessGroups("tenant-1", "res-payroll", nil, nil)
	got = policyRuleIDs(rules)
	want = []string{"policy-replace"}
	if !sameStrings(got, want) {
		t.Fatalf("replacement policies = %v, want %v", got, want)
	}

	rules = s.ListPolicyRulesForAccessGroups("tenant-1", "res-expenses", nil, nil)
	got = policyRuleIDs(rules)
	want = []string{"policy-other"}
	if !sameStrings(got, want) {
		t.Fatalf("other scope policies = %v, want %v", got, want)
	}
}

func policyRuleIDs(rules []*models.PolicyRule) []string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule != nil {
			ids = append(ids, rule.ID)
		}
	}
	return ids
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
