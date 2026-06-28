package store

import (
	"os"
	"strings"
	"testing"
	"time"

	"pdp/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("PDP_TEST_DATABASE_URL"))
	if databaseURL == "" {
		databaseURL = strings.TrimSpace(os.Getenv("PDP_DATABASE_URL"))
	}
	if databaseURL == "" {
		t.Skip("set PDP_TEST_DATABASE_URL or PDP_DATABASE_URL to run PostgreSQL store tests")
	}

	s := NewWithDatabaseURL(t.TempDir(), databaseURL)
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	resetTestStore(t, s)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func resetTestStore(t *testing.T, s *Store) {
	t.Helper()
	_, err := s.db.Exec(`TRUNCATE TABLE
		directory_group_members,
		directory_groups,
		directory_users,
		identity_provider_configs,
		mfa_recovery_codes,
		webauthn_credentials,
		login_locations,
		oidc_clients,
		gateways,
		device_users,
		revoked_certs,
		device_enrollments,
		revoked_tokens,
		device_data,
		audit_log,
		resources,
		sessions,
		policy_assignments,
		policy_rules,
		organization_memberships,
		organizations,
		users
		RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("reset test store: %v", err)
	}
}

func TestConsumeTokenOnceIsAtomicReplayGuard(t *testing.T) {
	s := newTestStore(t)

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
	s := newTestStore(t)

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
	if err := s.VerifyAuditChain(); err != nil {
		t.Fatalf("VerifyAuditChain returned error: %v", err)
	}
}

func TestAddAuditEntryResolvesUserContext(t *testing.T) {
	s := newTestStore(t)

	now := time.Now().UTC()
	s.SaveUser(&models.User{
		ID:             "user-1",
		Username:       "alice@example.test",
		Email:          "alice@example.test",
		Role:           "platform_admin",
		OrganizationID: "organization-1",
		CreatedAt:      now,
		UpdatedAt:      now,
	})

	s.AddAuditEntry(&models.AuditEntry{
		ID:        "aud-login",
		Timestamp: now,
		EventType: "admin_login",
		Username:  "alice@example.test",
		Details:   "Invalid credentials",
		Success:   false,
	})

	entries := s.GetAuditLog(10)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].UserID != "user-1" || entries[0].Username != "alice@example.test" || entries[0].OrganizationID != "organization-1" {
		t.Fatalf("resolved audit context = %+v", entries[0])
	}
}

func TestAddAuditEntrySkipsEventsWithoutUserContext(t *testing.T) {
	s := newTestStore(t)

	s.AddAuditEntry(&models.AuditEntry{
		ID:        "aud-system",
		Timestamp: time.Now().UTC(),
		EventType: "agent_user_authentication_request",
		Resource:  "device-1",
		Details:   "pre-authentication event",
		Success:   true,
	})

	if entries := s.GetAuditLog(10); len(entries) != 0 {
		t.Fatalf("audit entries = %d, want 0", len(entries))
	}
}

func TestIdentityProviderConfigsAreUniquePerOrganization(t *testing.T) {
	s := newTestStore(t)

	now := time.Now().UTC()
	s.SaveOrganization(&models.Organization{ID: "organization-1", Name: "Organization 1", Enabled: true, CreatedAt: now, UpdatedAt: now})
	s.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:             "idp-1",
		OrganizationID: "organization-1",
		Name:           "IdP 1",
		Type:           "oidc",
		Enabled:        true,
		Issuer:         "https://idp1.example.test",
		ClientID:       "client-1",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	s.SaveIdentityProviderConfig(&models.IdentityProviderConfig{
		ID:             "idp-2",
		OrganizationID: "organization-1",
		Name:           "IdP 2",
		Type:           "oidc",
		Enabled:        true,
		Issuer:         "https://idp2.example.test",
		ClientID:       "client-2",
		CreatedAt:      now.Add(time.Second),
		UpdatedAt:      now.Add(time.Second),
	})

	cfgs := s.ListIdentityProviderConfigsForOrganization("organization-1")
	if len(cfgs) != 1 {
		t.Fatalf("IdP count = %d, want 1", len(cfgs))
	}
}

func TestEnsureDefaultGlobalPolicyForOrganizationCreatesBaseline(t *testing.T) {
	s := newTestStore(t)

	now := time.Now().UTC()
	s.SaveOrganization(&models.Organization{ID: "organization-1", Name: "Organization 1", Enabled: true, CreatedAt: now, UpdatedAt: now})

	rule, assignment := s.EnsureDefaultGlobalPolicyForOrganization("organization-1")
	if rule == nil || assignment == nil {
		t.Fatalf("EnsureDefaultGlobalPolicyForOrganization returned rule=%v assignment=%v", rule, assignment)
	}
	if rule.ID != DefaultGlobalPolicyID("organization-1") || rule.Name != "Global Policy" || rule.Action != models.DecisionStepUpRequired {
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
	if assignment.ID != DefaultGlobalAssignmentID("organization-1") ||
		assignment.PolicyID != rule.ID ||
		assignment.OrganizationID != "organization-1" ||
		assignment.Level != "organization" ||
		assignment.OrderIndex != defaultGlobalOrderIndex ||
		!assignment.Enabled {
		t.Fatalf("default assignment = %+v", assignment)
	}

	s.EnsureDefaultGlobalPolicyForOrganization("organization-1")
	if got := s.ListPolicyAssignmentsForPolicy(rule.ID); len(got) != 1 {
		t.Fatalf("default assignment count after second ensure = %d, want 1", len(got))
	}
}

func TestPolicyAssignmentsUseDuoStyleLevelsForAccess(t *testing.T) {
	s := newTestStore(t)

	now := time.Now().UTC()
	for _, rule := range []*models.PolicyRule{
		{ID: "policy-org", Name: "Org", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-group", Name: "Group", Enabled: true, Action: "step_up_required", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-resource", Name: "Resource", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-resource-group", Name: "Resource Group", Enabled: true, Action: "deny", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-gateway", Name: "Gateway", Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
	} {
		s.SavePolicyRule(rule)
	}
	for _, assignment := range []*models.PolicyAssignment{
		{ID: "assign-org", PolicyID: "policy-org", Level: "organization", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-group", PolicyID: "policy-group", Level: "group", OrganizationID: "organization-1", GroupID: "grp-finance", GroupName: "Finance", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-resource", PolicyID: "policy-resource", Level: "resource", OrganizationID: "organization-1", ResourceID: "res-payroll", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-resource-group", PolicyID: "policy-resource-group", Level: "resource_group", OrganizationID: "organization-1", ResourceID: "res-payroll", GroupID: "grp-finance", GroupName: "Finance", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-gateway", PolicyID: "policy-gateway", Level: "gateway", OrganizationID: "organization-1", Enabled: true, CreatedAt: now, UpdatedAt: now},
	} {
		s.SavePolicyAssignment(assignment)
	}

	rules := s.ListPolicyRulesForAccessGroups("organization-1", "res-payroll", []string{"grp-finance"}, []string{"Finance"})
	got := policyRuleIDs(rules)
	want := []string{"policy-resource-group", "policy-resource", "policy-group", "policy-org"}
	if !sameStrings(got, want) {
		t.Fatalf("policy order = %v, want %v", got, want)
	}

	rules = s.ListPolicyRulesForAccessGroups("organization-1", "res-payroll", []string{"grp-sales"}, []string{"Sales"})
	got = policyRuleIDs(rules)
	want = []string{"policy-resource", "policy-org"}
	if !sameStrings(got, want) {
		t.Fatalf("policy order without group match = %v, want %v", got, want)
	}
}

func TestPolicyAssignmentPlacementOrdersPoliciesWithinScope(t *testing.T) {
	s := newTestStore(t)

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
		ID: "assign-first", PolicyID: "policy-first", Level: "resource", OrganizationID: "organization-1",
		ResourceID: "res-payroll", OrderIndex: 0, Enabled: true, CreatedAt: now, UpdatedAt: now,
	})
	s.SavePolicyAssignment(&models.PolicyAssignment{
		ID: "assign-second", PolicyID: "policy-second", Level: "resource", OrganizationID: "organization-1",
		ResourceID: "res-payroll", OrderIndex: 100, Enabled: true, CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second),
	})
	s.SavePolicyAssignment(&models.PolicyAssignment{
		ID: "assign-other", PolicyID: "policy-other", Level: "resource", OrganizationID: "organization-1",
		ResourceID: "res-expenses", OrderIndex: 0, Enabled: true, CreatedAt: now, UpdatedAt: now,
	})

	s.SavePolicyAssignmentWithPlacement(&models.PolicyAssignment{
		ID: "assign-top", PolicyID: "policy-top", Level: "resource", OrganizationID: "organization-1",
		ResourceID: "res-payroll", Enabled: true, CreatedAt: now.Add(2 * time.Second), UpdatedAt: now.Add(2 * time.Second),
	}, "top")
	s.SavePolicyAssignmentWithPlacement(&models.PolicyAssignment{
		ID: "assign-bottom", PolicyID: "policy-bottom", Level: "resource", OrganizationID: "organization-1",
		ResourceID: "res-payroll", Enabled: true, CreatedAt: now.Add(3 * time.Second), UpdatedAt: now.Add(3 * time.Second),
	}, "bottom")

	rules := s.ListPolicyRulesForAccessGroups("organization-1", "res-payroll", nil, nil)
	got := policyRuleIDs(rules)
	want := []string{"policy-top", "policy-first", "policy-second", "policy-bottom"}
	if !sameStrings(got, want) {
		t.Fatalf("ordered policies = %v, want %v", got, want)
	}

	deleted := s.SavePolicyAssignmentWithPlacement(&models.PolicyAssignment{
		ID: "assign-replace", PolicyID: "policy-replace", Level: "resource", OrganizationID: "organization-1",
		ResourceID: "res-payroll", Enabled: true, CreatedAt: now.Add(4 * time.Second), UpdatedAt: now.Add(4 * time.Second),
	}, "replace")
	if len(deleted) != 4 {
		t.Fatalf("replace deleted %d assignments, want 4", len(deleted))
	}

	rules = s.ListPolicyRulesForAccessGroups("organization-1", "res-payroll", nil, nil)
	got = policyRuleIDs(rules)
	want = []string{"policy-replace"}
	if !sameStrings(got, want) {
		t.Fatalf("replacement policies = %v, want %v", got, want)
	}

	rules = s.ListPolicyRulesForAccessGroups("organization-1", "res-expenses", nil, nil)
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
