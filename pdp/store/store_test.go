package store

import (
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

func TestPolicyAssignmentsUseDuoStyleLevelsForAccess(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC()
	for _, rule := range []*models.PolicyRule{
		{ID: "policy-org", Name: "Org", Priority: 40, Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-group", Name: "Group", Priority: 30, Enabled: true, Action: "mfa_required", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-resource", Name: "Resource", Priority: 20, Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-resource-group", Name: "Resource Group", Priority: 10, Enabled: true, Action: "deny", CreatedAt: now, UpdatedAt: now},
		{ID: "policy-legacy-gateway", Name: "Legacy Gateway", Priority: 1, Enabled: true, Action: "allow", CreatedAt: now, UpdatedAt: now},
	} {
		s.SavePolicyRule(rule)
	}
	for _, assignment := range []*models.PolicyAssignment{
		{ID: "assign-org", PolicyID: "policy-org", Level: "organization", TenantID: "tenant-1", Priority: 40, Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-group", PolicyID: "policy-group", Level: "group", TenantID: "tenant-1", GroupID: "grp-finance", GroupName: "Finance", Priority: 30, Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-resource", PolicyID: "policy-resource", Level: "resource", TenantID: "tenant-1", ResourceID: "res-payroll", Priority: 20, Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-resource-group", PolicyID: "policy-resource-group", Level: "resource_group", TenantID: "tenant-1", ResourceID: "res-payroll", GroupID: "grp-finance", GroupName: "Finance", Priority: 10, Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "assign-legacy-gateway", PolicyID: "policy-legacy-gateway", Level: "legacy_gateway", TenantID: "tenant-1", Priority: 1, Enabled: true, CreatedAt: now, UpdatedAt: now},
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
