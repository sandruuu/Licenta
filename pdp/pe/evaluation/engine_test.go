package evaluation

import (
	"testing"
	"time"

	"pdp/models"
	"pdp/store"
)

func TestPolicyMatchesAllowedProcessName(t *testing.T) {
	s := newTestStore(t)
	s.SaveUser(&models.User{ID: "user-1", Username: "alice", Email: "alice@example.test", Role: "user", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	s.SavePolicyRule(&models.PolicyRule{
		ID:       "rule-allow-putty",
		Name:     "Allow PuTTY SSH",
		Priority: 1,
		Enabled:  true,
		Conditions: models.RuleConditions{
			AllowedUsers:        []string{"user-1"},
			TargetPorts:         []int{22},
			AllowedProcessNames: []string{"putty.exe"},
		},
		Action:    "allow",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			SourceIP:     "192.0.2.10",
			Resource:     "10.0.0.22",
			ResourcePort: 22,
			Protocol:     "ssh",
			Process: &models.ProcessIdentity{
				Name: "PuTTY.EXE",
				Path: `C:\Program Files\PuTTY\putty.exe`,
			},
		},
		Rules:    s.ListPolicyRules(),
		UserRole: "user",
		Now:      businessHoursTime(),
	})

	if decision.Decision != "allow" {
		t.Fatalf("Decision = %q, want allow (reason=%s)", decision.Decision, decision.Reason)
	}
	if decision.MatchedRule != "rule-allow-putty" {
		t.Fatalf("MatchedRule = %q, want rule-allow-putty", decision.MatchedRule)
	}
}

func TestPolicyRequiresProcessIdentityWhenConfigured(t *testing.T) {
	s := newTestStore(t)
	s.SaveUser(&models.User{ID: "user-1", Username: "alice", Email: "alice@example.test", Role: "user", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	s.SavePolicyRule(&models.PolicyRule{
		ID:       "rule-allow-mstsc",
		Name:     "Allow RDP from mstsc",
		Priority: 1,
		Enabled:  true,
		Conditions: models.RuleConditions{
			AllowedUsers:           []string{"user-1"},
			TargetPorts:            []int{3389},
			RequireProcessIdentity: true,
			AllowedProcessNames:    []string{"mstsc.exe"},
		},
		Action:    "allow",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			SourceIP:     "192.0.2.10",
			Resource:     "10.0.0.20",
			ResourcePort: 3389,
			Protocol:     "rdp",
		},
		Rules:    s.ListPolicyRules(),
		UserRole: "user",
		Now:      businessHoursTime(),
	})

	if decision.MatchedRule == "rule-allow-mstsc" || decision.Decision == "allow" {
		t.Fatalf("Decision = %+v, want rule not to match without process identity", decision)
	}
}

func TestPolicyBlocksProcessHash(t *testing.T) {
	s := newTestStore(t)
	s.SavePolicyRule(&models.PolicyRule{
		ID:       "rule-block-bad-hash",
		Name:     "Block untrusted binary",
		Priority: 1,
		Enabled:  true,
		Conditions: models.RuleConditions{
			TargetPorts:          []int{443},
			BlockedProcessHashes: []string{"DEADBEEF"},
		},
		Action:    "deny",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			SourceIP:     "192.0.2.10",
			Resource:     "10.0.0.443",
			ResourcePort: 443,
			Protocol:     "https",
			Process: &models.ProcessIdentity{
				Name:   "browser.exe",
				SHA256: "deadbeef",
			},
		},
		Rules: s.ListPolicyRules(),
		Now:   businessHoursTime(),
	})

	if decision.Decision != "deny" || decision.MatchedRule != "rule-block-bad-hash" {
		t.Fatalf("Decision = %+v, want deny from blocked hash rule", decision)
	}
}

func TestPolicyMatchesAllowedRoleFromContext(t *testing.T) {
	s := newTestStore(t)
	s.SavePolicyRule(&models.PolicyRule{
		ID:       "rule-allow-admin",
		Name:     "Allow Admin",
		Priority: 1,
		Enabled:  true,
		Conditions: models.RuleConditions{
			AllowedRoles: []string{"admin"},
		},
		Action:    "allow",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			SourceIP:     "192.0.2.10",
			Resource:     "10.0.0.10",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules:    s.ListPolicyRules(),
		UserRole: "admin",
		Now:      businessHoursTime(),
	})

	if decision.Decision != "allow" || decision.MatchedRule != "rule-allow-admin" {
		t.Fatalf("Decision = %+v, want allow from admin role context", decision)
	}
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s := store.New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func businessHoursTime() time.Time {
	return time.Date(2026, time.May, 8, 10, 0, 0, 0, time.UTC)
}
