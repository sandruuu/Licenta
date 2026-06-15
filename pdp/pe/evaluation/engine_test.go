package evaluation

import (
	"testing"
	"time"

	"pdp/internal/testdb"
	"pdp/models"
	"pdp/store"
)

func TestPolicyMatchesAllowedProcessName(t *testing.T) {
	s := newTestStore(t)
	s.SaveUser(&models.User{ID: "user-1", Username: "alice", Email: "alice@example.test", Role: "user", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	s.SavePolicyRule(&models.PolicyRule{
		ID:      "rule-allow-putty",
		Name:    "Allow PuTTY SSH",
		Enabled: true,
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
		ID:      "rule-allow-mstsc",
		Name:    "Allow RDP from mstsc",
		Enabled: true,
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
		ID:      "rule-block-bad-hash",
		Name:    "Block untrusted binary",
		Enabled: true,
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
		ID:      "rule-allow-admin",
		Name:    "Allow Admin",
		Enabled: true,
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

func TestPolicyMatchesAllowedSCIMGroupFromContext(t *testing.T) {
	s := newTestStore(t)
	s.SavePolicyRule(&models.PolicyRule{
		ID:      "rule-allow-finance",
		Name:    "Allow Finance",
		Enabled: true,
		Conditions: models.RuleConditions{
			AllowedGroups: []string{"grp-finance"},
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
		Rules:             s.ListPolicyRules(),
		DirectoryGroupIDs: []string{"grp-finance"},
		Now:               businessHoursTime(),
	})

	if decision.Decision != "allow" || decision.MatchedRule != "rule-allow-finance" {
		t.Fatalf("Decision = %+v, want allow from SCIM group context", decision)
	}
}

func TestPolicyMatchesAllowedSCIMUserFromContext(t *testing.T) {
	s := newTestStore(t)
	s.SavePolicyRule(&models.PolicyRule{
		ID:      "rule-allow-directory-user",
		Name:    "Allow Directory User",
		Enabled: true,
		Conditions: models.RuleConditions{
			AllowedUsers: []string{"dir-user-1"},
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
		Rules:           s.ListPolicyRules(),
		DirectoryUserID: "dir-user-1",
		Now:             businessHoursTime(),
	})

	if decision.Decision != "allow" || decision.MatchedRule != "rule-allow-directory-user" {
		t.Fatalf("Decision = %+v, want allow from SCIM user context", decision)
	}
}

func TestPolicyRequiresConfiguredDeviceHealthSignals(t *testing.T) {
	s := newTestStore(t)
	s.SavePolicyRule(&models.PolicyRule{
		ID:      "rule-require-health",
		Name:    "Require health",
		Enabled: true,
		Conditions: models.RuleConditions{
			DevicePosture: models.DevicePosturePolicyConditions{
				RequiredChecks: []string{
					"firewall",
				},
				RequiredStatus: "good",
			},
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
		Rules: s.ListPolicyRules(),
		Now:   businessHoursTime(),
	})

	if decision.Decision != models.DecisionDeny || decision.MatchedRule != "rule-require-health" {
		t.Fatalf("Decision = %+v, want deny from failed device health requirement", decision)
	}
}

func TestPolicyEvaluationContinuesAfterNonMatchingPolicy(t *testing.T) {
	rules := []*models.PolicyRule{
		{
			ID:      "rule-other-user",
			Name:    "Other user needs MFA",
			Enabled: true,
			Conditions: models.RuleConditions{
				AllowedUsers: []string{"user-2"},
				Authentication: models.AuthenticationPolicyConditions{
					Policy:        models.AuthenticationPolicyEnforceMFA,
					StepUpMethods: []string{"totp"},
				},
			},
			Action: models.DecisionStepUpRequired,
		},
		{
			ID:      "rule-allow-user",
			Name:    "Allow user",
			Enabled: true,
			Conditions: models.RuleConditions{
				AllowedUsers: []string{"user-1"},
			},
			Action: models.DecisionAllow,
		},
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules: rules,
		Now:   businessHoursTime(),
	})

	if decision.Decision != models.DecisionAllow || decision.MatchedRule != "rule-allow-user" {
		t.Fatalf("Decision = %+v, want later matching allow policy to apply", decision)
	}
}

func TestPolicyEvaluationRequiresStepUpWhenAnyMatchingPolicyRequiresIt(t *testing.T) {
	rules := []*models.PolicyRule{
		{
			ID:      "rule-allow",
			Name:    "Allow baseline",
			Enabled: true,
			Action:  models.DecisionAllow,
		},
		{
			ID:      "rule-step-up",
			Name:    "Require MFA",
			Enabled: true,
			Conditions: models.RuleConditions{
				Authentication: models.AuthenticationPolicyConditions{
					Policy:        models.AuthenticationPolicyEnforceMFA,
					StepUpMethods: []string{"totp"},
				},
			},
			Action: models.DecisionStepUpRequired,
		},
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules:          rules,
		UserMFAEnabled: true,
		Now:            businessHoursTime(),
	})

	if decision.Decision != models.DecisionStepUpRequired || decision.MatchedRule != "rule-step-up" {
		t.Fatalf("Decision = %+v, want step-up to win over allow", decision)
	}
	if decision.StepUp == nil || !containsString(decision.StepUp.Methods, "totp") {
		t.Fatalf("StepUp = %+v, want combined step-up requirement with totp", decision.StepUp)
	}
}

func TestPolicyEvaluationDenyWinsAcrossMatchingPolicies(t *testing.T) {
	rules := []*models.PolicyRule{
		{
			ID:      "rule-allow",
			Name:    "Allow baseline",
			Enabled: true,
			Action:  models.DecisionAllow,
		},
		{
			ID:      "rule-deny",
			Name:    "Block sensitive resource",
			Enabled: true,
			Conditions: models.RuleConditions{
				TargetResources: []string{"res-admin"},
			},
			Action: models.DecisionDeny,
		},
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-admin",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules: rules,
		Now:   businessHoursTime(),
	})

	if decision.Decision != models.DecisionDeny || decision.MatchedRule != "rule-deny" {
		t.Fatalf("Decision = %+v, want deny policy to override allow", decision)
	}
}

func TestDeviceHealthFailureBlocksEvenWithLaterAllowPolicy(t *testing.T) {
	rules := []*models.PolicyRule{
		{
			ID:      "rule-require-health",
			Name:    "Require health",
			Enabled: true,
			Conditions: models.RuleConditions{
				DevicePosture: models.DevicePosturePolicyConditions{
					RequiredChecks: []string{"firewall"},
					RequiredStatus: "good",
				},
			},
			Action: models.DecisionAllow,
		},
		{
			ID:      "rule-allow",
			Name:    "Allow baseline",
			Enabled: true,
			Action:  models.DecisionAllow,
		},
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules: rules,
		Now:   businessHoursTime(),
	})

	if decision.Decision != models.DecisionDeny || decision.MatchedRule != "rule-require-health" {
		t.Fatalf("Decision = %+v, want failed device health policy to block access", decision)
	}
}

func TestPolicyReturnsStepUpRequiredWhenAuthContextIsNotFresh(t *testing.T) {
	s := newTestStore(t)
	s.SavePolicyRule(&models.PolicyRule{
		ID:      "rule-step-up",
		Name:    "Require step-up",
		Enabled: true,
		Conditions: models.RuleConditions{
			AllowedUsers: []string{"user-1"},
			Authentication: models.AuthenticationPolicyConditions{
				Policy:        models.AuthenticationPolicyEnforceMFA,
				StepUpMethods: []string{"totp"},
			},
		},
		Action:    models.DecisionStepUpRequired,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules: s.ListPolicyRules(),
		Now:   businessHoursTime(),
	})

	if decision.Decision != models.DecisionStepUpRequired || decision.StepUp == nil || decision.StepUp.RequiredACR != "urn:trustcloud:loa:2" {
		t.Fatalf("Decision = %+v, want step-up requirement", decision)
	}
}

func TestPolicyAllowsStepUpRuleWhenAuthContextIsFresh(t *testing.T) {
	s := newTestStore(t)
	s.SavePolicyRule(&models.PolicyRule{
		ID:      "rule-step-up",
		Name:    "Require step-up",
		Enabled: true,
		Conditions: models.RuleConditions{
			AllowedUsers: []string{"user-1"},
			Authentication: models.AuthenticationPolicyConditions{
				Policy:        models.AuthenticationPolicyEnforceMFA,
				StepUpMethods: []string{"totp"},
			},
		},
		Action:    models.DecisionStepUpRequired,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	now := businessHoursTime()

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Auth: models.AuthContext{
			ACR:              "urn:trustcloud:loa:2",
			AMR:              []string{"totp"},
			StepUpVerifiedAt: now.Add(-time.Minute),
			StepUpMethod:     "totp",
		},
		Rules: s.ListPolicyRules(),
		Now:   now,
	})

	if decision.Decision != models.DecisionAllow || decision.MatchedRule != "rule-step-up" {
		t.Fatalf("Decision = %+v, want allow from satisfied step-up", decision)
	}
}

func TestPolicyRequiresStepUpForNewLocationCondition(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-new-location",
		Name:    "MFA for new location",
		Enabled: true,
		Conditions: models.RuleConditions{
			AccessConditions: models.AccessConditions{
				Location: models.LocationAccessConditions{NewLocation: true},
			},
			Authentication: models.AuthenticationPolicyConditions{
				Policy:        models.AuthenticationPolicyEnforceMFA,
				StepUpMethods: []string{"totp"},
			},
		},
		Action: models.DecisionStepUpRequired,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules:         []*models.PolicyRule{rule},
		IsNewLocation: true,
		Now:           businessHoursTime(),
	})

	if decision.Decision != models.DecisionStepUpRequired || decision.MatchedRule != "rule-new-location" {
		t.Fatalf("Decision = %+v, want step-up from new location condition", decision)
	}
	if !decision.AccessConditions.Location.NewLocation {
		t.Fatalf("AccessConditions = %+v, want observed new location", decision.AccessConditions)
	}
}

func TestPolicyAccessConditionMustBeObserved(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-new-location-unobserved",
		Name:    "MFA for new location",
		Enabled: true,
		Conditions: models.RuleConditions{
			AccessConditions: models.AccessConditions{
				Location: models.LocationAccessConditions{NewLocation: true},
			},
		},
		Action: models.DecisionStepUpRequired,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules: []*models.PolicyRule{rule},
		Now:   businessHoursTime(),
	})

	if decision.MatchedRule == "rule-new-location-unobserved" || decision.Decision == models.DecisionStepUpRequired {
		t.Fatalf("Decision = %+v, want new-location rule not to match", decision)
	}
}

func TestPolicyAccessConditionCanMatchAnySelectedSignal(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-any-access-condition",
		Name:    "Any contextual risk",
		Enabled: true,
		Conditions: models.RuleConditions{
			AccessMatchMode: "any",
			AccessConditions: models.AccessConditions{
				Location:   models.LocationAccessConditions{ImpossibleTravel: true},
				Connection: models.ConnectionAccessConditions{SensitiveProtocol: true},
			},
			Authentication: models.AuthenticationPolicyConditions{
				Policy:        models.AuthenticationPolicyEnforceMFA,
				StepUpMethods: []string{"totp"},
			},
		},
		Action: models.DecisionStepUpRequired,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 22,
			Protocol:     "ssh",
		},
		Rules: []*models.PolicyRule{rule},
		Now:   businessHoursTime(),
	})

	if decision.Decision != models.DecisionStepUpRequired || decision.MatchedRule != "rule-any-access-condition" {
		t.Fatalf("Decision = %+v, want step-up when any selected access condition is observed", decision)
	}
}

func TestPolicyMatchesRiskLevelCondition(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-high-risk",
		Name:    "High risk needs passkey",
		Enabled: true,
		Conditions: models.RuleConditions{
			Risk: models.RiskPolicyConditions{Levels: []string{"high", "critical"}},
			Authentication: models.AuthenticationPolicyConditions{
				Policy:        models.AuthenticationPolicyEnforceMFA,
				StepUpMethods: []string{"webauthn"},
			},
		},
		Action: models.DecisionStepUpRequired,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 22,
			Protocol:     "ssh",
			DeviceHealth: &models.DeviceHealthReport{
				OverallScore: 10,
				ReportedAt:   time.Now().Add(-48 * time.Hour),
			},
			AnomalyScore: 20,
		},
		Rules:              []*models.PolicyRule{rule},
		FailedAttempts:     5,
		IsNewDevice:        true,
		IsNewLocation:      true,
		IsImpossibleTravel: true,
		Now:                businessHoursTime(),
	})

	if decision.Decision != models.DecisionStepUpRequired || decision.MatchedRule != "rule-high-risk" {
		t.Fatalf("Decision = %+v, want step-up from high risk condition", decision)
	}
	if decision.StepUp == nil || !containsString(decision.StepUp.Methods, "webauthn") {
		t.Fatalf("StepUp = %+v, want webauthn method", decision.StepUp)
	}
}

func TestPolicyMatchesSensitiveProtocolCondition(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-sensitive-protocol",
		Name:    "Passkey for SSH/RDP",
		Enabled: true,
		Conditions: models.RuleConditions{
			AccessConditions: models.AccessConditions{
				Connection: models.ConnectionAccessConditions{SensitiveProtocol: true},
			},
			Authentication: models.AuthenticationPolicyConditions{
				Policy:        models.AuthenticationPolicyEnforceMFA,
				StepUpMethods: []string{"webauthn"},
			},
		},
		Action: models.DecisionStepUpRequired,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-ssh",
			ResourcePort: 22,
			Protocol:     "ssh",
		},
		Rules: []*models.PolicyRule{rule},
		Now:   businessHoursTime(),
	})

	if decision.Decision != models.DecisionStepUpRequired || decision.MatchedRule != "rule-sensitive-protocol" {
		t.Fatalf("Decision = %+v, want step-up from sensitive protocol condition", decision)
	}
	if decision.StepUp == nil || !containsString(decision.StepUp.Methods, "webauthn") {
		t.Fatalf("StepUp = %+v, want webauthn method", decision.StepUp)
	}
}

func TestPolicyDecisionCarriesSessionControls(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-session-controls",
		Name:    "Short admin session",
		Enabled: true,
		Conditions: models.RuleConditions{
			Session: models.SessionPolicyControls{
				MaxAgeSeconds:          900,
				RevalidateEverySeconds: 120,
				RevokeOnPostureChange:  true,
				RevokeOnRiskIncrease:   true,
			},
		},
		Action: models.DecisionAllow,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-admin",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules: []*models.PolicyRule{rule},
		Now:   businessHoursTime(),
	})

	if decision.Decision != models.DecisionAllow || decision.MatchedRule != "rule-session-controls" {
		t.Fatalf("Decision = %+v, want allow from session control rule", decision)
	}
	if decision.SessionControls.MaxAgeSeconds != 900 || decision.SessionControls.RevalidateEverySeconds != 120 {
		t.Fatalf("SessionControls = %+v, want configured durations", decision.SessionControls)
	}
	if !decision.SessionControls.RevokeOnPostureChange || !decision.SessionControls.RevokeOnRiskIncrease {
		t.Fatalf("SessionControls = %+v, want revocation controls enabled", decision.SessionControls)
	}
}

func TestDuoStyleAuthorizedNetworkPolicyActions(t *testing.T) {
	tests := []struct {
		name           string
		sourceIP       string
		authPolicy     string
		newUserPolicy  string
		userMFAEnabled bool
		network        models.NetworkPolicyConditions
		want           string
	}{
		{
			name:           "skip MFA network bypasses enforced MFA",
			sourceIP:       "192.0.2.25",
			authPolicy:     models.AuthenticationPolicyEnforceMFA,
			userMFAEnabled: true,
			network: models.NetworkPolicyConditions{
				SkipMFACIDRs: []string{"192.0.2.0/24"},
			},
			want: models.DecisionAllow,
		},
		{
			name:           "require MFA network overrides authentication bypass",
			sourceIP:       "203.0.113.25",
			authPolicy:     models.AuthenticationPolicyBypassMFA,
			userMFAEnabled: true,
			network: models.NetworkPolicyConditions{
				RequireMFACIDRs: []string{"203.0.113.0/24"},
			},
			want: models.DecisionStepUpRequired,
		},
		{
			name:           "blocked network is most restrictive on overlap",
			sourceIP:       "198.51.100.25",
			authPolicy:     models.AuthenticationPolicyBypassMFA,
			userMFAEnabled: true,
			network: models.NetworkPolicyConditions{
				SkipMFACIDRs:    []string{"198.51.100.0/24"},
				RequireMFACIDRs: []string{"198.51.100.0/24"},
				BlockedCIDRs:    []string{"198.51.100.25"},
			},
			want: models.DecisionDeny,
		},
		{
			name:           "deny other networks blocks outside declared skip or require networks",
			sourceIP:       "198.51.100.25",
			authPolicy:     models.AuthenticationPolicyBypassMFA,
			userMFAEnabled: true,
			network: models.NetworkPolicyConditions{
				SkipMFACIDRs:      []string{"192.0.2.0/24"},
				DenyOtherNetworks: true,
			},
			want: models.DecisionDeny,
		},
		{
			name:           "allowed network is not blocked by deny other networks",
			sourceIP:       "192.0.2.25",
			authPolicy:     models.AuthenticationPolicyBypassMFA,
			userMFAEnabled: true,
			network: models.NetworkPolicyConditions{
				AllowedCIDRs:      []string{"192.0.2.0/24"},
				DenyOtherNetworks: true,
			},
			want: models.DecisionAllow,
		},
		{
			name:           "deny other networks blocks outside allowed networks",
			sourceIP:       "198.51.100.25",
			authPolicy:     models.AuthenticationPolicyBypassMFA,
			userMFAEnabled: true,
			network: models.NetworkPolicyConditions{
				AllowedCIDRs:      []string{"192.0.2.0/24"},
				DenyOtherNetworks: true,
			},
			want: models.DecisionDeny,
		},
		{
			name:           "allowed IP range is not blocked by deny other networks",
			sourceIP:       "198.51.100.15",
			authPolicy:     models.AuthenticationPolicyBypassMFA,
			userMFAEnabled: true,
			network: models.NetworkPolicyConditions{
				AllowedCIDRs:      []string{"198.51.100.10-198.51.100.20"},
				DenyOtherNetworks: true,
			},
			want: models.DecisionAllow,
		},
		{
			name:           "unenrolled user skips enrollment from skip MFA network by default",
			sourceIP:       "192.0.2.25",
			authPolicy:     models.AuthenticationPolicyEnforceMFA,
			newUserPolicy:  models.NewUserPolicyRequireEnrollment,
			userMFAEnabled: false,
			network: models.NetworkPolicyConditions{
				SkipMFACIDRs: []string{"192.0.2.0/24"},
			},
			want: models.DecisionAllow,
		},
		{
			name:           "skip MFA network can still require enrollment for new users",
			sourceIP:       "192.0.2.25",
			authPolicy:     models.AuthenticationPolicyEnforceMFA,
			newUserPolicy:  models.NewUserPolicyRequireEnrollment,
			userMFAEnabled: false,
			network: models.NetworkPolicyConditions{
				SkipMFACIDRs:                      []string{"192.0.2.0/24"},
				RequireEnrollmentFromSkipNetworks: true,
			},
			want: models.DecisionStepUpRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &models.PolicyRule{
				ID:      "rule-duo-network",
				Name:    "Duo-style authorized networks",
				Enabled: true,
				Conditions: models.RuleConditions{
					User: models.UserPolicyConditions{NewUserPolicy: tt.newUserPolicy},
					Authentication: models.AuthenticationPolicyConditions{
						Policy:        tt.authPolicy,
						StepUpMethods: []string{"totp"},
					},
					Network: tt.network,
				},
				Action: models.DecisionAllow,
			}

			decision := NewEngine().Evaluate(AccessContext{
				Request: models.AccessRequest{
					UserID:       "user-1",
					Username:     "alice",
					SourceIP:     tt.sourceIP,
					Resource:     "res-admin",
					ResourcePort: 443,
					Protocol:     "https",
				},
				Rules:          []*models.PolicyRule{rule},
				UserMFAEnabled: tt.userMFAEnabled,
				Now:            businessHoursTime(),
			})
			if decision.Decision != tt.want {
				t.Fatalf("Decision = %+v, want %s", decision, tt.want)
			}
		})
	}
}

func TestRiskBasedAuthenticationRequiresMFAForSelectedSignal(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-risk-auth",
		Name:    "Risk-based auth",
		Enabled: true,
		Conditions: models.RuleConditions{
			Authentication: models.AuthenticationPolicyConditions{
				Policy: models.AuthenticationPolicyBypassMFA,
			},
			RiskBasedAuth: models.RiskBasedAuthPolicyConditions{
				RequireMFAOnRisk: true,
				Signals:          []string{"new_location", "unrealistic_travel", "user_baseline_anomaly"},
				MatchMode:        "any",
			},
		},
		Action: models.DecisionAllow,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-admin",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules:                 []*models.PolicyRule{rule},
		UserMFAEnabled:        true,
		IsUserBaselineAnomaly: true,
		Now:                   businessHoursTime(),
	})

	if decision.Decision != models.DecisionStepUpRequired || decision.MatchedRule != "rule-risk-auth" {
		t.Fatalf("Decision = %+v, want step-up from risk-based authentication", decision)
	}
}

func TestRiskBasedAuthenticationDoesNotRequireMFAWithoutSelectedRisk(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-risk-auth",
		Name:    "Risk-based auth",
		Enabled: true,
		Conditions: models.RuleConditions{
			Authentication: models.AuthenticationPolicyConditions{
				Policy: models.AuthenticationPolicyBypassMFA,
			},
			RiskBasedAuth: models.RiskBasedAuthPolicyConditions{
				RequireMFAOnRisk: true,
				Signals:          []string{"user_baseline_anomaly"},
				MatchMode:        "any",
			},
		},
		Action: models.DecisionAllow,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-admin",
			ResourcePort: 443,
			Protocol:     "https",
		},
		Rules:          []*models.PolicyRule{rule},
		UserMFAEnabled: true,
		IsNewLocation:  true,
		Now:            businessHoursTime(),
	})

	if decision.Decision != models.DecisionAllow || decision.MatchedRule != "rule-risk-auth" {
		t.Fatalf("Decision = %+v, want allow without selected risk signal", decision)
	}
}

func TestDuoStyleNewUserAndAuthenticationPolicies(t *testing.T) {
	tests := []struct {
		name             string
		newUserPolicy    string
		authPolicy       string
		userMFAEnabled   bool
		want             string
		wantSatisfiedMFA bool
	}{
		{
			name:           "unenrolled user is prompted to enroll when MFA is enforced",
			newUserPolicy:  models.NewUserPolicyRequireEnrollment,
			authPolicy:     models.AuthenticationPolicyEnforceMFA,
			userMFAEnabled: false,
			want:           models.DecisionStepUpRequired,
		},
		{
			name:             "enrolled user follows enforced MFA policy",
			newUserPolicy:    models.NewUserPolicyRequireEnrollment,
			authPolicy:       models.AuthenticationPolicyEnforceMFA,
			userMFAEnabled:   true,
			want:             models.DecisionAllow,
			wantSatisfiedMFA: true,
		},
		{
			name:           "unenrolled user can bypass MFA when new user policy allows it",
			newUserPolicy:  models.NewUserPolicyAllowWithoutMFA,
			authPolicy:     models.AuthenticationPolicyEnforceMFA,
			userMFAEnabled: false,
			want:           models.DecisionAllow,
		},
		{
			name:           "unenrolled user is denied by new user policy",
			newUserPolicy:  models.NewUserPolicyDeny,
			authPolicy:     models.AuthenticationPolicyEnforceMFA,
			userMFAEnabled: false,
			want:           models.DecisionDeny,
		},
		{
			name:           "authentication bypass prevents inline enrollment",
			newUserPolicy:  models.NewUserPolicyRequireEnrollment,
			authPolicy:     models.AuthenticationPolicyBypassMFA,
			userMFAEnabled: false,
			want:           models.DecisionAllow,
		},
		{
			name:           "authentication deny blocks regardless of new user policy",
			newUserPolicy:  models.NewUserPolicyAllowWithoutMFA,
			authPolicy:     models.AuthenticationPolicyDeny,
			userMFAEnabled: false,
			want:           models.DecisionDeny,
		},
	}

	now := businessHoursTime()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &models.PolicyRule{
				ID:      "rule-duo-auth",
				Name:    "Duo-style auth",
				Enabled: true,
				Conditions: models.RuleConditions{
					User: models.UserPolicyConditions{
						NewUserPolicy: tt.newUserPolicy,
					},
					Authentication: models.AuthenticationPolicyConditions{
						Policy:        tt.authPolicy,
						StepUpMethods: []string{"totp"},
					},
				},
				Action: models.DecisionDeny,
			}
			ctx := AccessContext{
				Request: models.AccessRequest{
					UserID:       "user-1",
					Username:     "alice",
					Resource:     "res-admin",
					ResourcePort: 443,
					Protocol:     "https",
				},
				Rules:          []*models.PolicyRule{rule},
				UserMFAEnabled: tt.userMFAEnabled,
				Now:            now,
			}
			if tt.wantSatisfiedMFA {
				ctx.Auth = models.AuthContext{
					ACR:              "urn:trustcloud:loa:2",
					AMR:              []string{"totp"},
					StepUpVerifiedAt: now.Add(-time.Minute),
					StepUpMethod:     "totp",
				}
			}

			decision := NewEngine().Evaluate(ctx)
			if decision.Decision != tt.want {
				t.Fatalf("Decision = %+v, want %s", decision, tt.want)
			}
		})
	}
}

func TestDuoStyleUserLocationPolicyActions(t *testing.T) {
	tests := []struct {
		name        string
		countryCode string
		policy      models.UserLocationPolicyConditions
		authPolicy  string
		want        string
	}{
		{
			name:        "selected country can require MFA over authentication bypass",
			countryCode: "US",
			authPolicy:  models.AuthenticationPolicyBypassMFA,
			policy: models.UserLocationPolicyConditions{
				Rules: []models.UserLocationRule{
					{Countries: []string{"US"}, Action: models.UserLocationActionRequireMFA},
				},
				DefaultAction:         models.UserLocationActionAllow,
				UnknownLocationAction: models.UserLocationActionAllow,
				CheckMode:             "access_device_only",
			},
			want: models.DecisionStepUpRequired,
		},
		{
			name:        "all other countries can block access",
			countryCode: "DE",
			authPolicy:  models.AuthenticationPolicyBypassMFA,
			policy: models.UserLocationPolicyConditions{
				Rules: []models.UserLocationRule{
					{Countries: []string{"RO"}, Action: models.UserLocationActionAllow},
				},
				DefaultAction:         models.UserLocationActionBlock,
				UnknownLocationAction: models.UserLocationActionAllow,
				CheckMode:             "access_device_only",
			},
			want: models.DecisionDeny,
		},
		{
			name:        "selected country can skip enforced MFA",
			countryCode: "RO",
			authPolicy:  models.AuthenticationPolicyEnforceMFA,
			policy: models.UserLocationPolicyConditions{
				Rules: []models.UserLocationRule{
					{Countries: []string{"RO"}, Action: models.UserLocationActionSkipMFA},
				},
				DefaultAction:         models.UserLocationActionBlock,
				UnknownLocationAction: models.UserLocationActionAllow,
				CheckMode:             "access_device_only",
			},
			want: models.DecisionAllow,
		},
		{
			name:       "unknown locations use unknown action",
			authPolicy: models.AuthenticationPolicyBypassMFA,
			policy: models.UserLocationPolicyConditions{
				DefaultAction:         models.UserLocationActionAllow,
				UnknownLocationAction: models.UserLocationActionBlock,
				CheckMode:             "access_device_only",
			},
			want: models.DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &models.PolicyRule{
				ID:      "rule-user-location",
				Name:    "Duo-style location",
				Enabled: true,
				Conditions: models.RuleConditions{
					Authentication: models.AuthenticationPolicyConditions{
						Policy:        tt.authPolicy,
						StepUpMethods: []string{"totp"},
					},
					UserLocation: tt.policy,
				},
				Action: models.DecisionAllow,
			}
			ctx := AccessContext{
				Request: models.AccessRequest{
					UserID:       "user-1",
					Username:     "alice",
					Resource:     "res-admin",
					ResourcePort: 443,
					Protocol:     "https",
				},
				Rules:               []*models.PolicyRule{rule},
				UserMFAEnabled:      true,
				SourceCountryCode:   tt.countryCode,
				SourceLocationKnown: tt.countryCode != "",
				Now:                 businessHoursTime(),
			}

			decision := NewEngine().Evaluate(ctx)
			if decision.Decision != tt.want {
				t.Fatalf("Decision = %+v, want %s", decision, tt.want)
			}
		})
	}
}

func TestPolicyMatchesNestedDevicePostureHealth(t *testing.T) {
	rule := &models.PolicyRule{
		ID:      "rule-nested-device-posture",
		Name:    "Require healthy device",
		Enabled: true,
		Conditions: models.RuleConditions{
			DevicePosture: models.DevicePosturePolicyConditions{
				RequiredChecks: []string{"Firewall"},
				RequiredStatus: "good",
			},
		},
		Action: models.DecisionAllow,
	}

	decision := NewEngine().Evaluate(AccessContext{
		Request: models.AccessRequest{
			UserID:       "user-1",
			Username:     "alice",
			Resource:     "res-web",
			ResourcePort: 443,
			Protocol:     "https",
			DeviceHealth: &models.DeviceHealthReport{
				OverallScore: 90,
				Checks: []models.HealthCheck{
					{Name: "Firewall", Status: "good"},
				},
			},
		},
		Rules: []*models.PolicyRule{rule},
		Now:   businessHoursTime(),
	})
	if decision.Decision != models.DecisionAllow || decision.MatchedRule != "rule-nested-device-posture" {
		t.Fatalf("Decision = %+v, want allow from nested device posture conditions", decision)
	}
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	return testdb.NewStore(t)
}

func businessHoursTime() time.Time {
	return time.Date(2026, time.May, 8, 10, 0, 0, 0, time.UTC)
}
