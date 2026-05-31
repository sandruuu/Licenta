package transport

import (
	"testing"

	"pdp/models"
)

func TestValidateRiskBasedAuthenticationPolicyAllowsImplicitSignals(t *testing.T) {
	errMsg := validateRiskBasedAuthenticationPolicy(models.RiskBasedAuthPolicyConditions{
		RequireMFAOnRisk: true,
	})
	if errMsg != "" {
		t.Fatalf("validateRiskBasedAuthenticationPolicy() = %q, want no error", errMsg)
	}
}

func TestValidateRiskBasedAuthenticationPolicyRejectsUnknownSignal(t *testing.T) {
	errMsg := validateRiskBasedAuthenticationPolicy(models.RiskBasedAuthPolicyConditions{
		RequireMFAOnRisk: true,
		Signals:          []string{"unknown_signal"},
	})
	if errMsg == "" {
		t.Fatal("validateRiskBasedAuthenticationPolicy() accepted an unknown signal")
	}
}

func TestValidatePolicyConditionsAllowsNetworkAllowlistRanges(t *testing.T) {
	errMsg := validatePolicyConditions(models.DecisionAllow, models.RuleConditions{
		Authentication: models.AuthenticationPolicyConditions{
			Policy: models.AuthenticationPolicyBypassMFA,
		},
		Network: models.NetworkPolicyConditions{
			AllowedCIDRs:      []string{"192.0.2.10", "192.0.2.0/24", "198.51.100.10-198.51.100.20"},
			DenyOtherNetworks: true,
		},
	})
	if errMsg != "" {
		t.Fatalf("validatePolicyConditions() = %q, want no error", errMsg)
	}
}

func TestFilterPolicyRulesByOrganizationKeepsUnassignedPolicies(t *testing.T) {
	rules := []*models.PolicyRule{
		{ID: "policy-unassigned"},
		{
			ID: "policy-allowed",
			Assignments: []*models.PolicyAssignment{
				{ID: "assignment-allowed", TenantID: "org-1"},
				{ID: "assignment-denied", TenantID: "org-2"},
			},
		},
		{
			ID: "policy-denied",
			Assignments: []*models.PolicyAssignment{
				{ID: "assignment-other-org", TenantID: "org-2"},
			},
		},
	}

	filtered := filterPolicyRulesByOrganization(rules, map[string]bool{"org-1": true})
	if len(filtered) != 2 {
		t.Fatalf("len(filtered) = %d, want 2", len(filtered))
	}
	if filtered[0].ID != "policy-unassigned" {
		t.Fatalf("filtered[0].ID = %q, want policy-unassigned", filtered[0].ID)
	}
	if filtered[0].AssignmentCount != 0 || len(filtered[0].Assignments) != 0 {
		t.Fatalf("unassigned policy assignment state = count %d len %d, want 0/0", filtered[0].AssignmentCount, len(filtered[0].Assignments))
	}
	if filtered[1].ID != "policy-allowed" {
		t.Fatalf("filtered[1].ID = %q, want policy-allowed", filtered[1].ID)
	}
	if filtered[1].AssignmentCount != 1 || len(filtered[1].Assignments) != 1 || filtered[1].Assignments[0].ID != "assignment-allowed" {
		t.Fatalf("allowed policy assignments = %+v count %d, want only assignment-allowed", filtered[1].Assignments, filtered[1].AssignmentCount)
	}
}
