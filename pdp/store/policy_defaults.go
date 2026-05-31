package store

import (
	"strings"
	"time"

	"pdp/models"
)

const (
	defaultGlobalPolicyPrefix     = "policy-global-default-"
	defaultGlobalAssignmentPrefix = "assignment-global-default-"
	defaultGlobalOrderIndex       = 1000000
)

func DefaultGlobalPolicyID(tenantID string) string {
	return defaultGlobalPolicyPrefix + strings.TrimSpace(tenantID)
}

func DefaultGlobalAssignmentID(tenantID string) string {
	return defaultGlobalAssignmentPrefix + strings.TrimSpace(tenantID)
}

func IsDefaultGlobalPolicyID(policyID string) bool {
	return strings.HasPrefix(strings.TrimSpace(policyID), defaultGlobalPolicyPrefix)
}

func IsDefaultGlobalAssignmentID(assignmentID string) bool {
	return strings.HasPrefix(strings.TrimSpace(assignmentID), defaultGlobalAssignmentPrefix)
}

func DefaultGlobalPolicyRule(tenantID string, now time.Time) *models.PolicyRule {
	tenantID = strings.TrimSpace(tenantID)
	return &models.PolicyRule{
		ID:          DefaultGlobalPolicyID(tenantID),
		Name:        "Global Policy",
		Description: "Default baseline policy automatically applied to this organization.",
		Enabled:     true,
		Action:      models.DecisionStepUpRequired,
		Conditions: models.RuleConditions{
			User: models.UserPolicyConditions{
				NewUserPolicy: models.NewUserPolicyRequireEnrollment,
			},
			Authentication: models.AuthenticationPolicyConditions{
				Policy:        models.AuthenticationPolicyEnforceMFA,
				StepUpMethods: []string{"totp", "webauthn"},
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func DefaultGlobalPolicyAssignment(tenantID string, now time.Time) *models.PolicyAssignment {
	tenantID = strings.TrimSpace(tenantID)
	return &models.PolicyAssignment{
		ID:         DefaultGlobalAssignmentID(tenantID),
		PolicyID:   DefaultGlobalPolicyID(tenantID),
		TenantID:   tenantID,
		Level:      "organization",
		OrderIndex: defaultGlobalOrderIndex,
		Enabled:    true,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

func (s *Store) EnsureDefaultGlobalPolicyForTenant(tenantID string) (*models.PolicyRule, *models.PolicyAssignment) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	now := time.Now()

	policyID := DefaultGlobalPolicyID(tenantID)
	rule, found := s.GetPolicyRule(policyID)
	if !found || rule == nil {
		rule = DefaultGlobalPolicyRule(tenantID, now)
		s.SavePolicyRule(rule)
	}

	assignmentID := DefaultGlobalAssignmentID(tenantID)
	assignment, found := s.GetPolicyAssignment(assignmentID)
	if !found || assignment == nil {
		assignment = DefaultGlobalPolicyAssignment(tenantID, now)
		s.SavePolicyAssignment(assignment)
	} else if assignment.PolicyID != policyID ||
		assignment.TenantID != tenantID ||
		assignment.Level != "organization" ||
		assignment.OrderIndex != defaultGlobalOrderIndex ||
		!assignment.Enabled {
		createdAt := assignment.CreatedAt
		if createdAt.IsZero() {
			createdAt = now
		}
		assignment = DefaultGlobalPolicyAssignment(tenantID, now)
		assignment.CreatedAt = createdAt
		s.SavePolicyAssignment(assignment)
	}

	return rule, assignment
}

func (s *Store) EnsureDefaultGlobalPoliciesForTenants() {
	for _, tenant := range s.ListTenants() {
		if tenant == nil || strings.TrimSpace(tenant.ID) == "" {
			continue
		}
		s.EnsureDefaultGlobalPolicyForTenant(tenant.ID)
	}
}
