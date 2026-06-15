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

func DefaultGlobalPolicyID(organizationID string) string {
	return defaultGlobalPolicyPrefix + strings.TrimSpace(organizationID)
}

func DefaultGlobalAssignmentID(organizationID string) string {
	return defaultGlobalAssignmentPrefix + strings.TrimSpace(organizationID)
}

func IsDefaultGlobalPolicyID(policyID string) bool {
	return strings.HasPrefix(strings.TrimSpace(policyID), defaultGlobalPolicyPrefix)
}

func IsDefaultGlobalAssignmentID(assignmentID string) bool {
	return strings.HasPrefix(strings.TrimSpace(assignmentID), defaultGlobalAssignmentPrefix)
}

func DefaultGlobalPolicyRule(organizationID string, now time.Time) *models.PolicyRule {
	organizationID = strings.TrimSpace(organizationID)
	return &models.PolicyRule{
		ID:          DefaultGlobalPolicyID(organizationID),
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

func DefaultGlobalPolicyAssignment(organizationID string, now time.Time) *models.PolicyAssignment {
	organizationID = strings.TrimSpace(organizationID)
	return &models.PolicyAssignment{
		ID:             DefaultGlobalAssignmentID(organizationID),
		PolicyID:       DefaultGlobalPolicyID(organizationID),
		OrganizationID: organizationID,
		Level:          "organization",
		OrderIndex:     defaultGlobalOrderIndex,
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func (s *Store) EnsureDefaultGlobalPolicyForOrganization(organizationID string) (*models.PolicyRule, *models.PolicyAssignment) {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil, nil
	}
	now := time.Now()

	policyID := DefaultGlobalPolicyID(organizationID)
	rule, found := s.GetPolicyRule(policyID)
	if !found || rule == nil {
		rule = DefaultGlobalPolicyRule(organizationID, now)
		s.SavePolicyRule(rule)
	}

	assignmentID := DefaultGlobalAssignmentID(organizationID)
	assignment, found := s.GetPolicyAssignment(assignmentID)
	if !found || assignment == nil {
		assignment = DefaultGlobalPolicyAssignment(organizationID, now)
		s.SavePolicyAssignment(assignment)
	} else if assignment.PolicyID != policyID ||
		assignment.OrganizationID != organizationID ||
		assignment.Level != "organization" ||
		assignment.OrderIndex != defaultGlobalOrderIndex ||
		!assignment.Enabled {
		createdAt := assignment.CreatedAt
		if createdAt.IsZero() {
			createdAt = now
		}
		assignment = DefaultGlobalPolicyAssignment(organizationID, now)
		assignment.CreatedAt = createdAt
		s.SavePolicyAssignment(assignment)
	}

	return rule, assignment
}

func (s *Store) EnsureDefaultGlobalPoliciesForOrganizations() {
	for _, organization := range s.ListOrganizations() {
		if organization == nil || strings.TrimSpace(organization.ID) == "" {
			continue
		}
		s.EnsureDefaultGlobalPolicyForOrganization(organization.ID)
	}
}
