package store

import (
	"database/sql"
	"log"
	"strings"

	"pdp/models"
)

// ─────────────────────────────────────────────
// Policy Rule operations
// ─────────────────────────────────────────────

func (s *Store) GetPolicyRule(id string) (*models.PolicyRule, bool) {
	row := s.db.QueryRow(`SELECT id, name, description, enabled, conditions_json,
		action, created_at, updated_at FROM policy_rules WHERE id = ?`, id)

	r := &models.PolicyRule{}
	var enabled int
	var condJSON, createdAt, updatedAt string

	err := row.Scan(&r.ID, &r.Name, &r.Description, &enabled, &condJSON,
		&r.Action, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}

	r.Enabled = i2b(enabled)
	r.Conditions = fromJSON[models.RuleConditions](condJSON)
	r.CreatedAt = parseTime(createdAt)
	r.UpdatedAt = parseTime(updatedAt)
	return r, true
}

func (s *Store) SavePolicyRule(rule *models.PolicyRule) {
	_, err := s.db.Exec(`INSERT INTO policy_rules
		(id, name, description, enabled, conditions_json, action, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			enabled = EXCLUDED.enabled,
			conditions_json = EXCLUDED.conditions_json,
			action = EXCLUDED.action,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
		rule.ID, rule.Name, rule.Description, b2i(rule.Enabled),
		toJSON(rule.Conditions), rule.Action, fmtTime(rule.CreatedAt), fmtTime(rule.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save policy rule %s: %v", rule.ID, err)
	}
}

func (s *Store) ListPolicyRules() []*models.PolicyRule {
	rows, err := s.db.Query(`SELECT id, name, description, enabled, conditions_json,
		action, created_at, updated_at FROM policy_rules ORDER BY created_at ASC, id ASC`)
	if err != nil {
		log.Printf("[STORE] Failed to list policy rules: %v", err)
		return nil
	}
	defer rows.Close()
	rules := scanPolicyRules(rows)
	s.decoratePolicyRulesWithAssignments(rules)
	return rules
}

func (s *Store) ListPolicyRulesForAccessGroups(organizationID, resourceID string, groupIDs, groupNames []string) []*models.PolicyRule {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil
	}
	rows, err := s.db.Query(`SELECT
		pa.id, pa.policy_id, pa.level, pa.organization_id, pa.resource_id,
		pa.group_id, pa.group_name, pa.order_index, pa.enabled, pa.created_at, pa.updated_at,
		pr.id, pr.name, pr.description, pr.enabled, pr.conditions_json,
		pr.action, pr.created_at, pr.updated_at
		FROM policy_assignments pa
		JOIN policy_rules pr ON pr.id = pa.policy_id
		WHERE pa.enabled = 1
		  AND pr.enabled = 1
		  AND pa.organization_id = ?
		  AND COALESCE(NULLIF(pa.level, ''), 'organization') IN ('organization', 'group', 'resource', 'resource_group')
		ORDER BY
		  CASE COALESCE(NULLIF(pa.level, ''), 'organization')
			WHEN 'resource_group' THEN 1
			WHEN 'resource' THEN 2
			WHEN 'group' THEN 3
			WHEN 'organization' THEN 4
			ELSE 5
		  END,
		  pa.order_index ASC, pa.created_at ASC, pa.id ASC`, organizationID)
	if err != nil {
		log.Printf("[STORE] Failed to list policy rules for access: %v", err)
		return nil
	}
	defer rows.Close()

	rules := make([]*models.PolicyRule, 0)
	for rows.Next() {
		assignment, rule, ok := scanPolicyRuleAssignmentRow(rows)
		if !ok || !policyAssignmentApplies(assignment, resourceID, groupIDs, groupNames) {
			continue
		}
		rules = append(rules, materializePolicyRuleAssignment(rule, assignment))
	}
	return rules
}

func scanPolicyRuleAssignmentRow(rows *sql.Rows) (*models.PolicyAssignment, *models.PolicyRule, bool) {
	assignment := &models.PolicyAssignment{}
	rule := &models.PolicyRule{}
	var assignmentEnabled, ruleEnabled int
	var assignmentCreatedAt, assignmentUpdatedAt string
	var ruleConditionsJSON, ruleCreatedAt, ruleUpdatedAt string
	if err := rows.Scan(
		&assignment.ID, &assignment.PolicyID, &assignment.Level, &assignment.OrganizationID, &assignment.ResourceID,
		&assignment.GroupID, &assignment.GroupName, &assignment.OrderIndex, &assignmentEnabled, &assignmentCreatedAt, &assignmentUpdatedAt,
		&rule.ID, &rule.Name, &rule.Description, &ruleEnabled, &ruleConditionsJSON,
		&rule.Action, &ruleCreatedAt, &ruleUpdatedAt,
	); err != nil {
		return nil, nil, false
	}
	assignment.Enabled = i2b(assignmentEnabled)
	normalizePolicyAssignment(assignment)
	assignment.CreatedAt = parseTime(assignmentCreatedAt)
	assignment.UpdatedAt = parseTime(assignmentUpdatedAt)

	rule.Enabled = i2b(ruleEnabled)
	rule.Conditions = fromJSON[models.RuleConditions](ruleConditionsJSON)
	rule.CreatedAt = parseTime(ruleCreatedAt)
	rule.UpdatedAt = parseTime(ruleUpdatedAt)
	return assignment, rule, true
}

func scanPolicyRules(rows *sql.Rows) []*models.PolicyRule {
	var rules []*models.PolicyRule
	for rows.Next() {
		r := &models.PolicyRule{}
		var enabled int
		var condJSON, createdAt, updatedAt string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &enabled, &condJSON,
			&r.Action, &createdAt, &updatedAt); err != nil {
			continue
		}
		r.Enabled = i2b(enabled)
		r.Conditions = fromJSON[models.RuleConditions](condJSON)
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		rules = append(rules, r)
	}
	return rules
}

func (s *Store) DeletePolicyRule(id string) {
	s.DeletePolicyAssignmentsForPolicy(id)
	s.db.Exec("DELETE FROM policy_rules WHERE id = ?", id)
}

func (s *Store) normalizePolicyRuleConditions() error {
	if s == nil || s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, conditions_json FROM policy_rules`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type normalizedRule struct {
		id         string
		conditions string
	}
	var updates []normalizedRule
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		normalized := toJSON(fromJSON[models.RuleConditions](raw))
		if normalized != raw {
			updates = append(updates, normalizedRule{id: id, conditions: normalized})
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, update := range updates {
		if _, err := s.db.Exec(`UPDATE policy_rules SET conditions_json = ? WHERE id = ?`, update.conditions, update.id); err != nil {
			return err
		}
	}
	if len(updates) > 0 {
		log.Printf("[STORE] Normalized %d policy rule condition payload(s)", len(updates))
	}
	return nil
}

func (s *Store) GetPolicyAssignment(id string) (*models.PolicyAssignment, bool) {
	row := s.db.QueryRow(`SELECT id, policy_id, level, organization_id, resource_id,
		group_id, group_name, order_index, enabled, created_at, updated_at FROM policy_assignments
		WHERE id = ?
		  AND COALESCE(NULLIF(level, ''), 'organization') IN ('organization', 'group', 'resource', 'resource_group')`, id)

	assignment := &models.PolicyAssignment{}
	var enabled int
	var createdAt, updatedAt string
	if err := row.Scan(&assignment.ID, &assignment.PolicyID, &assignment.Level, &assignment.OrganizationID,
		&assignment.ResourceID, &assignment.GroupID, &assignment.GroupName,
		&assignment.OrderIndex, &enabled, &createdAt, &updatedAt); err != nil {
		return nil, false
	}
	assignment.Enabled = i2b(enabled)
	normalizePolicyAssignment(assignment)
	assignment.CreatedAt = parseTime(createdAt)
	assignment.UpdatedAt = parseTime(updatedAt)
	return assignment, true
}

func (s *Store) SavePolicyAssignment(assignment *models.PolicyAssignment) {
	if assignment == nil {
		return
	}
	normalizePolicyAssignment(assignment)
	_, err := s.db.Exec(`INSERT INTO policy_assignments
		(id, policy_id, level, organization_id, resource_id, group_id, group_name,
		 order_index, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			policy_id = EXCLUDED.policy_id,
			level = EXCLUDED.level,
			organization_id = EXCLUDED.organization_id,
			resource_id = EXCLUDED.resource_id,
			group_id = EXCLUDED.group_id,
			group_name = EXCLUDED.group_name,
			order_index = EXCLUDED.order_index,
			enabled = EXCLUDED.enabled,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at`,
		assignment.ID, assignment.PolicyID, assignment.Level, assignment.OrganizationID,
		assignment.ResourceID, assignment.GroupID, assignment.GroupName,
		assignment.OrderIndex,
		b2i(assignment.Enabled), fmtTime(assignment.CreatedAt), fmtTime(assignment.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save policy assignment %s: %v", assignment.ID, err)
	}
}

func (s *Store) SavePolicyAssignmentWithPlacement(assignment *models.PolicyAssignment, placement string) []*models.PolicyAssignment {
	if assignment == nil {
		return nil
	}
	normalizePolicyAssignment(assignment)
	placement = normalizedAssignmentOrderPlacement(placement)
	if placement == "" {
		s.SavePolicyAssignment(assignment)
		return nil
	}

	scopeAssignments := s.listPolicyAssignmentsForOrderScope(assignment)
	if placement == "replace" {
		deleted := make([]*models.PolicyAssignment, 0, len(scopeAssignments))
		for _, existing := range scopeAssignments {
			if existing == nil || strings.EqualFold(existing.ID, assignment.ID) {
				continue
			}
			if IsDefaultGlobalAssignmentID(existing.ID) {
				continue
			}
			if s.DeletePolicyAssignment(existing.ID) {
				deleted = append(deleted, existing)
			}
		}
		assignment.OrderIndex = 0
		s.SavePolicyAssignment(assignment)
		return deleted
	}

	assignment.OrderIndex = nextAssignmentOrderIndex(scopeAssignments, assignment.ID, placement)
	s.SavePolicyAssignment(assignment)
	return nil
}

func (s *Store) ListPolicyAssignments() []*models.PolicyAssignment {
	rows, err := s.db.Query(`SELECT id, policy_id, level, organization_id, resource_id,
		group_id, group_name, order_index, enabled, created_at, updated_at FROM policy_assignments
		WHERE COALESCE(NULLIF(level, ''), 'organization') IN ('organization', 'group', 'resource', 'resource_group')
		ORDER BY organization_id ASC,
		  CASE COALESCE(NULLIF(level, ''), 'organization')
			WHEN 'resource_group' THEN 1
			WHEN 'resource' THEN 2
			WHEN 'group' THEN 3
			WHEN 'organization' THEN 4
			ELSE 5
		  END,
		  order_index ASC, created_at ASC, id ASC`)
	if err != nil {
		log.Printf("[STORE] Failed to list policy assignments: %v", err)
		return nil
	}
	defer rows.Close()
	return scanPolicyAssignments(rows)
}

func (s *Store) ListPolicyAssignmentsForPolicy(policyID string) []*models.PolicyAssignment {
	rows, err := s.db.Query(`SELECT id, policy_id, level, organization_id, resource_id,
		group_id, group_name, order_index, enabled, created_at, updated_at FROM policy_assignments
		WHERE policy_id = ?
		  AND COALESCE(NULLIF(level, ''), 'organization') IN ('organization', 'group', 'resource', 'resource_group')
		ORDER BY
		  CASE COALESCE(NULLIF(level, ''), 'organization')
			WHEN 'resource_group' THEN 1
			WHEN 'resource' THEN 2
			WHEN 'group' THEN 3
			WHEN 'organization' THEN 4
			ELSE 5
		  END,
		  order_index ASC, created_at ASC, id ASC`, policyID)
	if err != nil {
		log.Printf("[STORE] Failed to list policy assignments for policy %s: %v", policyID, err)
		return nil
	}
	defer rows.Close()
	return scanPolicyAssignments(rows)
}

func (s *Store) ListPolicyAssignmentsForAccessGroups(organizationID, resourceID string, groupIDs, groupNames []string) []*models.PolicyAssignment {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, policy_id, level, organization_id, resource_id,
		group_id, group_name, order_index, enabled, created_at, updated_at FROM policy_assignments
		WHERE enabled = 1
		  AND organization_id = ?
		  AND COALESCE(NULLIF(level, ''), 'organization') IN ('organization', 'group', 'resource', 'resource_group')
		ORDER BY
		  CASE COALESCE(NULLIF(level, ''), 'organization')
			WHEN 'resource_group' THEN 1
			WHEN 'resource' THEN 2
			WHEN 'group' THEN 3
			WHEN 'organization' THEN 4
			ELSE 5
		  END,
		  order_index ASC, created_at ASC, id ASC`, organizationID)
	if err != nil {
		log.Printf("[STORE] Failed to list policy assignments for access: %v", err)
		return nil
	}
	defer rows.Close()
	assignments := scanPolicyAssignments(rows)
	applicable := make([]*models.PolicyAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		if policyAssignmentApplies(assignment, resourceID, groupIDs, groupNames) {
			applicable = append(applicable, assignment)
		}
	}
	return applicable
}

func (s *Store) DeletePolicyAssignment(id string) bool {
	res, err := s.db.Exec("DELETE FROM policy_assignments WHERE id = ?", id)
	if err != nil {
		log.Printf("[STORE] Failed to delete policy assignment %s: %v", id, err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) DeletePolicyAssignmentsForPolicy(policyID string) {
	s.db.Exec("DELETE FROM policy_assignments WHERE policy_id = ?", policyID)
}

func scanPolicyAssignments(rows *sql.Rows) []*models.PolicyAssignment {
	assignments := []*models.PolicyAssignment{}
	for rows.Next() {
		assignment := &models.PolicyAssignment{}
		var enabled int
		var createdAt, updatedAt string
		if err := rows.Scan(&assignment.ID, &assignment.PolicyID, &assignment.Level, &assignment.OrganizationID,
			&assignment.ResourceID, &assignment.GroupID, &assignment.GroupName,
			&assignment.OrderIndex, &enabled, &createdAt, &updatedAt); err != nil {
			continue
		}
		assignment.Enabled = i2b(enabled)
		normalizePolicyAssignment(assignment)
		assignment.CreatedAt = parseTime(createdAt)
		assignment.UpdatedAt = parseTime(updatedAt)
		assignments = append(assignments, assignment)
	}
	return assignments
}

func (s *Store) decoratePolicyRulesWithAssignments(rules []*models.PolicyRule) {
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		assignments := s.ListPolicyAssignmentsForPolicy(rule.ID)
		rule.Assignments = assignments
		rule.AssignmentCount = len(assignments)
	}
}

func materializePolicyRuleAssignment(rule *models.PolicyRule, assignment *models.PolicyAssignment) *models.PolicyRule {
	if rule == nil || assignment == nil {
		return rule
	}
	copyRule := *rule
	copyAssignment := *assignment
	copyRule.Assignments = []*models.PolicyAssignment{&copyAssignment}
	copyRule.AssignmentCount = 1
	return &copyRule
}

func normalizePolicyAssignment(assignment *models.PolicyAssignment) {
	if assignment == nil {
		return
	}
	assignment.OrganizationID = strings.TrimSpace(assignment.OrganizationID)
	assignment.ResourceID = strings.TrimSpace(assignment.ResourceID)
	assignment.GroupID = strings.TrimSpace(assignment.GroupID)
	assignment.GroupName = strings.TrimSpace(assignment.GroupName)
	assignment.Level = normalizedAssignmentLevel(assignment)
}

func normalizedAssignmentOrderPlacement(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "top", "before":
		return "top"
	case "bottom", "after":
		return "bottom"
	case "replace":
		return "replace"
	default:
		return ""
	}
}

func nextAssignmentOrderIndex(assignments []*models.PolicyAssignment, assignmentID, placement string) int {
	found := false
	minIndex := 0
	maxIndex := 0
	for _, assignment := range assignments {
		if assignment == nil || strings.EqualFold(assignment.ID, assignmentID) {
			continue
		}
		if !found {
			minIndex = assignment.OrderIndex
			maxIndex = assignment.OrderIndex
			found = true
			continue
		}
		if assignment.OrderIndex < minIndex {
			minIndex = assignment.OrderIndex
		}
		if assignment.OrderIndex > maxIndex {
			maxIndex = assignment.OrderIndex
		}
	}
	if !found {
		return 0
	}
	if placement == "top" {
		return minIndex - 1000
	}
	return maxIndex + 1000
}

func (s *Store) listPolicyAssignmentsForOrderScope(candidate *models.PolicyAssignment) []*models.PolicyAssignment {
	if candidate == nil {
		return nil
	}
	assignments := s.ListPolicyAssignments()
	scoped := make([]*models.PolicyAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		if policyAssignmentSameOrderScope(assignment, candidate) {
			scoped = append(scoped, assignment)
		}
	}
	return scoped
}

func policyAssignmentSameOrderScope(left, right *models.PolicyAssignment) bool {
	if left == nil || right == nil {
		return false
	}
	leftLevel := normalizedAssignmentLevel(left)
	rightLevel := normalizedAssignmentLevel(right)
	if leftLevel != rightLevel || !strings.EqualFold(strings.TrimSpace(left.OrganizationID), strings.TrimSpace(right.OrganizationID)) {
		return false
	}
	switch leftLevel {
	case "organization":
		return true
	case "resource":
		return strings.EqualFold(strings.TrimSpace(left.ResourceID), strings.TrimSpace(right.ResourceID))
	case "group":
		return assignmentGroupsSameOrderScope(left, right)
	case "resource_group":
		return strings.EqualFold(strings.TrimSpace(left.ResourceID), strings.TrimSpace(right.ResourceID)) &&
			assignmentGroupsSameOrderScope(left, right)
	default:
		return false
	}
}

func assignmentGroupsSameOrderScope(left, right *models.PolicyAssignment) bool {
	leftValues := []string{left.GroupID, left.GroupName}
	rightValues := []string{right.GroupID, right.GroupName}
	for _, leftValue := range leftValues {
		leftValue = strings.TrimSpace(leftValue)
		if leftValue == "" {
			continue
		}
		for _, rightValue := range rightValues {
			if strings.EqualFold(leftValue, strings.TrimSpace(rightValue)) {
				return true
			}
		}
	}
	return false
}

func normalizedAssignmentLevel(assignment *models.PolicyAssignment) string {
	if assignment == nil {
		return "organization"
	}
	level := strings.ToLower(strings.TrimSpace(assignment.Level))
	hasResource := strings.TrimSpace(assignment.ResourceID) != ""
	hasGroup := strings.TrimSpace(assignment.GroupID) != "" || strings.TrimSpace(assignment.GroupName) != ""
	if level == "" || (level == "organization" && (hasResource || hasGroup)) {
		switch {
		case hasResource && hasGroup:
			return "resource_group"
		case hasResource:
			return "resource"
		case hasGroup:
			return "group"
		}
	}
	switch level {
	case "organization", "group", "resource", "resource_group":
		return level
	case "gateway":
		return "unsupported"
	}
	if hasResource {
		if hasGroup {
			return "resource_group"
		}
		return "resource"
	}
	if hasGroup {
		return "group"
	}
	return "organization"
}

func policyAssignmentApplies(assignment *models.PolicyAssignment, resourceID string, groupIDs, groupNames []string) bool {
	if assignment == nil || !assignment.Enabled {
		return false
	}
	resourceID = strings.TrimSpace(resourceID)
	switch normalizedAssignmentLevel(assignment) {
	case "organization":
		return true
	case "group":
		return assignmentGroupMatches(assignment, groupIDs, groupNames)
	case "resource":
		return resourceID != "" && strings.EqualFold(strings.TrimSpace(assignment.ResourceID), resourceID)
	case "resource_group":
		return resourceID != "" &&
			strings.EqualFold(strings.TrimSpace(assignment.ResourceID), resourceID) &&
			assignmentGroupMatches(assignment, groupIDs, groupNames)
	default:
		return false
	}
}

func assignmentGroupMatches(assignment *models.PolicyAssignment, groupIDs, groupNames []string) bool {
	if assignment == nil {
		return false
	}
	groupID := strings.TrimSpace(assignment.GroupID)
	groupName := strings.TrimSpace(assignment.GroupName)
	if groupID == "" && groupName == "" {
		return false
	}
	return containsFold(groupIDs, groupID) || containsFold(groupIDs, groupName) ||
		containsFold(groupNames, groupID) || containsFold(groupNames, groupName)
}

func containsFold(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}
