package store

import (
	"database/sql"
	"log"
	"strings"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Policy Rule operations
// ─────────────────────────────────────────────

func (s *Store) GetPolicyRule(id string) (*models.PolicyRule, bool) {
	row := s.db.QueryRow(`SELECT id, name, description, priority, enabled, tenant_id,
		scope, gateway_id, resource_id, conditions_json,
		action, created_at, updated_at FROM policy_rules WHERE id = ?`, id)

	r := &models.PolicyRule{}
	var enabled int
	var condJSON, createdAt, updatedAt string

	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Priority, &enabled,
		&r.TenantID, &r.Scope, &r.GatewayID, &r.ResourceID, &condJSON,
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
	_, err := s.db.Exec(`INSERT OR REPLACE INTO policy_rules
		(id, name, description, priority, enabled, tenant_id, scope, gateway_id, resource_id,
		 conditions_json, action, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.Name, rule.Description, rule.Priority, b2i(rule.Enabled),
		rule.TenantID, normalizedRuleScope(rule.Scope), rule.GatewayID, rule.ResourceID,
		toJSON(rule.Conditions), rule.Action, fmtTime(rule.CreatedAt), fmtTime(rule.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save policy rule %s: %v", rule.ID, err)
	}
}

func (s *Store) ListPolicyRules() []*models.PolicyRule {
	rows, err := s.db.Query(`SELECT id, name, description, priority, enabled, tenant_id,
		scope, gateway_id, resource_id, conditions_json,
		action, created_at, updated_at FROM policy_rules ORDER BY priority ASC`)
	if err != nil {
		log.Printf("[STORE] Failed to list policy rules: %v", err)
		return nil
	}
	defer rows.Close()
	rules := scanPolicyRules(rows)
	s.decoratePolicyRulesWithAssignments(rules)
	return rules
}

func (s *Store) ListPolicyRulesForAccess(tenantID, gatewayID, resourceID string) []*models.PolicyRule {
	assignments := s.ListPolicyAssignmentsForAccess(tenantID, gatewayID, resourceID)
	if len(assignments) > 0 {
		rules := make([]*models.PolicyRule, 0, len(assignments))
		for _, assignment := range assignments {
			rule, ok := s.GetPolicyRule(assignment.PolicyID)
			if !ok || rule == nil || !rule.Enabled {
				continue
			}
			rules = append(rules, materializePolicyRuleAssignment(rule, assignment))
		}
		return rules
	}

	rows, err := s.db.Query(`SELECT id, name, description, priority, enabled, tenant_id,
		scope, gateway_id, resource_id, conditions_json,
		action, created_at, updated_at FROM policy_rules
		WHERE (tenant_id = ? OR tenant_id = '')
		  AND (
			(COALESCE(NULLIF(scope, ''), 'global') = 'resource' AND resource_id = ?)
			OR (COALESCE(NULLIF(scope, ''), 'global') = 'gateway' AND gateway_id = ?)
			OR (COALESCE(NULLIF(scope, ''), 'global') = 'global' AND tenant_id <> '')
		  )
		ORDER BY
		  CASE COALESCE(NULLIF(scope, ''), 'global')
			WHEN 'resource' THEN 1
			WHEN 'gateway' THEN 2
			ELSE 3
		  END,
		  priority ASC`, tenantID, resourceID, gatewayID)
	if err != nil {
		log.Printf("[STORE] Failed to list scoped policy rules: %v", err)
		return nil
	}
	defer rows.Close()
	return scanPolicyRules(rows)
}

func scanPolicyRules(rows *sql.Rows) []*models.PolicyRule {
	var rules []*models.PolicyRule
	for rows.Next() {
		r := &models.PolicyRule{}
		var enabled int
		var condJSON, createdAt, updatedAt string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Priority, &enabled,
			&r.TenantID, &r.Scope, &r.GatewayID, &r.ResourceID, &condJSON,
			&r.Action, &createdAt, &updatedAt); err != nil {
			continue
		}
		r.Enabled = i2b(enabled)
		r.Scope = normalizedRuleScope(r.Scope)
		r.Conditions = fromJSON[models.RuleConditions](condJSON)
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updatedAt)
		rules = append(rules, r)
	}
	return rules
}

func normalizedRuleScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "resource", "gateway":
		return strings.ToLower(strings.TrimSpace(scope))
	default:
		return "global"
	}
}

func (s *Store) DeletePolicyRule(id string) {
	s.DeletePolicyAssignmentsForPolicy(id)
	s.db.Exec("DELETE FROM policy_rules WHERE id = ?", id)
}

func (s *Store) GetPolicyAssignment(id string) (*models.PolicyAssignment, bool) {
	row := s.db.QueryRow(`SELECT id, policy_id, tenant_id, gateway_id, resource_id,
		enabled, created_at, updated_at FROM policy_assignments WHERE id = ?`, id)

	assignment := &models.PolicyAssignment{}
	var enabled int
	var createdAt, updatedAt string
	if err := row.Scan(&assignment.ID, &assignment.PolicyID, &assignment.TenantID,
		&assignment.GatewayID, &assignment.ResourceID, &enabled, &createdAt, &updatedAt); err != nil {
		return nil, false
	}
	assignment.Enabled = i2b(enabled)
	assignment.Scope = assignmentScope(assignment)
	assignment.CreatedAt = parseTime(createdAt)
	assignment.UpdatedAt = parseTime(updatedAt)
	return assignment, true
}

func (s *Store) SavePolicyAssignment(assignment *models.PolicyAssignment) {
	if assignment == nil {
		return
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO policy_assignments
		(id, policy_id, tenant_id, gateway_id, resource_id, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		assignment.ID, assignment.PolicyID, assignment.TenantID, assignment.GatewayID,
		assignment.ResourceID, b2i(assignment.Enabled), fmtTime(assignment.CreatedAt), fmtTime(assignment.UpdatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save policy assignment %s: %v", assignment.ID, err)
	}
}

func (s *Store) ListPolicyAssignments() []*models.PolicyAssignment {
	rows, err := s.db.Query(`SELECT id, policy_id, tenant_id, gateway_id, resource_id,
		enabled, created_at, updated_at FROM policy_assignments
		ORDER BY created_at ASC`)
	if err != nil {
		log.Printf("[STORE] Failed to list policy assignments: %v", err)
		return nil
	}
	defer rows.Close()
	return scanPolicyAssignments(rows)
}

func (s *Store) ListPolicyAssignmentsForPolicy(policyID string) []*models.PolicyAssignment {
	rows, err := s.db.Query(`SELECT id, policy_id, tenant_id, gateway_id, resource_id,
		enabled, created_at, updated_at FROM policy_assignments
		WHERE policy_id = ?
		ORDER BY created_at ASC`, policyID)
	if err != nil {
		log.Printf("[STORE] Failed to list policy assignments for policy %s: %v", policyID, err)
		return nil
	}
	defer rows.Close()
	return scanPolicyAssignments(rows)
}

func (s *Store) ListPolicyAssignmentsForAccess(tenantID, gatewayID, resourceID string) []*models.PolicyAssignment {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, policy_id, tenant_id, gateway_id, resource_id,
		enabled, created_at, updated_at FROM policy_assignments
		WHERE enabled = 1
		  AND tenant_id = ?
		  AND (
			(resource_id <> '' AND resource_id = ?)
			OR (resource_id = '' AND gateway_id <> '' AND gateway_id = ?)
			OR (resource_id = '' AND gateway_id = '')
		  )
		ORDER BY
		  CASE
			WHEN resource_id <> '' THEN 1
			WHEN gateway_id <> '' THEN 2
			ELSE 3
		  END,
		  created_at ASC`, tenantID, strings.TrimSpace(resourceID), strings.TrimSpace(gatewayID))
	if err != nil {
		log.Printf("[STORE] Failed to list policy assignments for access: %v", err)
		return nil
	}
	defer rows.Close()
	return scanPolicyAssignments(rows)
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
		if err := rows.Scan(&assignment.ID, &assignment.PolicyID, &assignment.TenantID,
			&assignment.GatewayID, &assignment.ResourceID, &enabled, &createdAt, &updatedAt); err != nil {
			continue
		}
		assignment.Enabled = i2b(enabled)
		assignment.Scope = assignmentScope(assignment)
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
	copyRule.Assignments = nil
	copyRule.AssignmentCount = 0
	copyRule.TenantID = assignment.TenantID
	copyRule.GatewayID = assignment.GatewayID
	copyRule.ResourceID = assignment.ResourceID
	copyRule.Scope = assignmentScope(assignment)
	return &copyRule
}

func assignmentScope(assignment *models.PolicyAssignment) string {
	if assignment == nil {
		return "global"
	}
	if strings.TrimSpace(assignment.ResourceID) != "" {
		return "resource"
	}
	if strings.TrimSpace(assignment.GatewayID) != "" {
		return "gateway"
	}
	return "global"
}
