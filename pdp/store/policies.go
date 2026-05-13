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
	return scanPolicyRules(rows)
}

func (s *Store) ListPolicyRulesForAccess(tenantID, gatewayID, resourceID string) []*models.PolicyRule {
	rows, err := s.db.Query(`SELECT id, name, description, priority, enabled, tenant_id,
		scope, gateway_id, resource_id, conditions_json,
		action, created_at, updated_at FROM policy_rules
		WHERE (tenant_id = ? OR tenant_id = '')
		  AND (
			(COALESCE(NULLIF(scope, ''), 'global') = 'resource' AND resource_id = ?)
			OR (COALESCE(NULLIF(scope, ''), 'global') = 'gateway' AND gateway_id = ?)
			OR COALESCE(NULLIF(scope, ''), 'global') = 'global'
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
	s.db.Exec("DELETE FROM policy_rules WHERE id = ?", id)
}
