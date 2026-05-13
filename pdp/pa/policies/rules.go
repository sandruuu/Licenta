package policies

import (
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/config"
	"pdp/models"
	"pdp/store"
	"pdp/util"
)

// InitDefaultRules loads configured seed rules into the store if no rules exist.
func InitDefaultRules(s *store.Store, policyCfg config.PolicyConfig) {
	if !policyCfg.SeedDefaultRules || len(policyCfg.DefaultRules) == 0 {
		return
	}
	existing := s.ListPolicyRules()
	if len(existing) > 0 {
		log.Printf("[PA] %d policy rules already exist, skipping default initialization", len(existing))
		return
	}

	now := time.Now()
	created := 0
	for _, configured := range policyCfg.DefaultRules {
		rule := configured
		if rule.ID == "" {
			id, err := generateRuleID()
			if err != nil {
				log.Printf("[PA] Skipping configured policy rule without ID: %v", err)
				continue
			}
			rule.ID = id
		}
		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = now
		}
		if rule.UpdatedAt.IsZero() {
			rule.UpdatedAt = now
		}
		if err := validateRule(&rule); err != nil {
			log.Printf("[PA] Skipping invalid configured policy rule %q: %v", rule.ID, err)
			continue
		}
		s.SavePolicyRule(&rule)
		seedDefaultRuleAssignments(s, &rule)
		created++
	}
	if created > 0 {
		log.Printf("[PA] Initialized %d configured policy rules", created)
	}
}

func seedDefaultRuleAssignments(s *store.Store, rule *models.PolicyRule) {
	if s == nil || rule == nil {
		return
	}
	if strings.TrimSpace(rule.TenantID) != "" || strings.TrimSpace(rule.GatewayID) != "" || strings.TrimSpace(rule.ResourceID) != "" {
		s.SavePolicyAssignment(&models.PolicyAssignment{
			ID:         "assign_" + rule.ID,
			PolicyID:   rule.ID,
			TenantID:   rule.TenantID,
			GatewayID:  rule.GatewayID,
			ResourceID: rule.ResourceID,
			Enabled:    rule.Enabled,
			CreatedAt:  rule.CreatedAt,
			UpdatedAt:  rule.UpdatedAt,
		})
		return
	}
	for _, tenant := range s.ListTenants() {
		if tenant == nil || !tenant.Enabled {
			continue
		}
		s.SavePolicyAssignment(&models.PolicyAssignment{
			ID:        "assign_" + rule.ID + "_" + tenant.ID,
			PolicyID:  rule.ID,
			TenantID:  tenant.ID,
			Enabled:   rule.Enabled,
			CreatedAt: rule.CreatedAt,
			UpdatedAt: rule.UpdatedAt,
		})
	}
}

// RuleManager provides CRUD operations for policy rules
type RuleManager struct {
	store *store.Store
}

// NewRuleManager creates a new RuleManager
func NewRuleManager(s *store.Store) *RuleManager {
	return &RuleManager{store: s}
}

// validActions defines the allowed policy rule actions
var validActions = map[string]bool{
	"allow":        true,
	"deny":         true,
	"mfa_required": true,
	"restrict":     true,
}

// validateRule checks that required fields are valid
func validateRule(rule *models.PolicyRule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("rule name is required")
	}
	if !validActions[rule.Action] {
		return fmt.Errorf("invalid action %q: must be allow, deny, mfa_required, or restrict", rule.Action)
	}
	if rule.Priority < 0 {
		return fmt.Errorf("priority must be >= 0")
	}
	rule.Scope = normalizeScope(rule.Scope)
	return nil
}

func normalizeScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "gateway", "resource":
		return strings.ToLower(strings.TrimSpace(scope))
	default:
		return "global"
	}
}

func (rm *RuleManager) validateScopeBindings(rule *models.PolicyRule) error {
	if rm == nil || rm.store == nil || rule == nil {
		return nil
	}
	tenantID := strings.TrimSpace(rule.TenantID)
	if tenantID != "" {
		tenant, ok := rm.store.GetTenant(tenantID)
		if !ok || tenant == nil || !tenant.Enabled {
			return fmt.Errorf("tenant not found or disabled: %s", tenantID)
		}
	}
	switch rule.Scope {
	case "gateway":
		gateway, ok := rm.store.GetGateway(rule.GatewayID)
		if !ok || gateway == nil {
			return fmt.Errorf("gateway not found: %s", rule.GatewayID)
		}
		if tenantID != "" && gateway.TenantID != tenantID {
			return fmt.Errorf("gateway %s does not belong to tenant %s", rule.GatewayID, tenantID)
		}
	case "resource":
		resource, ok := rm.store.GetResource(rule.ResourceID)
		if !ok || resource == nil {
			return fmt.Errorf("resource not found: %s", rule.ResourceID)
		}
		if tenantID != "" && resource.TenantID != tenantID {
			return fmt.Errorf("resource %s does not belong to tenant %s", rule.ResourceID, tenantID)
		}
		if strings.TrimSpace(rule.GatewayID) == "" {
			rule.GatewayID = resource.GatewayID
		}
		if strings.TrimSpace(rule.GatewayID) != "" && strings.TrimSpace(resource.GatewayID) != "" && rule.GatewayID != resource.GatewayID {
			return fmt.Errorf("resource %s is not assigned to gateway %s", rule.ResourceID, rule.GatewayID)
		}
	}
	return nil
}

func (rm *RuleManager) validateAssignment(assignment *models.PolicyAssignment) error {
	if assignment == nil {
		return fmt.Errorf("assignment is required")
	}
	if strings.TrimSpace(assignment.PolicyID) == "" {
		return fmt.Errorf("policy_id is required")
	}
	if _, ok := rm.store.GetPolicyRule(assignment.PolicyID); !ok {
		return fmt.Errorf("policy not found: %s", assignment.PolicyID)
	}
	if strings.TrimSpace(assignment.TenantID) == "" {
		return fmt.Errorf("organization is required for policy assignment")
	}
	tenant, ok := rm.store.GetTenant(assignment.TenantID)
	if !ok || tenant == nil || !tenant.Enabled {
		return fmt.Errorf("tenant not found or disabled: %s", assignment.TenantID)
	}
	if strings.TrimSpace(assignment.ResourceID) != "" {
		resource, ok := rm.store.GetResource(assignment.ResourceID)
		if !ok || resource == nil {
			return fmt.Errorf("resource not found: %s", assignment.ResourceID)
		}
		if resource.TenantID != "" && resource.TenantID != assignment.TenantID {
			return fmt.Errorf("resource %s does not belong to tenant %s", assignment.ResourceID, assignment.TenantID)
		}
		if strings.TrimSpace(assignment.GatewayID) == "" {
			assignment.GatewayID = resource.GatewayID
		}
		if strings.TrimSpace(assignment.GatewayID) != "" && strings.TrimSpace(resource.GatewayID) != "" && assignment.GatewayID != resource.GatewayID {
			return fmt.Errorf("resource %s is not assigned to gateway %s", assignment.ResourceID, assignment.GatewayID)
		}
	}
	if strings.TrimSpace(assignment.GatewayID) != "" {
		gateway, ok := rm.store.GetGateway(assignment.GatewayID)
		if !ok || gateway == nil {
			return fmt.Errorf("gateway not found: %s", assignment.GatewayID)
		}
		if gateway.TenantID != "" && gateway.TenantID != assignment.TenantID {
			return fmt.Errorf("gateway %s does not belong to tenant %s", assignment.GatewayID, assignment.TenantID)
		}
	}
	if !assignment.Enabled {
		assignment.Enabled = false
	}
	if strings.TrimSpace(assignment.ResourceID) != "" {
		assignment.Scope = "resource"
	} else if strings.TrimSpace(assignment.GatewayID) != "" {
		assignment.Scope = "gateway"
	} else {
		assignment.Scope = "tenant"
	}
	return nil
}

// CreateRule adds a new policy rule
func (rm *RuleManager) CreateRule(rule *models.PolicyRule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	if rule.ID == "" {
		id, err := generateRuleID()
		if err != nil {
			return err
		}
		rule.ID = id
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rm.store.SavePolicyRule(rule)
	log.Printf("[PA] Rule created: %s (%s)", rule.Name, rule.ID)
	return nil
}

// UpdateRule modifies an existing policy rule
func (rm *RuleManager) UpdateRule(rule *models.PolicyRule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	existing, ok := rm.store.GetPolicyRule(rule.ID)
	if !ok {
		return fmt.Errorf("rule not found: %s", rule.ID)
	}
	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedAt = time.Now()
	rm.store.SavePolicyRule(rule)
	log.Printf("[PA] Rule updated: %s (%s)", rule.Name, rule.ID)
	return nil
}

// DeleteRule removes a policy rule
func (rm *RuleManager) DeleteRule(id string) error {
	_, ok := rm.store.GetPolicyRule(id)
	if !ok {
		return fmt.Errorf("rule not found: %s", id)
	}
	rm.store.DeletePolicyRule(id)
	log.Printf("[PA] Rule deleted: %s", id)
	return nil
}

// GetRule returns a specific rule by ID
func (rm *RuleManager) GetRule(id string) (*models.PolicyRule, error) {
	rule, ok := rm.store.GetPolicyRule(id)
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", id)
	}
	return rule, nil
}

// ListRules returns all rules sorted by priority
func (rm *RuleManager) ListRules() []*models.PolicyRule {
	return rm.store.ListPolicyRules()
}

func (rm *RuleManager) CreateAssignment(assignment *models.PolicyAssignment) error {
	if assignment == nil {
		return fmt.Errorf("assignment is required")
	}
	if assignment.ID == "" {
		id, err := util.GenerateID("assign")
		if err != nil {
			return err
		}
		assignment.ID = id
	}
	if !assignment.Enabled {
		assignment.Enabled = false
	} else {
		assignment.Enabled = true
	}
	if err := rm.validateAssignment(assignment); err != nil {
		return err
	}
	now := time.Now()
	assignment.CreatedAt = now
	assignment.UpdatedAt = now
	rm.store.SavePolicyAssignment(assignment)
	log.Printf("[PA] Policy assignment created: policy=%s assignment=%s", assignment.PolicyID, assignment.ID)
	return nil
}

func (rm *RuleManager) UpdateAssignment(assignment *models.PolicyAssignment) error {
	if assignment == nil || strings.TrimSpace(assignment.ID) == "" {
		return fmt.Errorf("assignment ID is required")
	}
	existing, ok := rm.store.GetPolicyAssignment(assignment.ID)
	if !ok {
		return fmt.Errorf("assignment not found: %s", assignment.ID)
	}
	if !assignment.Enabled {
		assignment.Enabled = false
	} else {
		assignment.Enabled = true
	}
	if err := rm.validateAssignment(assignment); err != nil {
		return err
	}
	assignment.CreatedAt = existing.CreatedAt
	assignment.UpdatedAt = time.Now()
	rm.store.SavePolicyAssignment(assignment)
	log.Printf("[PA] Policy assignment updated: policy=%s assignment=%s", assignment.PolicyID, assignment.ID)
	return nil
}

func (rm *RuleManager) DeleteAssignment(id string) error {
	if !rm.store.DeletePolicyAssignment(id) {
		return fmt.Errorf("assignment not found: %s", id)
	}
	log.Printf("[PA] Policy assignment deleted: %s", id)
	return nil
}

func (rm *RuleManager) GetAssignment(id string) (*models.PolicyAssignment, error) {
	assignment, ok := rm.store.GetPolicyAssignment(id)
	if !ok {
		return nil, fmt.Errorf("assignment not found: %s", id)
	}
	return assignment, nil
}

func (rm *RuleManager) ListAssignments() []*models.PolicyAssignment {
	return rm.store.ListPolicyAssignments()
}

// generateRuleID creates a unique rule ID
func generateRuleID() (string, error) {
	return util.GenerateID("rule")
}
