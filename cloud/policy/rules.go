package policy

import (
	"fmt"
	"log"
	"strings"
	"time"

	"cloud/models"
	"cloud/store"
	"cloud/util"
)

// DefaultRules returns a set of default policy rules that demonstrate
// conditional access capabilities
func DefaultRules() []*models.PolicyRule {
	now := time.Now()
	return []*models.PolicyRule{
		{
			ID:          "rule_default_deny_unhealthy",
			Name:        "Deny Unhealthy Devices",
			Description: "Block access for devices with critical health issues",
			Priority:    10,
			Enabled:     true,
			Conditions: models.RuleConditions{
				MinHealthScore: 40,
			},
			Action:    "deny",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "rule_mfa_rdp",
			Name:        "Require MFA for RDP",
			Description: "All RDP connections require multi-factor authentication",
			Priority:    20,
			Enabled:     true,
			Conditions: models.RuleConditions{
				TargetPorts: []int{3389},
			},
			Action:    "mfa_required",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "rule_mfa_ssh",
			Name:        "Require MFA for SSH",
			Description: "All SSH connections require multi-factor authentication",
			Priority:    25,
			Enabled:     true,
			Conditions: models.RuleConditions{
				TargetPorts: []int{22},
			},
			Action:    "mfa_required",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "rule_block_high_risk",
			Name:        "Block High Risk Access",
			Description: "Deny access when risk score exceeds threshold",
			Priority:    15,
			Enabled:     true,
			Conditions: models.RuleConditions{
				MaxRiskScore: 75,
			},
			Action:    "deny",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "rule_allow_admin",
			Name:        "Allow Admin Full Access",
			Description: "Administrators have full access to all resources",
			Priority:    5,
			Enabled:     true,
			Conditions: models.RuleConditions{
				AllowedRoles: []string{"admin"},
			},
			Action:    "allow",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "rule_business_hours_web",
			Name:        "Allow Web During Business Hours",
			Description: "Web access allowed during business hours for all users",
			Priority:    30,
			Enabled:     true,
			Conditions: models.RuleConditions{
				TargetPorts:      []int{80, 443},
				AllowedTimeStart: "08:00",
				AllowedTimeEnd:   "18:00",
				AllowedDays:      []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"},
			},
			Action:    "allow",
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
}

// InitDefaultRules loads default rules into the store if no rules exist
func InitDefaultRules(s *store.Store) {
	existing := s.ListPolicyRules()
	if len(existing) > 0 {
		log.Printf("[PA] %d policy rules already exist, skipping default initialization", len(existing))
		return
	}

	for _, rule := range DefaultRules() {
		s.SavePolicyRule(rule)
	}
	log.Printf("[PA] Initialized %d default policy rules", len(DefaultRules()))
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

// generateRuleID creates a unique rule ID
func generateRuleID() (string, error) {
	return util.GenerateID("rule")
}
