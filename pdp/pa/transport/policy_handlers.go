package transport

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	"pdp/util"
)

type policyRulePayload struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Priority    int                   `json:"priority"`
	Enabled     *bool                 `json:"enabled"`
	Conditions  models.RuleConditions `json:"conditions"`
	Action      string                `json:"action"`
}

type policyAssignmentPayload struct {
	ID         string `json:"id"`
	PolicyID   string `json:"policy_id"`
	TenantID   string `json:"tenant_id"`
	Level      string `json:"level"`
	GroupID    string `json:"group_id"`
	GroupName  string `json:"group_name"`
	ResourceID string `json:"resource_id"`
	Priority   int    `json:"priority"`
	Enabled    *bool  `json:"enabled"`
}

func (s *Server) handleAdminPolicies(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store unavailable"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: s.pa.Store.ListPolicyRules()})

	case http.MethodPost:
		payload, ok := decodePolicyRulePayload(w, r)
		if !ok {
			return
		}
		rule, errMsg := s.policyRuleFromPayload(payload, nil)
		if errMsg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": errMsg})
			return
		}
		s.pa.Store.SavePolicyRule(rule)
		writeJSON(w, http.StatusCreated, models.APIResponse{Success: true, Message: "Policy created", Data: rule})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminPolicyByID(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store unavailable"})
		return
	}
	policyID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/admin/policies/"))
	if policyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy ID required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		rule, found := s.pa.Store.GetPolicyRule(policyID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		rule.Assignments = s.pa.Store.ListPolicyAssignmentsForPolicy(rule.ID)
		rule.AssignmentCount = len(rule.Assignments)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: rule})

	case http.MethodPut:
		existing, found := s.pa.Store.GetPolicyRule(policyID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		payload, ok := decodePolicyRulePayload(w, r)
		if !ok {
			return
		}
		rule, errMsg := s.policyRuleFromPayload(payload, existing)
		if errMsg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": errMsg})
			return
		}
		rule.ID = policyID
		s.pa.Store.SavePolicyRule(rule)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Policy updated", Data: rule})

	case http.MethodDelete:
		if _, found := s.pa.Store.GetPolicyRule(policyID); !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		s.pa.Store.DeletePolicyRule(policyID)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Policy deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminPolicyAssignments(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store unavailable"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: s.pa.Store.ListPolicyAssignments()})

	case http.MethodPost:
		payload, ok := decodePolicyAssignmentPayload(w, r)
		if !ok {
			return
		}
		assignment, errMsg := s.policyAssignmentFromPayload(payload, nil)
		if errMsg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": errMsg})
			return
		}
		s.pa.Store.SavePolicyAssignment(assignment)
		writeJSON(w, http.StatusCreated, models.APIResponse{Success: true, Message: "Policy assignment created", Data: assignment})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminPolicyAssignmentByID(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store unavailable"})
		return
	}
	assignmentID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/admin/policy-assignments/"))
	if assignmentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy assignment ID required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		assignment, found := s.pa.Store.GetPolicyAssignment(assignmentID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy assignment not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: assignment})

	case http.MethodPut:
		existing, found := s.pa.Store.GetPolicyAssignment(assignmentID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy assignment not found"})
			return
		}
		payload, ok := decodePolicyAssignmentPayload(w, r)
		if !ok {
			return
		}
		assignment, errMsg := s.policyAssignmentFromPayload(payload, existing)
		if errMsg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": errMsg})
			return
		}
		assignment.ID = assignmentID
		s.pa.Store.SavePolicyAssignment(assignment)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Policy assignment updated", Data: assignment})

	case http.MethodDelete:
		if !s.pa.Store.DeletePolicyAssignment(assignmentID) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy assignment not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Policy assignment deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func decodePolicyRulePayload(w http.ResponseWriter, r *http.Request) (policyRulePayload, bool) {
	var payload policyRulePayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return payload, false
	}
	return payload, true
}

func decodePolicyAssignmentPayload(w http.ResponseWriter, r *http.Request) (policyAssignmentPayload, bool) {
	var payload policyAssignmentPayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return payload, false
	}
	return payload, true
}

func (s *Server) policyRuleFromPayload(payload policyRulePayload, existing *models.PolicyRule) (*models.PolicyRule, string) {
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		return nil, "policy name required"
	}
	action, ok := normalizePolicyAction(payload.Action)
	if !ok {
		return nil, "policy action must be allow, deny, or mfa_required"
	}

	now := time.Now()
	rule := &models.PolicyRule{
		ID:          strings.TrimSpace(payload.ID),
		Name:        name,
		Description: strings.TrimSpace(payload.Description),
		Priority:    payload.Priority,
		Enabled:     boolFromPayload(payload.Enabled, true),
		Conditions:  payload.Conditions,
		Action:      action,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if existing != nil {
		rule.ID = existing.ID
		rule.CreatedAt = existing.CreatedAt
		if payload.Enabled == nil {
			rule.Enabled = existing.Enabled
		}
	}
	if rule.ID == "" {
		rule.ID, _ = util.GenerateID("policy")
	}
	if rule.Priority <= 0 {
		rule.Priority = 100
	}
	return rule, ""
}

func (s *Server) policyAssignmentFromPayload(payload policyAssignmentPayload, existing *models.PolicyAssignment) (*models.PolicyAssignment, string) {
	policyID := strings.TrimSpace(payload.PolicyID)
	tenantID := strings.TrimSpace(payload.TenantID)
	level := normalizePolicyLayer(payload.Level)
	resourceID := strings.TrimSpace(payload.ResourceID)
	groupID := strings.TrimSpace(payload.GroupID)
	groupName := strings.TrimSpace(payload.GroupName)

	if existing != nil {
		if policyID == "" {
			policyID = existing.PolicyID
		}
		if tenantID == "" {
			tenantID = existing.TenantID
		}
		if level == "" {
			level = existing.Level
		}
	}
	if _, found := s.pa.Store.GetPolicyRule(policyID); !found {
		return nil, "policy not found"
	}
	if _, found := s.pa.Store.GetTenant(tenantID); !found {
		return nil, "organization not found"
	}
	if errMsg := validatePolicyAssignmentTarget(level, resourceID, groupID, groupName); errMsg != "" {
		return nil, errMsg
	}

	now := time.Now()
	assignment := &models.PolicyAssignment{
		ID:         strings.TrimSpace(payload.ID),
		PolicyID:   policyID,
		TenantID:   tenantID,
		Level:      level,
		GroupID:    groupID,
		GroupName:  groupName,
		ResourceID: resourceID,
		Priority:   payload.Priority,
		Enabled:    boolFromPayload(payload.Enabled, true),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if existing != nil {
		assignment.ID = existing.ID
		assignment.CreatedAt = existing.CreatedAt
		if payload.Enabled == nil {
			assignment.Enabled = existing.Enabled
		}
	}
	if assignment.ID == "" {
		assignment.ID, _ = util.GenerateID("policy_assignment")
	}
	if assignment.Priority <= 0 {
		assignment.Priority = 100
	}
	return assignment, ""
}

func normalizePolicyAction(action string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "allow":
		return "allow", true
	case "deny", "block":
		return "deny", true
	case "mfa", "require_mfa", "mfa_required":
		return "mfa_required", true
	default:
		return "", false
	}
}

func normalizePolicyLayer(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "tenant", "global", "organization":
		return "organization"
	case "group":
		return "group"
	case "resource", "application":
		return "resource"
	case "resource_group", "application_group":
		return "resource_group"
	default:
		return ""
	}
}

func validatePolicyAssignmentTarget(level, resourceID, groupID, groupName string) string {
	if level == "" {
		return "policy assignment level must be organization, group, resource, or resource_group"
	}
	hasResource := strings.TrimSpace(resourceID) != ""
	hasGroup := strings.TrimSpace(groupID) != "" || strings.TrimSpace(groupName) != ""
	switch level {
	case "organization":
		return ""
	case "group":
		if !hasGroup {
			return "group assignment requires a group"
		}
	case "resource":
		if !hasResource {
			return "resource assignment requires a resource"
		}
	case "resource_group":
		if !hasResource || !hasGroup {
			return "resource-group assignment requires both a resource and a group"
		}
	}
	return ""
}

func boolFromPayload(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
	}
	return *value
}
