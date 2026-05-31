package transport

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa/events"
	pdpstore "pdp/store"
	"pdp/util"
)

type policyRulePayload struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Enabled     *bool                 `json:"enabled"`
	Conditions  models.RuleConditions `json:"conditions"`
	Action      string                `json:"action"`
}

type policyAssignmentPayload struct {
	ID             string `json:"id"`
	PolicyID       string `json:"policy_id"`
	TenantID       string `json:"tenant_id"`
	OrganizationID string `json:"organization_id"`
	Level          string `json:"level"`
	GroupID        string `json:"group_id"`
	GroupName      string `json:"group_name"`
	ResourceID     string `json:"resource_id"`
	OrderIndex     *int   `json:"order_index"`
	OrderPlacement string `json:"order_placement"`
	Enabled        *bool  `json:"enabled"`
}

func (s *Server) handleAdminPolicies(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store unavailable"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: filterPolicyRulesByOrganization(s.pa.Store.ListPolicyRules(), s.allowedOrganizationIDs(r))})

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
		s.publishPolicyEvent("created", rule, nil)
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
		assignments := s.pa.Store.ListPolicyAssignmentsForPolicy(rule.ID)
		rule.Assignments = filterPolicyAssignmentsByOrganization(assignments, s.allowedOrganizationIDs(r))
		if len(assignments) > 0 && len(rule.Assignments) == 0 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "organization access denied"})
			return
		}
		rule.AssignmentCount = len(rule.Assignments)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: rule})

	case http.MethodPut:
		existing, found := s.pa.Store.GetPolicyRule(policyID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		if !s.policyRuleAccessAllowed(r, existing.ID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "organization access denied"})
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
		s.publishPolicyEvent("updated", rule, nil)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Policy updated", Data: rule})

	case http.MethodDelete:
		if _, found := s.pa.Store.GetPolicyRule(policyID); !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		if pdpstore.IsDefaultGlobalPolicyID(policyID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "default global policy cannot be deleted"})
			return
		}
		if !s.policyRuleAccessAllowed(r, policyID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "organization access denied"})
			return
		}
		s.pa.Store.DeletePolicyRule(policyID)
		s.publishPolicyEvent("deleted", &models.PolicyRule{ID: policyID}, nil)
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
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: filterPolicyAssignmentsByOrganization(s.pa.Store.ListPolicyAssignments(), s.allowedOrganizationIDs(r))})

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
		if !s.requireOrganizationAccess(w, r, assignment.TenantID) {
			return
		}
		placement, _ := normalizePolicyAssignmentOrderPlacement(payload.OrderPlacement)
		deleted := s.pa.Store.SavePolicyAssignmentWithPlacement(assignment, placement)
		for _, deletedAssignment := range deleted {
			s.publishPolicyEvent("assignment_deleted", nil, deletedAssignment)
		}
		s.publishPolicyEvent("assignment_created", nil, assignment)
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
		if !s.requireOrganizationAccess(w, r, assignment.TenantID) {
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: assignment})

	case http.MethodPut:
		existing, found := s.pa.Store.GetPolicyAssignment(assignmentID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy assignment not found"})
			return
		}
		if pdpstore.IsDefaultGlobalAssignmentID(assignmentID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "default global policy assignment cannot be modified"})
			return
		}
		if !s.requireOrganizationAccess(w, r, existing.TenantID) {
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
		if !s.requireOrganizationAccess(w, r, assignment.TenantID) {
			return
		}
		assignment.ID = assignmentID
		placement, _ := normalizePolicyAssignmentOrderPlacement(payload.OrderPlacement)
		deleted := s.pa.Store.SavePolicyAssignmentWithPlacement(assignment, placement)
		for _, deletedAssignment := range deleted {
			s.publishPolicyEvent("assignment_deleted", nil, deletedAssignment)
		}
		s.publishPolicyEvent("assignment_updated", nil, assignment)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Policy assignment updated", Data: assignment})

	case http.MethodDelete:
		existing, _ := s.pa.Store.GetPolicyAssignment(assignmentID)
		if pdpstore.IsDefaultGlobalAssignmentID(assignmentID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "default global policy assignment cannot be removed"})
			return
		}
		if existing != nil && !s.requireOrganizationAccess(w, r, existing.TenantID) {
			return
		}
		if !s.pa.Store.DeletePolicyAssignment(assignmentID) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy assignment not found"})
			return
		}
		s.publishPolicyEvent("assignment_deleted", nil, existing)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Policy assignment deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) publishPolicyEvent(action string, rule *models.PolicyRule, assignment *models.PolicyAssignment) {
	fields := map[string]string{
		"action": action,
		"reason": "policy_updated",
	}
	if rule != nil {
		fields["policy_id"] = rule.ID
	}
	if assignment != nil {
		fields["assignment_id"] = assignment.ID
		if strings.TrimSpace(fields["policy_id"]) == "" {
			fields["policy_id"] = assignment.PolicyID
		}
		fields["tenant_id"] = assignment.TenantID
		fields["resource_id"] = assignment.ResourceID
		fields["level"] = assignment.Level
		fields["group_id"] = assignment.GroupID
		fields["group_name"] = assignment.GroupName
		fields["order_index"] = strconv.Itoa(assignment.OrderIndex)
	}
	s.publishCAEPEvent(events.TopicPolicyUpdated, fields)
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
	action, ok := models.PolicyActionForAuthenticationPolicy(payload.Conditions.Authentication.Policy)
	if !ok {
		return nil, "authentication policy required"
	}
	if errMsg := validatePolicyConditions(action, payload.Conditions); errMsg != "" {
		return nil, errMsg
	}

	now := time.Now()
	rule := &models.PolicyRule{
		ID:          strings.TrimSpace(payload.ID),
		Name:        name,
		Description: strings.TrimSpace(payload.Description),
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
	return rule, ""
}

func validatePolicyConditions(action string, conditions models.RuleConditions) string {
	if conditions.Risk.MinScore < 0 || conditions.Risk.MinScore > 100 ||
		conditions.Risk.MaxScore < 0 || conditions.Risk.MaxScore > 100 {
		return "risk score bounds must be between 0 and 100"
	}
	if conditions.Risk.MinScore > 0 && conditions.Risk.MaxScore > 0 && conditions.Risk.MinScore > conditions.Risk.MaxScore {
		return "minimum risk score cannot be greater than maximum risk score"
	}
	if policy := strings.TrimSpace(conditions.User.NewUserPolicy); policy != "" {
		if _, ok := models.NormalizeNewUserPolicy(policy); !ok {
			return "new user policy must be require_enrollment, allow_without_mfa, or deny"
		}
	}
	if policy := strings.TrimSpace(conditions.Authentication.Policy); policy == "" {
		return "authentication policy required"
	} else if _, ok := models.NormalizeAuthenticationPolicy(policy); !ok {
		return "authentication policy must be enforce_mfa, bypass_mfa, or deny"
	}
	if errMsg := validateUserLocationPolicy(conditions.UserLocation); errMsg != "" {
		return errMsg
	}
	if errMsg := validateRiskBasedAuthenticationPolicy(conditions.RiskBasedAuth); errMsg != "" {
		return errMsg
	}
	if strings.TrimSpace(conditions.AccessMatchMode) != "" {
		mode := strings.ToLower(strings.TrimSpace(conditions.AccessMatchMode))
		if mode != "all" && mode != "any" {
			return "access condition match mode must be all or any"
		}
	}
	if !validPolicyCIDRs(conditions.Network.AllowedCIDRs) ||
		!validPolicyCIDRs(conditions.Network.SkipMFACIDRs) ||
		!validPolicyCIDRs(conditions.Network.RequireMFACIDRs) ||
		!validPolicyCIDRs(conditions.Network.BlockedCIDRs) {
		return "network policies must contain valid IP addresses, CIDR ranges, or IP ranges"
	}
	if conditions.Network.AllowAllNetworks &&
		(len(conditions.Network.AllowedCIDRs) > 0 ||
			len(conditions.Network.SkipMFACIDRs) > 0 ||
			len(conditions.Network.RequireMFACIDRs) > 0 ||
			len(conditions.Network.BlockedCIDRs) > 0 ||
			conditions.Network.DenyOtherNetworks) {
		return "allow all networks cannot be combined with network restrictions"
	}
	if conditions.Network.DenyOtherNetworks &&
		len(conditions.Network.AllowedCIDRs) == 0 &&
		len(conditions.Network.SkipMFACIDRs) == 0 &&
		len(conditions.Network.RequireMFACIDRs) == 0 {
		return "deny other networks requires at least one allow, skip MFA, or require MFA network"
	}
	if conditions.Session.MaxAgeSeconds < 0 || conditions.Session.RevalidateEverySeconds < 0 {
		return "session control durations must be zero or greater"
	}
	if action != models.DecisionStepUpRequired {
		return ""
	}
	for _, method := range conditions.Authentication.StepUpMethods {
		switch strings.ToLower(strings.TrimSpace(method)) {
		case "", "totp", "webauthn":
		default:
			return "step-up methods must be totp or webauthn"
		}
	}
	return ""
}

func validateUserLocationPolicy(policy models.UserLocationPolicyConditions) string {
	if _, ok := models.NormalizeUserLocationAction(policy.DefaultAction); !ok {
		return "user location default action must be allow, require_mfa, skip_mfa, or block"
	}
	if _, ok := models.NormalizeUserLocationAction(policy.UnknownLocationAction); !ok {
		return "user location unknown action must be allow, require_mfa, skip_mfa, or block"
	}
	if mode := strings.TrimSpace(policy.CheckMode); mode != "" && mode != "access_device_only" {
		return "user location check mode must be access_device_only"
	}
	for _, rule := range policy.Rules {
		action, ok := models.NormalizeUserLocationAction(rule.Action)
		if !ok {
			return "user location rule action must be allow, require_mfa, skip_mfa, or block"
		}
		if len(rule.Countries) == 0 && action != models.UserLocationActionAllow {
			return "user location rule countries are required"
		}
		for _, country := range rule.Countries {
			country = strings.TrimSpace(country)
			if country == "" {
				return "user location countries cannot be empty"
			}
			if strings.ContainsAny(country, ",;") {
				return "user location countries must be individual country codes"
			}
		}
	}
	return ""
}

func validateRiskBasedAuthenticationPolicy(policy models.RiskBasedAuthPolicyConditions) string {
	if !policy.RequireMFAOnRisk {
		return ""
	}
	if mode := strings.ToLower(strings.TrimSpace(policy.MatchMode)); mode != "" && mode != "any" && mode != "all" {
		return "risk-based authentication match mode must be any or all"
	}
	for _, signal := range policy.Signals {
		switch strings.ToLower(strings.TrimSpace(signal)) {
		case "new_location", "unrealistic_travel", "impossible_travel", "user_baseline_anomaly":
		default:
			return "risk-based authentication signal must be new_location, unrealistic_travel, or user_baseline_anomaly"
		}
	}
	return ""
}

func validPolicyCIDRs(values []string) bool {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "-") && !strings.Contains(value, "/") {
			parts := strings.Split(value, "-")
			if len(parts) != 2 {
				return false
			}
			start := net.ParseIP(strings.TrimSpace(parts[0]))
			end := net.ParseIP(strings.TrimSpace(parts[1]))
			if start == nil || end == nil || !sameIPFamily(start, end) {
				return false
			}
			continue
		}
		if strings.Contains(value, "/") {
			if _, _, err := net.ParseCIDR(value); err != nil {
				return false
			}
			continue
		}
		if net.ParseIP(value) == nil {
			return false
		}
	}
	return true
}

func sameIPFamily(left net.IP, right net.IP) bool {
	if left == nil || right == nil {
		return false
	}
	leftIsIPv4 := left.To4() != nil
	rightIsIPv4 := right.To4() != nil
	return leftIsIPv4 == rightIsIPv4
}

func (s *Server) policyAssignmentFromPayload(payload policyAssignmentPayload, existing *models.PolicyAssignment) (*models.PolicyAssignment, string) {
	if _, ok := normalizePolicyAssignmentOrderPlacement(payload.OrderPlacement); !ok {
		return nil, "policy assignment order placement must be top, bottom, or replace"
	}
	policyID := strings.TrimSpace(payload.PolicyID)
	tenantID := strings.TrimSpace(payload.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(payload.OrganizationID)
	}
	level := normalizePolicyLayer(payload.Level)
	resourceID := strings.TrimSpace(payload.ResourceID)
	groupID := strings.TrimSpace(payload.GroupID)
	groupName := strings.TrimSpace(payload.GroupName)
	orderIndex := 0

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
		orderIndex = existing.OrderIndex
	}
	if payload.OrderIndex != nil {
		orderIndex = *payload.OrderIndex
	}
	if _, found := s.pa.Store.GetPolicyRule(policyID); !found {
		return nil, "policy not found"
	}
	if pdpstore.IsDefaultGlobalPolicyID(policyID) && (existing == nil || !pdpstore.IsDefaultGlobalAssignmentID(existing.ID)) {
		return nil, "default global policy is assigned automatically per organization"
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
		OrderIndex: orderIndex,
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
	return assignment, ""
}

func normalizePolicyAction(action string) (string, bool) {
	return models.NormalizePolicyAction(action)
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

func normalizePolicyAssignmentOrderPlacement(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", true
	case "top", "before":
		return "top", true
	case "bottom", "after":
		return "bottom", true
	case "replace":
		return "replace", true
	default:
		return "", false
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

func filterPolicyAssignmentsByOrganization(assignments []*models.PolicyAssignment, allowed map[string]bool) []*models.PolicyAssignment {
	filtered := make([]*models.PolicyAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		if assignment != nil && organizationAllowed(allowed, assignment.TenantID) {
			filtered = append(filtered, assignment)
		}
	}
	return filtered
}

func filterPolicyRulesByOrganization(rules []*models.PolicyRule, allowed map[string]bool) []*models.PolicyRule {
	filtered := make([]*models.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		assignments := filterPolicyAssignmentsByOrganization(rule.Assignments, allowed)
		if len(rule.Assignments) > 0 && len(assignments) == 0 {
			continue
		}
		copyRule := *rule
		copyRule.Assignments = assignments
		copyRule.AssignmentCount = len(assignments)
		filtered = append(filtered, &copyRule)
	}
	return filtered
}

func (s *Server) policyRuleAccessAllowed(r *http.Request, policyID string) bool {
	assignments := s.pa.Store.ListPolicyAssignmentsForPolicy(policyID)
	if len(assignments) == 0 {
		return true
	}
	return len(filterPolicyAssignmentsByOrganization(assignments, s.allowedOrganizationIDs(r))) > 0
}
