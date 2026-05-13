package models

import "time"

// PolicyRule defines a conditional access rule.
type PolicyRule struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	Priority        int                 `json:"priority"`
	Enabled         bool                `json:"enabled"`
	AssignmentCount int                 `json:"assignment_count,omitempty"`
	Assignments     []*PolicyAssignment `json:"assignments,omitempty"`
	TenantID        string              `json:"tenant_id,omitempty"`
	Scope           string              `json:"scope,omitempty"`
	GatewayID       string              `json:"gateway_id,omitempty"`
	ResourceID      string              `json:"resource_id,omitempty"`
	Conditions      RuleConditions      `json:"conditions"`
	Action          string              `json:"action"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

// PolicyAssignment attaches a reusable policy rule to an organization,
// gateway, or resource. The policy rule defines the conditions and action;
// the assignment defines where the policy takes effect.
type PolicyAssignment struct {
	ID         string    `json:"id"`
	PolicyID   string    `json:"policy_id"`
	TenantID   string    `json:"tenant_id"`
	GatewayID  string    `json:"gateway_id,omitempty"`
	ResourceID string    `json:"resource_id,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// RuleConditions defines the conditions under which a policy rule applies.
type RuleConditions struct {
	MinHealthScore      int      `json:"min_health_score,omitempty"`
	RequiredChecks      []string `json:"required_checks,omitempty"`
	RequiredCheckStatus string   `json:"required_check_status,omitempty"`

	AllowedRoles  []string `json:"allowed_roles,omitempty"`
	AllowedUsers  []string `json:"allowed_users,omitempty"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`

	AllowedIPs []string `json:"allowed_ips,omitempty"`
	BlockedIPs []string `json:"blocked_ips,omitempty"`

	AllowedTimeStart string   `json:"allowed_time_start,omitempty"`
	AllowedTimeEnd   string   `json:"allowed_time_end,omitempty"`
	AllowedDays      []string `json:"allowed_days,omitempty"`
	Timezone         string   `json:"timezone,omitempty"`
	BlockedDates     []string `json:"blocked_dates,omitempty"`
	DateRangeStart   string   `json:"date_range_start,omitempty"`
	DateRangeEnd     string   `json:"date_range_end,omitempty"`

	TargetResources []string `json:"target_resources,omitempty"`
	TargetPorts     []int    `json:"target_ports,omitempty"`

	RequireProcessIdentity bool     `json:"require_process_identity,omitempty"`
	AllowedProcessNames    []string `json:"allowed_process_names,omitempty"`
	BlockedProcessNames    []string `json:"blocked_process_names,omitempty"`
	AllowedProcessHashes   []string `json:"allowed_process_hashes,omitempty"`
	BlockedProcessHashes   []string `json:"blocked_process_hashes,omitempty"`

	MaxRiskScore int `json:"max_risk_score,omitempty"`
}
