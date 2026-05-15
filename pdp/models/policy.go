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

	Conditions RuleConditions `json:"conditions"`
	Action     string         `json:"action"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// PolicyAssignment attaches a reusable policy rule to a Duo-style access layer.
// Supported levels are organization, group, resource, and resource_group.
type PolicyAssignment struct {
	ID        string `json:"id"`
	PolicyID  string `json:"policy_id"`
	TenantID  string `json:"tenant_id"`
	Level     string `json:"level"`
	GroupID   string `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`

	ResourceID string    `json:"resource_id,omitempty"`
	Priority   int       `json:"priority"`
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

	EndpointTrustPolicy             string   `json:"endpoint_trust_policy,omitempty"`
	EndpointTrustBypassIPs          []string `json:"endpoint_trust_bypass_ips,omitempty"`
	BlockCompromisedEndpoints       bool     `json:"block_compromised_endpoints,omitempty"`
	TreatMobileEndpointsDifferently bool     `json:"treat_mobile_endpoints_differently,omitempty"`
	MobileEndpointTrustPolicy       string   `json:"mobile_endpoint_trust_policy,omitempty"`

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
}
