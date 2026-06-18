package models

import "time"

// PolicyRule defines a conditional access rule.
type PolicyRule struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
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
	ID             string `json:"id"`
	PolicyID       string `json:"policy_id"`
	OrganizationID string `json:"organization_id"`
	Level          string `json:"level"`
	GroupID        string `json:"group_id,omitempty"`
	GroupName      string `json:"group_name,omitempty"`
	OrderIndex     int    `json:"order_index"`

	ResourceID string    `json:"resource_id,omitempty"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// RuleConditions defines the conditions under which a policy rule applies.
type RuleConditions struct {
	AccessConditions AccessConditions `json:"access_conditions,omitempty"`
	AccessMatchMode  string           `json:"access_match_mode,omitempty"`

	Risk           RiskPolicyConditions           `json:"risk,omitempty"`
	RiskBasedAuth  RiskBasedAuthPolicyConditions  `json:"risk_based_authentication,omitempty"`
	User           UserPolicyConditions           `json:"user,omitempty"`
	UserLocation   UserLocationPolicyConditions   `json:"user_location,omitempty"`
	Network        NetworkPolicyConditions        `json:"network,omitempty"`
	Authentication AuthenticationPolicyConditions `json:"authentication,omitempty"`
	DevicePosture  DevicePosturePolicyConditions  `json:"device_posture,omitempty"`
	Session        SessionPolicyControls          `json:"session,omitempty"`

	AllowedRoles  []string `json:"allowed_roles,omitempty"`
	AllowedUsers  []string `json:"allowed_users,omitempty"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`

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

// RiskPolicyConditions lets a policy match explicit contextual risk signals.
// Risk conditions match concrete signals observed during the access request.
type RiskPolicyConditions struct {
	Signals []string `json:"signals,omitempty"`
}

// RiskBasedAuthPolicyConditions enables adaptive MFA based on internal risk
// detectors such as new locations, unrealistic travel, and user baseline
// anomalies.
type RiskBasedAuthPolicyConditions struct {
	RequireMFAOnRisk bool     `json:"require_mfa_on_risk,omitempty"`
	Signals          []string `json:"signals,omitempty"`
	MatchMode        string   `json:"match_mode,omitempty"`
}

// UserPolicyConditions captures Duo-style user enrollment behavior.
type UserPolicyConditions struct {
	NewUserPolicy string `json:"new_user_policy,omitempty"`
}

// UserLocationPolicyConditions captures Duo-style country rules for access
// device geolocation.
type UserLocationPolicyConditions struct {
	Rules                 []UserLocationRule `json:"rules,omitempty"`
	DefaultAction         string             `json:"default_action,omitempty"`
	UnknownLocationAction string             `json:"unknown_location_action,omitempty"`
	CheckMode             string             `json:"check_mode,omitempty"`
}

type UserLocationRule struct {
	Countries []string `json:"countries,omitempty"`
	Action    string   `json:"action,omitempty"`
}

// NetworkPolicyConditions captures network scopes separately from user,
// device, and authentication policy settings.
type NetworkPolicyConditions struct {
	AllowedCIDRs                      []string `json:"allowed_cidrs,omitempty"`
	SkipMFACIDRs                      []string `json:"skip_mfa_cidrs,omitempty"`
	RequireMFACIDRs                   []string `json:"require_mfa_cidrs,omitempty"`
	BlockedCIDRs                      []string `json:"blocked_cidrs,omitempty"`
	DenyOtherNetworks                 bool     `json:"deny_other_networks,omitempty"`
	RequireEnrollmentFromSkipNetworks bool     `json:"require_enrollment_from_skip_networks,omitempty"`
	AllowAllNetworks                  bool     `json:"allow_all_networks,omitempty"`
}

// AuthenticationPolicyConditions defines Duo-style authentication behavior and
// the MFA methods available when step-up is required.
type AuthenticationPolicyConditions struct {
	Policy        string   `json:"policy,omitempty"`
	StepUpMethods []string `json:"step_up_methods,omitempty"`
}

// DevicePosturePolicyConditions captures required endpoint health checks.
type DevicePosturePolicyConditions struct {
	RequiredChecks  []string `json:"required_checks,omitempty"`
	RequiredStatus  string   `json:"required_status,omitempty"`
	StaleDataAction string   `json:"stale_data_action,omitempty"`
}

// SessionPolicyControls are evaluated/applied by the access workflow when a
// matching rule creates or renews an access session.
type SessionPolicyControls struct {
	MaxAgeSeconds          int  `json:"max_age_seconds,omitempty"`
	RevalidateEverySeconds int  `json:"revalidate_every_seconds,omitempty"`
	RevokeOnPostureChange  bool `json:"revoke_on_posture_change,omitempty"`
}

// AccessConditions are the contextual conditions that can trigger a policy.
// Keep this intentionally small so policy authors only configure the access
// contexts supported by the product.
type AccessConditions struct {
	Location LocationAccessConditions `json:"location,omitempty"`
}

type LocationAccessConditions struct {
	NewLocation         bool `json:"new_location,omitempty"`
	ImpossibleTravel    bool `json:"impossible_travel,omitempty"`
	UserBaselineAnomaly bool `json:"user_baseline_anomaly,omitempty"`
}

func (c AccessConditions) Empty() bool {
	return !c.Location.NewLocation &&
		!c.Location.ImpossibleTravel &&
		!c.Location.UserBaselineAnomaly
}

func (c AccessConditions) IsZero() bool {
	return c.Empty()
}
