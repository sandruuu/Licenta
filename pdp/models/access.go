package models

// ProcessIdentity is the local endpoint process context observed by TrustAgent.
type ProcessIdentity struct {
	PID    int    `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Signer string `json:"signer,omitempty"`
}

// AccessRequest is sent by the gateway when a user tries to access a resource.
type AccessRequest struct {
	UserID         string              `json:"user_id"`
	Username       string              `json:"username"`
	DeviceID       string              `json:"device_id"`
	SourceIP       string              `json:"source_ip"`
	Resource       string              `json:"resource"`
	OrganizationID string              `json:"organization_id,omitempty"`
	GatewayID      string              `json:"gateway_id,omitempty"`
	ResourcePort   int                 `json:"resource_port"`
	Protocol       string              `json:"protocol"`
	AuthToken      string              `json:"auth_token"`
	AppID          string              `json:"app_id,omitempty"`
	Process        *ProcessIdentity    `json:"process,omitempty"`
	DeviceHealth   *DeviceHealthReport `json:"device_health,omitempty"`

	AnomalyAlerts []string `json:"anomaly_alerts,omitempty"`
}

// AccessDecision is the policy engine's response.
type AccessDecision struct {
	Decision         string                `json:"decision"`
	Reason           string                `json:"reason"`
	RiskSignals      []string              `json:"risk_signals,omitempty"`
	AccessConditions AccessConditions      `json:"access_conditions,omitempty"`
	SessionControls  SessionPolicyControls `json:"session_controls,omitempty"`
	MatchedRule      string                `json:"matched_rule"`
	Policies         []string              `json:"policies"`
	SessionID        string                `json:"session_id,omitempty"`
	ExpiresAt        int64                 `json:"expires_at,omitempty"`
	StepUp           *StepUpRequirement    `json:"step_up,omitempty"`
}
