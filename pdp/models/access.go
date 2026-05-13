package models

import "time"

// ProcessIdentity is the local process context observed by the connect app.
type ProcessIdentity struct {
	PID    int    `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Signer string `json:"signer,omitempty"`
}

// AccessRequest is sent by the gateway when a user tries to access a resource.
type AccessRequest struct {
	UserID       string              `json:"user_id"`
	Username     string              `json:"username"`
	DeviceID     string              `json:"device_id"`
	SourceIP     string              `json:"source_ip"`
	Resource     string              `json:"resource"`
	TenantID     string              `json:"tenant_id,omitempty"`
	GatewayID    string              `json:"gateway_id,omitempty"`
	ResourcePort int                 `json:"resource_port"`
	Protocol     string              `json:"protocol"`
	AuthToken    string              `json:"auth_token"`
	AppID        string              `json:"app_id,omitempty"`
	Process      *ProcessIdentity    `json:"process,omitempty"`
	DeviceHealth *DeviceHealthReport `json:"device_health,omitempty"`

	AnomalyAlerts []string `json:"anomaly_alerts,omitempty"`
	AnomalyScore  int      `json:"anomaly_score,omitempty"`
}

// AccessDecision is the policy engine's response.
type AccessDecision struct {
	Decision    string   `json:"decision"`
	Reason      string   `json:"reason"`
	RiskScore   int      `json:"risk_score"`
	MatchedRule string   `json:"matched_rule"`
	Policies    []string `json:"policies"`
	SessionID   string   `json:"session_id,omitempty"`
	ExpiresAt   int64    `json:"expires_at,omitempty"`
}

// RiskContext contains all contextual information used for risk scoring.
type RiskContext struct {
	UserID             string
	SourceIP           string
	DeviceHealth       *DeviceHealthReport
	FailedAttempts     int
	IsNewDevice        bool
	IsNewLocation      bool
	TimeOfDay          time.Time
	Protocol           string
	GeoVelocity        float64
	IsImpossibleTravel bool

	AnomalyAlerts []string
	AnomalyScore  int
}
