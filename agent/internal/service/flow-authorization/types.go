package flowauthorization

import (
	"context"
	"time"

	"agent/internal/service/enrollment"
)

const (
	DecisionAllow          = "allow"
	DecisionDeny           = "deny"
	DecisionStepUpRequired = "step_up_required"
)

type Client interface {
	AuthorizeResource(context.Context, AuthorizeRequest) (AuthorizeResponse, error)
	Close() error
}

type AuthorizeRequest struct {
	AgentSessionToken string
	ResourceID        string
	Protocol          string
	Port              int
	Process           *ProcessIdentity
}

type ProcessIdentity struct {
	PID    int
	Name   string
	Path   string
	SHA256 string
	Signer string
}

type AuthorizeResponse struct {
	Decision          string
	Reason            string
	RiskScore         int
	MatchedRule       string
	Policies          []string
	SessionID         string
	SessionToken      string
	GatewayID         string
	GatewayEndpoint   string
	GatewayServerName string
	ResourceID        string
	Protocol          string
	Port              int
	ExpiresAt         time.Time
	StepUpChallengeID string
	StepUpURL         string
	StepUpMethods     []string
	StepUpRequiredACR string
	StepUpExpiresAt   time.Time
}

type EnrollmentProvider interface {
	Record(context.Context) (enrollment.EnrollmentRecord, error)
}
