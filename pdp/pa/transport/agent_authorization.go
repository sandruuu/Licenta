package transport

import (
	"context"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa"
)

type agentAuthorizeRequest struct {
	ResourceID string                  `json:"resource_id"`
	Protocol   string                  `json:"protocol,omitempty"`
	Port       int                     `json:"port,omitempty"`
	Process    *models.ProcessIdentity `json:"process,omitempty"`
}

type agentAuthorizeResponse struct {
	Decision          string   `json:"decision"`
	Reason            string   `json:"reason"`
	RiskSignals       []string `json:"risk_signals,omitempty"`
	MatchedRule       string   `json:"matched_rule,omitempty"`
	Policies          []string `json:"policies,omitempty"`
	SessionID         string   `json:"session_id,omitempty"`
	SessionToken      string   `json:"session_token,omitempty"`
	GatewayID         string   `json:"gateway_id,omitempty"`
	GatewayEndpoint   string   `json:"gateway_endpoint,omitempty"`
	GatewayServerName string   `json:"gateway_server_name,omitempty"`
	ResourceID        string   `json:"resource_id,omitempty"`
	Protocol          string   `json:"protocol,omitempty"`
	Port              int      `json:"port,omitempty"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	StepUpChallengeID string   `json:"step_up_challenge_id,omitempty"`
	StepUpURL         string   `json:"step_up_url,omitempty"`
	StepUpMethods     []string `json:"step_up_methods,omitempty"`
	StepUpRequiredACR string   `json:"step_up_required_acr,omitempty"`
	StepUpExpiresAt   string   `json:"step_up_expires_at,omitempty"`
}

func (s *Server) authorizeAgentResource(ctx context.Context, enrollment *models.DeviceEnrollment, certificateThumbprint, token string, req agentAuthorizeRequest, sourceIP string) (agentAuthorizeResponse, int, error) {
	if s == nil || s.pa == nil {
		return agentAuthorizeResponse{}, http.StatusServiceUnavailable, newAccessErrorForTransport("policy administrator is not available")
	}
	deviceID := ""
	if enrollment != nil {
		deviceID = enrollment.DeviceID
	}
	publicOrigin, err := s.publicOrigin()
	if err != nil {
		return agentAuthorizeResponse{}, http.StatusServiceUnavailable, newAccessErrorForTransport(err.Error())
	}
	result, err := s.pa.AuthorizeAgentResource(ctx, pa.AgentAuthorizationRequest{
		DeviceID:             deviceID,
		DeviceCertThumbprint: strings.TrimSpace(certificateThumbprint),
		UserToken:            token,
		ResourceID:           req.ResourceID,
		Protocol:             req.Protocol,
		Port:                 req.Port,
		Process:              req.Process,
		SourceIP:             sourceIP,
		PublicOrigin:         publicOrigin,
	}, s.gatewayControl)
	if err != nil {
		return agentAuthorizeResponse{}, httpStatusForAccessError(err), err
	}
	if result.SessionID != "" && result.GatewayID != "" {
		s.rememberGatewaySession(result.SessionID, result.GatewayID)
	}
	if result.Decision == models.DecisionAllow {
		s.touchAgentSessionActivity(token, deviceID, certificateThumbprint)
	}
	return agentAuthorizeResponseFromPA(result), http.StatusOK, nil
}

func agentAuthorizeResponseFromPA(response pa.AgentAuthorizationResponse) agentAuthorizeResponse {
	result := agentAuthorizeResponse{
		Decision:          response.Decision,
		Reason:            response.Reason,
		RiskSignals:       append([]string(nil), response.RiskSignals...),
		MatchedRule:       response.MatchedRule,
		Policies:          response.Policies,
		SessionID:         response.SessionID,
		SessionToken:      response.SessionToken,
		GatewayID:         response.GatewayID,
		GatewayEndpoint:   response.GatewayEndpoint,
		GatewayServerName: response.GatewayServerName,
		ResourceID:        response.ResourceID,
		Protocol:          response.Protocol,
		Port:              response.Port,
	}
	if !response.ExpiresAt.IsZero() {
		result.ExpiresAt = response.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	if response.StepUp != nil {
		result.StepUpChallengeID = response.StepUp.ChallengeID
		result.StepUpURL = response.StepUp.URL
		result.StepUpMethods = append([]string(nil), response.StepUp.Methods...)
		result.StepUpRequiredACR = response.StepUp.RequiredACR
		if !response.StepUp.ExpiresAt.IsZero() {
			result.StepUpExpiresAt = response.StepUp.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
	}
	return result
}

func httpStatusForAccessError(err error) int {
	switch pa.AccessErrorCodeOf(err) {
	case pa.AccessErrorInvalidRequest:
		return http.StatusBadRequest
	case pa.AccessErrorUnauthenticated:
		return http.StatusUnauthorized
	case pa.AccessErrorPermissionDenied:
		return http.StatusForbidden
	case pa.AccessErrorNotFound:
		return http.StatusNotFound
	case pa.AccessErrorConflict:
		return http.StatusConflict
	case pa.AccessErrorServiceUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func newAccessErrorForTransport(message string) error {
	return &pa.AccessError{Code: pa.AccessErrorServiceUnavailable, Message: message}
}
