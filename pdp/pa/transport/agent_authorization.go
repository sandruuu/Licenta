package transport

import (
	"context"
	"net/http"
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
	Decision        string   `json:"decision"`
	Reason          string   `json:"reason"`
	RiskScore       int      `json:"risk_score"`
	MatchedRule     string   `json:"matched_rule,omitempty"`
	Policies        []string `json:"policies,omitempty"`
	SessionID       string   `json:"session_id,omitempty"`
	SessionToken    string   `json:"session_token,omitempty"`
	GatewayID       string   `json:"gateway_id,omitempty"`
	GatewayEndpoint string   `json:"gateway_endpoint,omitempty"`
	ResourceID      string   `json:"resource_id,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	Port            int      `json:"port,omitempty"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
}

func (s *Server) authorizeAgentResource(ctx context.Context, enrollment *models.DeviceEnrollment, token string, req agentAuthorizeRequest, sourceIP string) (agentAuthorizeResponse, int, error) {
	if s == nil || s.pa == nil {
		return agentAuthorizeResponse{}, http.StatusServiceUnavailable, newAccessErrorForTransport("policy administrator is not available")
	}
	deviceID := ""
	if enrollment != nil {
		deviceID = enrollment.DeviceID
	}
	result, err := s.pa.AuthorizeAgentResource(ctx, pa.AgentAuthorizationRequest{
		DeviceID:   deviceID,
		UserToken:  token,
		ResourceID: req.ResourceID,
		Protocol:   req.Protocol,
		Port:       req.Port,
		Process:    req.Process,
		SourceIP:   sourceIP,
	}, s.gatewayControl)
	if err != nil {
		return agentAuthorizeResponse{}, httpStatusForAccessError(err), err
	}
	if result.SessionID != "" && result.GatewayID != "" {
		s.rememberGatewaySession(result.SessionID, result.GatewayID)
	}
	return agentAuthorizeResponseFromPA(result), http.StatusOK, nil
}

func agentAuthorizeResponseFromPA(response pa.AgentAuthorizationResponse) agentAuthorizeResponse {
	result := agentAuthorizeResponse{
		Decision:        response.Decision,
		Reason:          response.Reason,
		RiskScore:       response.RiskScore,
		MatchedRule:     response.MatchedRule,
		Policies:        response.Policies,
		SessionID:       response.SessionID,
		SessionToken:    response.SessionToken,
		GatewayID:       response.GatewayID,
		GatewayEndpoint: response.GatewayEndpoint,
		ResourceID:      response.ResourceID,
		Protocol:        response.Protocol,
		Port:            response.Port,
	}
	if !response.ExpiresAt.IsZero() {
		result.ExpiresAt = response.ExpiresAt.UTC().Format(time.RFC3339Nano)
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
