package transport

import (
	"context"
	"encoding/json"
	"io"
	"net"
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

func (s *Server) handleAgentAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	enrollment, ok := deviceEnrollmentFromContext(r)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device identity not found in request context"})
		return
	}
	token, err := bearerToken(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization bearer token required"})
		return
	}
	var req agentAuthorizeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	response, statusCode, err := s.authorizeAgentResource(r.Context(), enrollment, token, req, sourceIPForPolicy(r))
	if err != nil {
		writeJSON(w, statusCode, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response)
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

func sourceIPForPolicy(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		return strings.TrimSpace(strings.SplitN(forwarded, ",", 2)[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
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
