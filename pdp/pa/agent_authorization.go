package pa

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/idp"
	"pdp/models"
	"pdp/pa/catalog"
	pagateway "pdp/pa/gateway"
)

type AgentAuthorizationRequest struct {
	DeviceID   string
	UserToken  string
	ResourceID string
	Protocol   string
	Port       int
	Process    *models.ProcessIdentity
	SourceIP   string
}

type AgentAuthorizationResponse struct {
	Decision        string
	Reason          string
	RiskScore       int
	MatchedRule     string
	Policies        []string
	SessionID       string
	SessionToken    string
	GatewayID       string
	GatewayEndpoint string
	ResourceID      string
	Protocol        string
	Port            int
	ExpiresAt       time.Time
}

type GatewayProvisionedSession = pagateway.ProvisionedSession

type AgentGatewayProvisioner interface {
	ConnectedGatewayIDs() []string
	ProvisionSession(ctx context.Context, gatewayID string, session GatewayProvisionedSession) error
}

type resolvedAgentAuthorization struct {
	resource *models.Resource
	protocol string
	port     int
}

func (pa *PolicyAdministrator) AuthorizeAgentResource(ctx context.Context, req AgentAuthorizationRequest, provisioner AgentGatewayProvisioner) (AgentAuthorizationResponse, error) {
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorPermissionDenied, "device identity is required", nil)
	}
	claims, err := pa.ValidateDeviceUserToken(req.UserToken, deviceID)
	if err != nil {
		return AgentAuthorizationResponse{}, err
	}
	resolved, err := pa.resolveAgentAuthorization(req, claims)
	if err != nil {
		return AgentAuthorizationResponse{}, err
	}

	accessReq := models.AccessRequest{
		UserID:       claims.UserID,
		Username:     claims.Username,
		DeviceID:     deviceID,
		SourceIP:     strings.TrimSpace(req.SourceIP),
		Resource:     resolved.resource.ID,
		ResourcePort: resolved.port,
		Protocol:     resolved.protocol,
		AuthToken:    strings.TrimSpace(req.UserToken),
		AppID:        resolved.resource.ID,
		Process:      req.Process,
	}
	if pa != nil && pa.Store != nil {
		if health, ok := pa.Store.GetDeviceHealth(deviceID); ok {
			accessReq.DeviceHealth = health
		}
	}

	decision := pa.EvaluateAccess(accessReq)
	if decision == nil {
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorInternal, "policy decision failed", nil)
	}
	if decision.Decision != "allow" {
		pa.auditAgentAuthorization(accessReq, decision, false)
		return agentAuthorizationResponseFromDecision(decision), nil
	}

	gateway, endpoint, err := pa.connectedGatewayForResource(resolved.resource.ID, provisioner)
	if err != nil {
		return AgentAuthorizationResponse{}, err
	}
	session, err := pa.Sessions.CreateSession(decision, accessReq)
	if err != nil {
		log.Printf("[AGENT-AUTHZ] Failed to create PA session: %v", err)
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorInternal, "failed to create session", err)
	}
	sessionToken, err := generateSessionToken()
	if err != nil {
		_ = pa.Sessions.RevokeSession(session.ID)
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorInternal, "failed to generate session token", err)
	}

	provision := pagateway.ProvisionedSession{
		ID:            session.ID,
		SessionToken:  sessionToken,
		DeviceID:      deviceID,
		UserID:        claims.UserID,
		Username:      claims.Username,
		ResourceID:    resolved.resource.ID,
		ResourceName:  resolved.resource.Name,
		InternalHost:  resolved.resource.Host,
		InternalPort:  resolved.port,
		Protocol:      resolved.protocol,
		ExpiresAt:     session.ExpiresAt,
		Constraints:   agentAuthorizationConstraints(decision),
		PolicyVersion: strings.TrimSpace(decision.MatchedRule),
	}
	if err := provisioner.ProvisionSession(ctx, gateway.ID, provision); err != nil {
		_ = pa.Sessions.RevokeSession(session.ID)
		log.Printf("[AGENT-AUTHZ] Failed to provision Gateway session: gateway=%s session=%s err=%v", gateway.ID, session.ID, err)
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorConflict, "gateway is not ready for session provisioning", err)
	}

	decision.SessionID = session.ID
	decision.ExpiresAt = session.ExpiresAt.Unix()
	pa.auditAgentAuthorization(accessReq, decision, true)

	response := agentAuthorizationResponseFromDecision(decision)
	response.SessionID = session.ID
	response.SessionToken = sessionToken
	response.GatewayID = gateway.ID
	response.GatewayEndpoint = endpoint
	response.ResourceID = resolved.resource.ID
	response.Protocol = resolved.protocol
	response.Port = resolved.port
	response.ExpiresAt = session.ExpiresAt
	return response, nil
}

func (pa *PolicyAdministrator) ValidateDeviceUserToken(token, deviceID string) (*idp.CustomClaims, error) {
	if pa == nil || pa.IdP == nil || pa.IdP.JWT == nil || pa.Store == nil {
		return nil, newAccessError(AccessErrorServiceUnavailable, "identity services are not available", nil)
	}
	claims, err := pa.IdP.JWT.ParseAuthTokenForAudience(strings.TrimSpace(token), "ztna-gateway")
	if err != nil || claims == nil || claims.Purpose != "" {
		return nil, newAccessError(AccessErrorUnauthenticated, "invalid or expired user token", err)
	}
	if claims.ID != "" && pa.Store.IsTokenRevoked(claims.ID) {
		return nil, newAccessError(AccessErrorUnauthenticated, "token has been revoked", nil)
	}
	if strings.TrimSpace(claims.DeviceID) == "" {
		return nil, newAccessError(AccessErrorPermissionDenied, "user token is not bound to a device_id", nil)
	}
	if strings.TrimSpace(deviceID) != "" && claims.DeviceID != strings.TrimSpace(deviceID) {
		return nil, newAccessError(AccessErrorPermissionDenied, "user token device_id does not match mTLS device identity", nil)
	}
	user, exists := pa.IdP.Users.GetUser(claims.UserID)
	if !exists || user.Disabled {
		return nil, newAccessError(AccessErrorPermissionDenied, "user is not allowed to request catalog", nil)
	}
	claims.Role = user.Role
	return claims, nil
}

func (pa *PolicyAdministrator) resolveAgentAuthorization(req AgentAuthorizationRequest, claims *idp.CustomClaims) (resolvedAgentAuthorization, error) {
	if claims == nil {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorUnauthenticated, "invalid or expired user token", nil)
	}
	resourceID := strings.TrimSpace(req.ResourceID)
	if resourceID == "" {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorInvalidRequest, "resource_id is required", nil)
	}
	if pa == nil || pa.Store == nil {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorServiceUnavailable, "resource store is not available", nil)
	}
	resource, ok := pa.Store.GetResource(resourceID)
	if !ok || resource == nil || !resource.Enabled {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorNotFound, "resource not found or disabled", nil)
	}
	if !ResourceVisibleForRole(resource, claims.Role) {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorPermissionDenied, "resource is not available to this user", nil)
	}

	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if protocol == "" {
		protocol = ResourceProtocol(resource)
	}
	resourceProtocol := ResourceProtocol(resource)
	if !strings.EqualFold(protocol, resourceProtocol) {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorInvalidRequest, fmt.Sprintf("protocol must be %s", resourceProtocol), nil)
	}
	port := req.Port
	resourcePort := ResourcePort(resource, resourceProtocol)
	if port == 0 {
		port = resourcePort
	}
	if port <= 0 || resourcePort <= 0 || port != resourcePort {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorInvalidRequest, fmt.Sprintf("port must be %d", resourcePort), nil)
	}
	return resolvedAgentAuthorization{resource: resource, protocol: protocol, port: port}, nil
}

func (pa *PolicyAdministrator) connectedGatewayForResource(resourceID string, provisioner AgentGatewayProvisioner) (*models.Gateway, string, error) {
	if pa == nil || pa.Store == nil || provisioner == nil {
		return nil, "", newAccessError(AccessErrorConflict, "gateway control plane is not available", nil)
	}
	connected := make(map[string]struct{})
	for _, gatewayID := range provisioner.ConnectedGatewayIDs() {
		connected[strings.TrimSpace(gatewayID)] = struct{}{}
	}
	for _, gateway := range pa.Store.ListGateways() {
		if gateway == nil || gateway.Status != "enrolled" {
			continue
		}
		if !GatewayServesResource(gateway, resourceID) {
			continue
		}
		if _, ok := connected[gateway.ID]; !ok {
			continue
		}
		endpoint := firstNonEmptyString(gateway.ListenAddr, gateway.FQDN)
		if endpoint == "" {
			return nil, "", newAccessError(AccessErrorConflict, fmt.Sprintf("connected gateway %s has no endpoint", gateway.ID), nil)
		}
		return gateway, endpoint, nil
	}
	return nil, "", newAccessError(AccessErrorConflict, "no connected gateway is assigned to the requested resource", nil)
}

func ResourceVisibleForRole(resource *models.Resource, role string) bool {
	return catalog.ResourceVisibleForRole(resource, role)
}

func ResourceProtocol(resource *models.Resource) string {
	return catalog.ResourceProtocol(resource)
}

func ResourcePort(resource *models.Resource, protocol string) int {
	return catalog.ResourcePort(resource, protocol)
}

func GatewayServesResource(gateway *models.Gateway, resourceID string) bool {
	if gateway == nil {
		return false
	}
	if len(gateway.AssignedResources) == 0 {
		return true
	}
	for _, assigned := range gateway.AssignedResources {
		if strings.TrimSpace(assigned) == strings.TrimSpace(resourceID) {
			return true
		}
	}
	return false
}

func agentAuthorizationResponseFromDecision(decision *models.AccessDecision) AgentAuthorizationResponse {
	if decision == nil {
		return AgentAuthorizationResponse{}
	}
	return AgentAuthorizationResponse{
		Decision:    decision.Decision,
		Reason:      decision.Reason,
		RiskScore:   decision.RiskScore,
		MatchedRule: decision.MatchedRule,
		Policies:    decision.Policies,
	}
}

func generateSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func agentAuthorizationConstraints(decision *models.AccessDecision) []string {
	if decision == nil {
		return nil
	}
	constraints := make([]string, 0, len(decision.Policies)+1)
	if decision.MatchedRule != "" {
		constraints = append(constraints, "policy:"+decision.MatchedRule)
	}
	for _, policy := range decision.Policies {
		if strings.TrimSpace(policy) != "" {
			constraints = append(constraints, "resource:"+strings.TrimSpace(policy))
		}
	}
	return constraints
}

func (pa *PolicyAdministrator) auditAgentAuthorization(req models.AccessRequest, decision *models.AccessDecision, success bool) {
	if pa == nil || pa.Audit == nil || decision == nil {
		return
	}
	pa.Audit.LogEvent("agent_access_request", req.UserID, req.Username, req.SourceIP, req.Resource, decision.Decision, decision.Reason, success)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
