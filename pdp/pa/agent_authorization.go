package pa

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa/auth"
	"pdp/pa/catalog"
	pagateway "pdp/pa/gateway"
)

type AgentAuthorizationRequest struct {
	DeviceID             string
	DeviceCertThumbprint string
	UserToken            string
	ResourceID           string
	Protocol             string
	Port                 int
	Process              *models.ProcessIdentity
	SourceIP             string
	PublicOrigin         string
}

type AgentAuthorizationResponse struct {
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
	StepUp            *models.StepUpRequirement
}

type GatewayProvisionedSession = pagateway.ProvisionedSession

type AgentGatewayProvisioner interface {
	ConnectedGatewayIDs() []string
	ProvisionSession(ctx context.Context, gatewayID string, session GatewayProvisionedSession) error
}

type resolvedAgentAuthorization struct {
	resource *models.Resource
	gateway  *models.Gateway
	protocol string
	port     int
}

func (pa *PolicyAdministrator) AuthorizeAgentResource(ctx context.Context, req AgentAuthorizationRequest, provisioner AgentGatewayProvisioner) (AgentAuthorizationResponse, error) {
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorPermissionDenied, "device identity is required", nil)
	}
	claims, err := pa.ValidateDeviceUserTokenBoundForScope(req.UserToken, deviceID, req.DeviceCertThumbprint, "flow:authorize")
	if err != nil {
		return AgentAuthorizationResponse{}, err
	}
	resolved, err := pa.resolveAgentAuthorization(req, claims)
	if err != nil {
		return AgentAuthorizationResponse{}, err
	}

	accessReq := models.AccessRequest{
		UserID:         claims.UserID,
		Username:       claims.Username,
		DeviceID:       deviceID,
		SourceIP:       strings.TrimSpace(req.SourceIP),
		Resource:       resolved.resource.ID,
		OrganizationID: resolved.resource.OrganizationID,
		GatewayID:      resolved.gateway.ID,
		ResourcePort:   resolved.port,
		Protocol:       resolved.protocol,
		AuthToken:      strings.TrimSpace(req.UserToken),
		AppID:          resolved.resource.ID,
		Process:        req.Process,
	}
	if pa != nil && pa.Store != nil {
		if deviceData, ok := pa.Store.GetDeviceData(deviceID); ok {
			accessReq.DeviceHealth = DeviceHealthFromData(deviceData)
		}
	}

	authCtx := models.AuthContext{
		ACR: strings.TrimSpace(claims.ACR),
		AMR: append([]string(nil), claims.AMR...),
	}
	if pa != nil && pa.StepUps != nil {
		if completed := pa.StepUps.AuthContext(claims.SessionID, claims.UserID, deviceID, resolved.resource.ID, time.Now().UTC()); completed.ACR != "" {
			authCtx = completed
		}
	}
	decision := pa.EvaluateAccessWithAuth(accessReq, authCtx)
	if decision == nil {
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorInternal, "policy decision failed", nil)
	}
	if decision.Decision != models.DecisionAllow {
		if decision.Decision == models.DecisionStepUpRequired {
			if err := pa.attachStepUpChallenge(decision, req, claims, resolved.resource); err != nil {
				log.Printf("[AGENT-AUTHZ] Failed to create step-up challenge: device=%s resource=%s err=%v", deviceID, resolved.resource.ID, err)
			}
		}
		pa.auditAgentAuthorization(accessReq, decision, false)
		return agentAuthorizationResponseFromDecision(decision), nil
	}

	gateway, endpoint, err := pa.connectedGatewayForResource(resolved.resource, provisioner)
	if err != nil {
		return AgentAuthorizationResponse{}, err
	}
	session, reusedSession, err := pa.Sessions.CreateOrRenewSession(decision, accessReq, pa.resourceSessionRenewBefore())
	if err != nil {
		log.Printf("[AGENT-AUTHZ] Failed to create or renew PA session: %v", err)
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorInternal, "failed to create session", err)
	}
	sessionToken, err := generateSessionToken()
	if err != nil {
		if !reusedSession {
			_ = pa.Sessions.RevokeSession(session.ID)
		}
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
		if !reusedSession {
			_ = pa.Sessions.RevokeSession(session.ID)
		}
		log.Printf("[AGENT-AUTHZ] Failed to provision Gateway session: gateway=%s session=%s err=%v", gateway.ID, session.ID, err)
		return AgentAuthorizationResponse{}, newAccessError(AccessErrorConflict, "gateway is not ready for session provisioning", err)
	}

	decision.SessionID = session.ID
	decision.ExpiresAt = session.ExpiresAt.Unix()
	pa.auditAgentAuthorization(accessReq, decision, true)
	pa.recordAccessLocation(accessReq)

	response := agentAuthorizationResponseFromDecision(decision)
	response.SessionID = session.ID
	response.SessionToken = sessionToken
	response.GatewayID = gateway.ID
	response.GatewayEndpoint = endpoint
	response.GatewayServerName = strings.TrimSpace(gateway.FQDN)
	response.ResourceID = resolved.resource.ID
	response.Protocol = resolved.protocol
	response.Port = resolved.port
	response.ExpiresAt = session.ExpiresAt
	return response, nil
}

func (pa *PolicyAdministrator) attachStepUpChallenge(decision *models.AccessDecision, req AgentAuthorizationRequest, claims *auth.CustomClaims, resource *models.Resource) error {
	if pa == nil || pa.StepUps == nil || decision == nil || claims == nil || resource == nil {
		return fmt.Errorf("step-up services are not available")
	}
	requirement := decision.StepUp
	if requirement == nil {
		requirement = &models.StepUpRequirement{}
		decision.StepUp = requirement
	}
	challenge, err := pa.StepUps.CreateChallenge(StepUpChallengeRequest{
		AgentSessionID: strings.TrimSpace(claims.SessionID),
		UserID:         strings.TrimSpace(claims.UserID),
		Username:       strings.TrimSpace(claims.Username),
		OrganizationID: strings.TrimSpace(resource.OrganizationID),
		DeviceID:       strings.TrimSpace(req.DeviceID),
		ResourceID:     strings.TrimSpace(resource.ID),
		PolicyID:       strings.TrimSpace(decision.MatchedRule),
		PublicOrigin:   strings.TrimSpace(req.PublicOrigin),
		Requirement:    requirement,
	})
	if err != nil {
		return err
	}
	if pa.Audit != nil {
		details := "Additional verification required for resource access"
		pa.Audit.LogEvent("agent_step_up_required", claims.UserID, claims.Username, strings.TrimSpace(req.SourceIP),
			resource.ID, models.DecisionStepUpRequired, details, true)
	}
	requirement.ChallengeID = challenge.ID
	requirement.URL = challenge.URL
	requirement.Methods = append([]string(nil), challenge.Methods...)
	requirement.MinStrength = challenge.MinStrength
	requirement.WebAuthnAttachment = challenge.WebAuthnAttachment
	requirement.AllowedAAGUIDs = append([]string(nil), challenge.AllowedAAGUIDs...)
	requirement.RequiredACR = challenge.RequiredACR
	requirement.MaxAgeSeconds = challenge.MaxAgeSeconds
	requirement.ExpiresAt = challenge.ExpiresAt
	requirement.PolicyID = challenge.PolicyID
	requirement.ResourceID = challenge.ResourceID
	return nil
}

func (pa *PolicyAdministrator) ValidateDeviceUserToken(token, deviceID string) (*auth.CustomClaims, error) {
	return pa.ValidateDeviceUserTokenBoundForScope(token, deviceID, "", "flow:authorize")
}

func (pa *PolicyAdministrator) ValidateDeviceUserTokenBoundForScope(token, deviceID, certificateThumbprint, requiredScope string) (*auth.CustomClaims, error) {
	return pa.validateDeviceUserTokenBound(token, deviceID, certificateThumbprint, requiredScope)
}

func (pa *PolicyAdministrator) validateDeviceUserTokenBound(token, deviceID, certificateThumbprint, requiredScope string) (*auth.CustomClaims, error) {
	if pa == nil || pa.Auth == nil || pa.Auth.JWT == nil || pa.Store == nil {
		return nil, newAccessError(AccessErrorServiceUnavailable, "identity services are not available", nil)
	}
	trimmedToken := strings.TrimSpace(token)
	claims, err := pa.Auth.JWT.ParseAuthTokenForAudience(trimmedToken, auth.AgentSessionAudience)
	if err != nil || claims == nil {
		return nil, newAccessError(AccessErrorUnauthenticated, "invalid or expired agent session token", err)
	}
	if claims.Purpose != auth.AgentSessionPurpose {
		return nil, newAccessError(AccessErrorUnauthenticated, "invalid agent session token purpose", nil)
	}
	if expected := strings.ToLower(strings.TrimSpace(certificateThumbprint)); expected != "" {
		if agentSessionCertificateThumbprint(claims) != expected {
			return nil, newAccessError(AccessErrorPermissionDenied, "agent session token is not bound to the mTLS device certificate", nil)
		}
	}
	if scope := strings.TrimSpace(requiredScope); scope != "" && !agentSessionHasScope(claims, scope) {
		return nil, newAccessError(AccessErrorPermissionDenied, "agent session token is missing required scope "+scope, nil)
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
	user, exists := pa.Auth.Users.GetUser(claims.UserID)
	if !exists || user.Disabled {
		return nil, newAccessError(AccessErrorPermissionDenied, "user is not allowed to request catalog", nil)
	}
	claims.Role = user.Role
	return claims, nil
}

func agentSessionCertificateThumbprint(claims *auth.CustomClaims) string {
	if claims == nil {
		return ""
	}
	if claims.Confirmation != nil {
		if thumbprint := strings.ToLower(strings.TrimSpace(claims.Confirmation.CertificateThumbprintSHA256)); thumbprint != "" {
			return thumbprint
		}
	}
	return strings.ToLower(strings.TrimSpace(claims.CertificateThumbprintSHA256))
}

func agentSessionHasScope(claims *auth.CustomClaims, requiredScope string) bool {
	if claims == nil {
		return false
	}
	requiredScope = strings.TrimSpace(requiredScope)
	if requiredScope == "" {
		return true
	}
	for _, scope := range claims.Scopes {
		if strings.EqualFold(strings.TrimSpace(scope), requiredScope) {
			return true
		}
	}
	return false
}

func (pa *PolicyAdministrator) resolveAgentAuthorization(req AgentAuthorizationRequest, claims *auth.CustomClaims) (resolvedAgentAuthorization, error) {
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
	if strings.TrimSpace(resource.OrganizationID) == "" {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorConflict, "resource has no organization assignment", nil)
	}
	if strings.TrimSpace(resource.GatewayID) == "" {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorConflict, "resource has no gateway assignment", nil)
	}
	gateway, ok := pa.Store.GetGateway(resource.GatewayID)
	if !ok || gateway == nil {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorConflict, "resource gateway not found", nil)
	}
	if strings.TrimSpace(gateway.OrganizationID) == "" || !strings.EqualFold(gateway.OrganizationID, resource.OrganizationID) {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorConflict, "resource gateway belongs to a different organization", nil)
	}
	user, ok := pa.Store.GetUser(claims.UserID)
	if !ok || user == nil || user.Disabled {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorPermissionDenied, "user is not allowed to access resources", nil)
	}
	if strings.TrimSpace(user.OrganizationID) == "" || !strings.EqualFold(user.OrganizationID, resource.OrganizationID) {
		return resolvedAgentAuthorization{}, newAccessError(AccessErrorPermissionDenied, "resource is outside the user's organization", nil)
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
	return resolvedAgentAuthorization{resource: resource, gateway: gateway, protocol: protocol, port: port}, nil
}

func (pa *PolicyAdministrator) connectedGatewayForResource(resource *models.Resource, provisioner AgentGatewayProvisioner) (*models.Gateway, string, error) {
	if pa == nil || pa.Store == nil || provisioner == nil {
		return nil, "", newAccessError(AccessErrorConflict, "gateway control plane is not available", nil)
	}
	if resource == nil || strings.TrimSpace(resource.GatewayID) == "" {
		return nil, "", newAccessError(AccessErrorConflict, "resource has no gateway assignment", nil)
	}
	connected := make(map[string]struct{})
	for _, gatewayID := range provisioner.ConnectedGatewayIDs() {
		connected[strings.TrimSpace(gatewayID)] = struct{}{}
	}
	gateway, found := pa.Store.GetGateway(resource.GatewayID)
	if !found || gateway == nil || gateway.Status != "enrolled" {
		return nil, "", newAccessError(AccessErrorConflict, "resource gateway is not enrolled", nil)
	}
	if strings.TrimSpace(gateway.OrganizationID) == "" || !strings.EqualFold(gateway.OrganizationID, resource.OrganizationID) {
		return nil, "", newAccessError(AccessErrorConflict, "resource gateway organization mismatch", nil)
	}
	if _, ok := connected[gateway.ID]; !ok {
		return nil, "", newAccessError(AccessErrorConflict, "assigned gateway is not connected", nil)
	}
	endpoint := firstNonEmptyString(gateway.ListenAddr, gateway.FQDN)
	if endpoint == "" {
		return nil, "", newAccessError(AccessErrorConflict, fmt.Sprintf("connected gateway %s has no endpoint", gateway.ID), nil)
	}
	return gateway, endpoint, nil
}

func DeviceHealthFromData(report *models.DeviceDataReport) *models.DeviceHealthReport {
	if report == nil {
		return nil
	}
	score := 100
	if len(report.Checks) > 0 {
		points := 0
		for _, check := range report.Checks {
			switch strings.ToLower(strings.TrimSpace(check.Status)) {
			case "good", "ok", "pass", "passed", "healthy":
				points += 100
			case "warning":
				points += 70
			case "unavailable", "unknown":
				points += 50
			default:
				points += 0
			}
		}
		score = points / len(report.Checks)
	}
	return &models.DeviceHealthReport{
		DeviceID:       report.DeviceID,
		Hostname:       report.Hostname,
		OS:             report.OS,
		Checks:         append([]models.HealthCheck(nil), report.Checks...),
		OverallScore:   score,
		ReportedAt:     report.ReportedAt,
		OrganizationID: report.OrganizationID,
	}
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
		return false
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
		StepUp:      decision.StepUp,
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

func (pa *PolicyAdministrator) recordAccessLocation(req models.AccessRequest) {
	if pa == nil || pa.Geo == nil || strings.TrimSpace(req.UserID) == "" || strings.TrimSpace(req.SourceIP) == "" {
		return
	}
	pa.Geo.SaveCurrentLocation(req.UserID, req.SourceIP)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (pa *PolicyAdministrator) resourceSessionRenewBefore() time.Duration {
	if pa == nil || pa.Cfg == nil {
		return time.Minute
	}
	if pa.Cfg.Runtime.ResourceSessionRenewBefore <= 0 {
		return time.Minute
	}
	return pa.Cfg.Runtime.ResourceSessionRenewBefore
}
