package enforcement

import (
	"context"
	"fmt"
	"log"
	"strings"

	"pdp/models"
	paadmin "pdp/pa"
	"pdp/pa/events"
)

// Service consumes PA state-change events and turns them into continuous
// enforcement actions against already-issued resource sessions.
type Service struct {
	pa     *paadmin.PolicyAdministrator
	broker *events.Broker
}

func NewService(policyAdmin *paadmin.PolicyAdministrator, broker *events.Broker) *Service {
	return &Service{pa: policyAdmin, broker: broker}
}

func (service *Service) Start(ctx context.Context) {
	if service == nil || service.broker == nil {
		return
	}
	sub := service.broker.Subscribe(
		events.TopicHealthChanged,
		events.TopicPolicyUpdated,
		events.TopicResourcesUpdated,
		events.TopicDeviceRevoked,
		events.TopicGatewayRevoked,
	)
	go func() {
		defer service.broker.Unsubscribe(sub)
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-sub.C:
				if !ok {
					return
				}
				service.HandleEvent(evt)
			}
		}
	}()
}

// HandleEvent is exported for deterministic tests; Start uses the same path for
// asynchronous broker delivery in production.
func (service *Service) HandleEvent(evt events.Event) int {
	if service == nil || service.pa == nil || service.pa.Sessions == nil {
		return 0
	}
	switch evt.Type {
	case events.TopicHealthChanged:
		return service.handleHealthChanged(evt)
	case events.TopicPolicyUpdated:
		return service.handlePolicyUpdated(evt)
	case events.TopicResourcesUpdated:
		return service.handleResourceUpdated(evt)
	case events.TopicDeviceRevoked:
		return service.handleDeviceRevoked(evt)
	case events.TopicGatewayRevoked:
		return service.handleGatewayRevoked(evt)
	default:
		return 0
	}
}

func (service *Service) handleHealthChanged(evt events.Event) int {
	deviceID := eventField(evt, "device_id")
	if deviceID == "" {
		return 0
	}
	organizationID := eventField(evt, "organization_id")
	return service.pa.Sessions.RevokeSessionsMatching("device_posture_changed", func(session *models.Session) bool {
		if session == nil {
			return false
		}
		if strings.TrimSpace(session.DeviceID) != deviceID {
			return false
		}
		if organizationID != "" && strings.TrimSpace(session.OrganizationID) != organizationID {
			return false
		}
		allowed, denyReason := service.sessionStillAllowed(session)
		if allowed {
			return false
		}
		if !healthChangedRevocationApplies(session, denyReason) {
			return false
		}
		service.auditContinuousRevocation(session, "device_posture_changed", denyReason)
		return true
	})
}

func healthChangedRevocationApplies(session *models.Session, denyReason string) bool {
	if session != nil && session.RevokeOnPostureChange {
		return true
	}
	return strings.Contains(strings.ToLower(denyReason), "device health")
}

func (service *Service) handlePolicyUpdated(evt events.Event) int {
	organizationID := eventField(evt, "organization_id")
	resourceID := eventField(evt, "resource_id")
	return service.revokeSessionsNoLongerAllowed("policy_updated", func(session *models.Session) bool {
		if resourceID != "" && strings.TrimSpace(session.Resource) != resourceID {
			return false
		}
		return organizationID == "" || strings.TrimSpace(session.OrganizationID) == organizationID
	})
}

func (service *Service) handleResourceUpdated(evt events.Event) int {
	resourceID := eventField(evt, "resource_id")
	if resourceID == "" {
		return 0
	}
	action := eventField(evt, "action")
	reason := resourceRevokeReason(action)
	organizationID := eventField(evt, "organization_id")

	switch action {
	case "created":
		return 0
	case "deleted":
		return service.pa.Sessions.RevokeSessionsForResource(resourceID, organizationID, reason)
	}

	if eventBool(evt, "revokes_sessions") {
		return service.pa.Sessions.RevokeSessionsForResource(resourceID, organizationID, reason)
	}
	if service.resourceUnavailable(resourceID) {
		return service.pa.Sessions.RevokeSessionsForResource(resourceID, organizationID, reason)
	}
	return 0
}

func (service *Service) handleDeviceRevoked(evt events.Event) int {
	deviceID := eventField(evt, "device_id")
	if deviceID == "" {
		return 0
	}
	return service.pa.Sessions.RevokeSessionsForDevice(deviceID, eventField(evt, "organization_id"), "device_revoked")
}

func (service *Service) handleGatewayRevoked(evt events.Event) int {
	gatewayID := eventField(evt, "gateway_id")
	if gatewayID == "" {
		return 0
	}
	return service.pa.Sessions.RevokeSessionsForGateway(gatewayID, eventField(evt, "organization_id"), "gateway_revoked")
}

func (service *Service) revokeSessionsNoLongerAllowed(reason string, match func(*models.Session) bool) int {
	return service.pa.Sessions.RevokeSessionsMatching(reason, func(session *models.Session) bool {
		if session == nil || !match(session) {
			return false
		}
		allowed, denyReason := service.sessionStillAllowed(session)
		if allowed {
			return false
		}
		service.auditContinuousRevocation(session, reason, denyReason)
		return true
	})
}

func (service *Service) sessionStillAllowed(session *models.Session) (bool, string) {
	if service == nil || service.pa == nil || service.pa.Store == nil {
		return false, "policy administrator is unavailable"
	}
	user, ok := service.pa.Store.GetUser(session.UserID)
	if !ok || user == nil || user.Disabled {
		return false, "user is disabled or missing"
	}
	resource, ok := service.pa.Store.GetResource(session.Resource)
	if !ok || resource == nil || !resource.Enabled {
		return false, "resource is missing or disabled"
	}
	organizationID := firstNonEmpty(session.OrganizationID, resource.OrganizationID, user.OrganizationID)
	if organizationID == "" {
		return false, "organization context is missing"
	}
	if user.OrganizationID != "" && !strings.EqualFold(user.OrganizationID, organizationID) {
		return false, "user organization does not match session organization"
	}
	if resource.OrganizationID != "" && !strings.EqualFold(resource.OrganizationID, organizationID) {
		return false, "resource organization does not match session organization"
	}

	gatewayID := firstNonEmpty(session.GatewayID, resource.GatewayID)
	gateway, ok := service.pa.Store.GetGateway(gatewayID)
	if gatewayID == "" || !ok || gateway == nil || gateway.Status != "enrolled" {
		return false, "gateway is not enrolled"
	}
	if gateway.OrganizationID != "" && !strings.EqualFold(gateway.OrganizationID, organizationID) {
		return false, "gateway organization does not match session organization"
	}

	protocol := firstNonEmpty(session.Protocol, paadmin.ResourceProtocol(resource))
	port := paadmin.ResourcePort(resource, protocol)
	req := models.AccessRequest{
		UserID:         session.UserID,
		Username:       session.Username,
		DeviceID:       session.DeviceID,
		SourceIP:       session.SourceIP,
		Resource:       resource.ID,
		OrganizationID: organizationID,
		GatewayID:      gateway.ID,
		ResourcePort:   port,
		Protocol:       protocol,
		AppID:          resource.ID,
	}
	if deviceData, ok := service.pa.Store.GetDeviceDataForSubject(session.DeviceID, session.UserID); ok {
		req.DeviceHealth = paadmin.DeviceHealthFromData(deviceData)
	}

	decision := service.pa.EvaluateAccessWithAuth(req, sessionStepUpAuthContext(session))
	if decision == nil {
		return false, "policy evaluation failed"
	}
	if !strings.EqualFold(decision.Decision, "allow") {
		return false, firstNonEmpty(decision.Reason, fmt.Sprintf("policy returned %s", decision.Decision))
	}
	return true, ""
}

func sessionStepUpAuthContext(session *models.Session) models.AuthContext {
	if session == nil || session.StepUpVerifiedAt.IsZero() {
		return models.AuthContext{}
	}
	auth := models.AuthContext{
		ACR:              strings.TrimSpace(session.StepUpACR),
		StepUpVerifiedAt: session.StepUpVerifiedAt,
		StepUpExpiresAt:  session.StepUpExpiresAt,
		StepUpMethod:     strings.TrimSpace(session.StepUpMethod),
		StepUpStrength:   strings.TrimSpace(session.StepUpStrength),
		StepUpAAGUID:     strings.TrimSpace(session.StepUpAAGUID),
		StepUpAttachment: strings.TrimSpace(session.StepUpAttachment),
	}
	if auth.StepUpMethod != "" {
		auth.AMR = []string{auth.StepUpMethod}
	}
	return auth
}

func (service *Service) resourceUnavailable(resourceID string) bool {
	if service == nil || service.pa == nil || service.pa.Store == nil || strings.TrimSpace(resourceID) == "" {
		return true
	}
	resource, ok := service.pa.Store.GetResource(resourceID)
	return !ok || resource == nil || !resource.Enabled
}

func (service *Service) auditContinuousRevocation(session *models.Session, reason, details string) {
	if service == nil || service.pa == nil || service.pa.Audit == nil || session == nil {
		return
	}
	message := strings.TrimSpace(details)
	if message == "" {
		message = reason
	}
	if strings.TrimSpace(session.ID) != "" {
		message = strings.TrimSpace(message) + " session_id=" + strings.TrimSpace(session.ID)
	}
	if strings.TrimSpace(session.GatewayID) != "" {
		message = strings.TrimSpace(message) + " gateway_id=" + strings.TrimSpace(session.GatewayID)
	}
	service.pa.Audit.LogEvent("continuous_access_revoked", session.UserID, session.Username, session.SourceIP, session.Resource, "deny", message, true)
	log.Printf("[ENFORCEMENT] Revoking active session %s reason=%s detail=%s", session.ID, reason, message)
}

func eventField(evt events.Event, key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	switch payload := evt.Payload.(type) {
	case map[string]string:
		return strings.TrimSpace(payload[key])
	case map[string]interface{}:
		if value, ok := payload[key]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func eventBool(evt events.Event, key string) bool {
	value := strings.ToLower(eventField(evt, key))
	return value == "true" || value == "1" || value == "yes"
}

func resourceRevokeReason(action string) string {
	switch strings.TrimSpace(action) {
	case "deleted":
		return "resource_deleted"
	case "updated":
		return "resource_updated"
	default:
		return "resource_unavailable"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
