package transport

import (
	"context"
	"log"
	"strings"
	"time"

	"pdp/events"
	"pdp/models"
	"pdp/pa"
)

const gatewaySessionRevocationTimeout = 5 * time.Second

func (s *Server) wireSessionDeleteSink() {
	if s == nil || s.pa == nil || s.pa.Sessions == nil {
		return
	}
	s.pa.Sessions.SetDeleteEventSink(func(session *models.Session, reason string) {
		fields := map[string]string{"reason": reason}
		if session != nil {
			fields["session_id"] = session.ID
			fields["user_id"] = session.UserID
			fields["device_id"] = session.DeviceID
			fields["resource_id"] = session.Resource
			fields["tenant_id"] = session.TenantID
			fields["gateway_id"] = session.GatewayID
		}
		s.publishCAEPEvent(events.TopicSessionDeleted, fields)
		s.revokeProvisionedGatewaySession(session, reason)
	})
}

func (s *Server) rememberGatewaySession(sessionID, gatewayID string) {
	if s == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	gatewayID = strings.TrimSpace(gatewayID)
	if sessionID == "" || gatewayID == "" {
		return
	}
	s.sessionGatewayMu.Lock()
	if s.sessionGateways == nil {
		s.sessionGateways = make(map[string]string)
	}
	s.sessionGateways[sessionID] = gatewayID
	s.sessionGatewayMu.Unlock()
}

func (s *Server) gatewaySessionBinding(sessionID string) (string, bool) {
	if s == nil {
		return "", false
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", false
	}
	s.sessionGatewayMu.RLock()
	defer s.sessionGatewayMu.RUnlock()
	if s.sessionGateways == nil {
		return "", false
	}
	gatewayID, ok := s.sessionGateways[sessionID]
	return strings.TrimSpace(gatewayID), ok && strings.TrimSpace(gatewayID) != ""
}

func (s *Server) forgetGatewaySession(sessionID string) {
	if s == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	s.sessionGatewayMu.Lock()
	if s.sessionGateways != nil {
		delete(s.sessionGateways, sessionID)
	}
	s.sessionGatewayMu.Unlock()
}

func (s *Server) revokeProvisionedGatewaySession(session *models.Session, reason string) {
	if s == nil || session == nil || s.gatewayControl == nil {
		return
	}
	gatewayIDs := s.gatewayIDsForSessionRevocation(session)
	if len(gatewayIDs) == 0 {
		return
	}
	for _, gatewayID := range gatewayIDs {
		ctx, cancel := context.WithTimeout(context.Background(), gatewaySessionRevocationTimeout)
		err := s.gatewayControl.RevokeSession(ctx, gatewayID, session.ID, reason)
		cancel()
		if err != nil {
			log.Printf("[GATEWAY-CONTROL] Failed to revoke provisioned session: gateway=%s session=%s reason=%s err=%v", gatewayID, session.ID, strings.TrimSpace(reason), err)
		} else {
			s.forgetGatewaySession(session.ID)
			log.Printf("[GATEWAY-CONTROL] Revoked provisioned session: gateway=%s session=%s reason=%s", gatewayID, session.ID, strings.TrimSpace(reason))
		}
	}
}

func (s *Server) gatewayIDsForSessionRevocation(session *models.Session) []string {
	if s == nil || session == nil || strings.TrimSpace(session.ID) == "" {
		return nil
	}
	if gatewayID, ok := s.gatewaySessionBinding(session.ID); ok {
		return []string{gatewayID}
	}
	if gatewayID := strings.TrimSpace(session.GatewayID); gatewayID != "" {
		return []string{gatewayID}
	}
	if s.pa == nil || s.pa.Store == nil || s.gatewayControl == nil {
		return nil
	}
	connected := make(map[string]struct{})
	for _, gatewayID := range s.gatewayControl.ConnectedGatewayIDs() {
		connected[strings.TrimSpace(gatewayID)] = struct{}{}
	}
	if len(connected) == 0 {
		return nil
	}
	gatewayIDs := make([]string, 0, len(connected))
	seen := make(map[string]struct{}, len(connected))
	if resource, found := s.pa.Store.GetResource(session.Resource); found && resource != nil {
		if gatewayID := strings.TrimSpace(resource.GatewayID); gatewayID != "" {
			if _, ok := connected[gatewayID]; ok {
				return []string{gatewayID}
			}
		}
	}
	for _, gateway := range s.pa.Store.ListGateways() {
		if gateway == nil || gateway.Status != "enrolled" {
			continue
		}
		gatewayID := strings.TrimSpace(gateway.ID)
		if _, ok := connected[gatewayID]; !ok {
			continue
		}
		if !pa.GatewayServesResource(gateway, session.Resource) {
			continue
		}
		if _, ok := seen[gatewayID]; ok {
			continue
		}
		seen[gatewayID] = struct{}{}
		gatewayIDs = append(gatewayIDs, gatewayID)
	}
	return gatewayIDs
}
