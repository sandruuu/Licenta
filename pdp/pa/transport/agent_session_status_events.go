package transport

import (
	"strings"

	"pdp/pa/events"
)

func (s *Server) publishAgentSessionStatus(session *agentSessionTransaction) {
	if s == nil || session == nil {
		return
	}
	fields := map[string]string{
		"session_id":      strings.TrimSpace(session.ID),
		"status":          strings.TrimSpace(session.Status),
		"device_id":       strings.TrimSpace(session.DeviceID),
		"organization_id": strings.TrimSpace(session.OrganizationID),
	}
	if strings.TrimSpace(session.Reason) != "" {
		fields["reason"] = strings.TrimSpace(session.Reason)
	}
	s.publishCAEPEvent(events.TopicAgentSessionUpdated, fields)
}
