package transport

import (
	"strings"
	"time"

	"pdp/pa/auth"
)

func (s *Server) touchAgentSessionActivity(token, deviceID, certificateThumbprint string) {
	if s == nil || s.pa == nil || s.pa.Auth == nil || s.agentSessions == nil {
		return
	}
	claims, err := s.pa.ValidateDeviceUserTokenBoundForScope(token, deviceID, certificateThumbprint, "flow:authorize")
	if err != nil {
		return
	}
	s.touchAgentSessionActivityForClaims(claims, certificateThumbprint)
}

func (s *Server) touchAgentSessionActivityWithClaims(claims *auth.CustomClaims, fallbackToken, deviceID, certificateThumbprint string) {
	if claims == nil {
		s.touchAgentSessionActivity(fallbackToken, deviceID, certificateThumbprint)
		return
	}
	s.touchAgentSessionActivityForClaims(claims, certificateThumbprint)
}

func (s *Server) touchAgentSessionActivityForClaims(claims *auth.CustomClaims, certificateThumbprint string) {
	if s == nil || s.agentSessions == nil || claims == nil {
		return
	}
	sessionID := strings.TrimSpace(claims.SessionID)
	if sessionID == "" {
		return
	}
	now := time.Now().UTC()
	idleTTL := s.appConfig().Runtime.AgentSessionIdleTTL
	if idleTTL <= 0 {
		idleTTL = 30 * time.Minute
	}
	_, _ = s.agentSessions.updateByAgentSessionID(sessionID, func(live *agentSessionTransaction) error {
		if err := validateClaimedAgentSessionForToken(live, claims, certificateThumbprint, now); err != nil {
			return err
		}
		live.LastActivityAt = now
		live.IdleExpiresAt = now.Add(idleTTL)
		if !live.AbsoluteExpiresAt.IsZero() && live.AbsoluteExpiresAt.UTC().Before(live.IdleExpiresAt.UTC()) {
			live.IdleExpiresAt = live.AbsoluteExpiresAt.UTC()
		}
		live.ExpiresAt = minNonZeroTime(live.IdleExpiresAt, live.AbsoluteExpiresAt)
		return nil
	})
}
