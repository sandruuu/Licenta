package enrollment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type interactiveSessionLocker interface {
	WithLock(ctx context.Context, name string, ttl, wait time.Duration, fn func() error) error
}

func (s *Service) saveInteractiveSession(session *InteractiveSession) error {
	if s == nil || s.runtime == nil || session == nil {
		return fmt.Errorf("enrollment runtime state is unavailable")
	}
	session.ID = strings.TrimSpace(session.ID)
	if session.ID == "" {
		return fmt.Errorf("%w: interactive session ID is required", ErrInvalidRequest)
	}
	raw, err := json.Marshal(session)
	if err != nil {
		return err
	}
	expiresAt := session.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(s.activeBrowserSessionTTL())
	}
	return s.runtime.SaveEphemeralState(interactiveSessionStateKind, session.ID, raw, expiresAt.Add(interactiveSessionExpiredStateGrace))
}

func (s *Service) getInteractiveSession(sessionID string) (*InteractiveSession, bool) {
	if s == nil || s.runtime == nil {
		return nil, false
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, false
	}
	raw, ok := s.runtime.GetEphemeralState(interactiveSessionStateKind, sessionID)
	if !ok {
		return nil, false
	}
	var session InteractiveSession
	if err := json.Unmarshal(raw, &session); err != nil {
		_ = s.runtime.DeleteEphemeralState(interactiveSessionStateKind, sessionID)
		return nil, false
	}
	return &session, true
}

func (s *Service) listInteractiveSessions() []InteractiveSession {
	if s == nil || s.runtime == nil {
		return nil
	}
	rawSessions, err := s.runtime.ListEphemeralState(interactiveSessionStateKind)
	if err != nil {
		return nil
	}
	out := make([]InteractiveSession, 0, len(rawSessions))
	for id, raw := range rawSessions {
		var session InteractiveSession
		if err := json.Unmarshal(raw, &session); err != nil {
			_ = s.runtime.DeleteEphemeralState(interactiveSessionStateKind, id)
			continue
		}
		if strings.TrimSpace(session.ID) == "" {
			session.ID = strings.TrimSpace(id)
		}
		out = append(out, session)
	}
	return out
}

func (s *Service) deleteInteractiveSession(sessionID string) {
	if s == nil || s.runtime == nil {
		return
	}
	_ = s.runtime.DeleteEphemeralState(interactiveSessionStateKind, strings.TrimSpace(sessionID))
}

func (s *Service) expiredHandler() InteractiveSessionExpiredHandler {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.interactiveSessionExpiredHandler
}

func (s *Service) withInteractiveSessionLock(sessionID string, fn func() error) error {
	if fn == nil {
		return nil
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return fmt.Errorf("%w: session ID is required", ErrInvalidRequest)
	}
	if locker, ok := s.runtime.(interactiveSessionLocker); ok {
		return locker.WithLock(context.Background(), "interactive-enroll-"+sessionID, interactiveSessionLockTTL, interactiveSessionLockWait, fn)
	}
	return fn()
}
