package store

import (
	"time"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Pending Auth Session operations (in-memory, ephemeral)
// ─────────────────────────────────────────────

func (s *Store) SavePendingAuth(session *models.PendingAuthSession) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.PendingAuth[session.ID] = session
}

func (s *Store) GetPendingAuth(id string) (*models.PendingAuthSession, bool) {
	s.pendingMu.RLock()
	defer s.pendingMu.RUnlock()
	sess, ok := s.PendingAuth[id]
	return sess, ok
}

func (s *Store) DeletePendingAuth(id string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	delete(s.PendingAuth, id)
}

func (s *Store) CleanExpiredPendingAuth() int {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	count := 0
	now := time.Now()
	for id, sess := range s.PendingAuth {
		if sess.ExpiresAt.Before(now) {
			delete(s.PendingAuth, id)
			count++
		}
	}
	return count
}

// ─────────────────────────────────────────────
// Pending Enroll Session operations (in-memory, ephemeral)
// ─────────────────────────────────────────────

func (s *Store) SavePendingEnroll(session *models.PendingEnrollSession) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.PendingEnroll[session.ID] = session
}

func (s *Store) GetPendingEnroll(id string) (*models.PendingEnrollSession, bool) {
	s.enrollMu.RLock()
	defer s.enrollMu.RUnlock()
	sess, ok := s.PendingEnroll[id]
	return sess, ok
}

func (s *Store) DeletePendingEnroll(id string) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	delete(s.PendingEnroll, id)
}

func (s *Store) CleanExpiredPendingEnroll() int {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	count := 0
	now := time.Now()
	for id, sess := range s.PendingEnroll {
		if sess.ExpiresAt.Before(now) {
			delete(s.PendingEnroll, id)
			count++
		}
	}
	return count
}

// StartAutoSave is a no-op for SQLite (data is always persisted).
// Kept for API compatibility.
func (s *Store) StartAutoSave(interval time.Duration, stopChan <-chan struct{}) {
	// SQLite auto-persists — no periodic save needed.
	// Run periodic cleanup of pending auth sessions instead.
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				s.CleanExpiredPendingAuth()
				s.CleanExpiredPendingEnroll()
				s.CleanExpiredRevokedTokens()
			}
		}
	}()
}
