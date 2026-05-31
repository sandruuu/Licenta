package transport

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"pdp/models"
	"pdp/util"
)

type adminMFAChallenge struct {
	ID                string
	UserID            string
	Username          string
	Role              string
	PendingTOTPSecret string
	ExpiresAt         time.Time
	Attempts          int
}

type adminMFAStore struct {
	mu         sync.Mutex
	challenges map[string]*adminMFAChallenge
}

func newAdminMFAStore() *adminMFAStore {
	return &adminMFAStore{challenges: map[string]*adminMFAChallenge{}}
}

func (s *adminMFAStore) create(user *models.User, pendingTOTPSecret string, ttl time.Duration) (*adminMFAChallenge, error) {
	if s == nil || user == nil {
		return nil, fmt.Errorf("MFA challenge store unavailable")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	id, err := util.GenerateID("mfa")
	if err != nil {
		return nil, err
	}
	challenge := &adminMFAChallenge{
		ID:                id,
		UserID:            user.ID,
		Username:          user.Username,
		Role:              user.Role,
		PendingTOTPSecret: strings.TrimSpace(pendingTOTPSecret),
		ExpiresAt:         time.Now().UTC().Add(ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now().UTC())
	s.challenges[id] = challenge
	return challenge, nil
}

func (s *adminMFAStore) get(id string) (*adminMFAChallenge, bool) {
	if s == nil {
		return nil, false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	challenge, ok := s.challenges[id]
	if !ok || challenge == nil || now.After(challenge.ExpiresAt) {
		delete(s.challenges, id)
		return nil, false
	}
	copyChallenge := *challenge
	return &copyChallenge, true
}

func (s *adminMFAStore) recordFailure(id string, maxAttempts int) bool {
	if s == nil {
		return false
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, ok := s.challenges[id]
	if !ok || challenge == nil {
		return false
	}
	challenge.Attempts++
	if challenge.Attempts >= maxAttempts {
		delete(s.challenges, id)
		return false
	}
	return true
}

func (s *adminMFAStore) consume(id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.challenges, strings.TrimSpace(id))
}

func (s *adminMFAStore) cleanupLocked(now time.Time) {
	for id, challenge := range s.challenges {
		if challenge == nil || now.After(challenge.ExpiresAt) {
			delete(s.challenges, id)
		}
	}
}
