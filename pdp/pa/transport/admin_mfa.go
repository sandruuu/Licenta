package transport

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"pdp/models"
	"pdp/runtime/redisstate"
	"pdp/util"
)

const adminMFAStateKind = "admin_mfa_challenge"

type adminMFAChallenge struct {
	ID                string
	UserID            string
	Username          string
	Role              string
	Purpose           string
	PendingTOTPSecret string
	ExpiresAt         time.Time
	Attempts          int
}

type adminMFAStore struct {
	state *redisstate.Client
}

func newAdminMFAStore(state *redisstate.Client) *adminMFAStore {
	return &adminMFAStore{state: state}
}

func (s *adminMFAStore) create(user *models.User, pendingTOTPSecret string, ttl time.Duration, purpose string) (*adminMFAChallenge, error) {
	if s == nil || s.state == nil || user == nil {
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
		Purpose:           strings.TrimSpace(purpose),
		PendingTOTPSecret: strings.TrimSpace(pendingTOTPSecret),
		ExpiresAt:         time.Now().UTC().Add(ttl),
	}
	if err := s.save(challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}

func (s *adminMFAStore) get(id string) (*adminMFAChallenge, bool) {
	challenge, ok := s.load(id)
	if !ok || challenge == nil {
		return nil, false
	}
	if time.Now().UTC().After(challenge.ExpiresAt) {
		_ = s.state.DeleteEphemeralState(adminMFAStateKind, id)
		return nil, false
	}
	copyChallenge := *challenge
	return &copyChallenge, true
}

func (s *adminMFAStore) recordFailure(id string, maxAttempts int) bool {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	challenge, ok := s.load(id)
	if !ok || challenge == nil {
		return false
	}
	challenge.Attempts++
	if challenge.Attempts >= maxAttempts {
		_ = s.state.DeleteEphemeralState(adminMFAStateKind, id)
		return false
	}
	_ = s.save(challenge)
	return true
}

func (s *adminMFAStore) consume(id string) {
	if s == nil || s.state == nil {
		return
	}
	_ = s.state.DeleteEphemeralState(adminMFAStateKind, strings.TrimSpace(id))
}

func (s *adminMFAStore) save(challenge *adminMFAChallenge) error {
	if s == nil || s.state == nil || challenge == nil {
		return fmt.Errorf("MFA challenge store unavailable")
	}
	raw, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	return s.state.SaveEphemeralState(adminMFAStateKind, challenge.ID, raw, challenge.ExpiresAt)
}

func (s *adminMFAStore) load(id string) (*adminMFAChallenge, bool) {
	if s == nil || s.state == nil {
		return nil, false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false
	}
	raw, ok := s.state.GetEphemeralState(adminMFAStateKind, id)
	if !ok {
		return nil, false
	}
	var challenge adminMFAChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		_ = s.state.DeleteEphemeralState(adminMFAStateKind, id)
		return nil, false
	}
	return &challenge, true
}
