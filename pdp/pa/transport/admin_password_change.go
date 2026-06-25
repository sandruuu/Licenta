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

const adminPasswordChangeStateKind = "admin_password_change_challenge"

type adminPasswordChangeChallenge struct {
	ID        string
	UserID    string
	Username  string
	ExpiresAt time.Time
}

type adminPasswordChangeStore struct {
	state *redisstate.Client
}

func newAdminPasswordChangeStore(state *redisstate.Client) *adminPasswordChangeStore {
	return &adminPasswordChangeStore{state: state}
}

func (s *adminPasswordChangeStore) create(user *models.User, ttl time.Duration) (*adminPasswordChangeChallenge, error) {
	if s == nil || s.state == nil || user == nil {
		return nil, fmt.Errorf("password change challenge store unavailable")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	id, err := util.GenerateID("pwd")
	if err != nil {
		return nil, err
	}
	challenge := &adminPasswordChangeChallenge{
		ID:        id,
		UserID:    user.ID,
		Username:  user.Username,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	if err := s.save(challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}

func (s *adminPasswordChangeStore) get(id string) (*adminPasswordChangeChallenge, bool) {
	challenge, ok := s.load(id)
	if !ok || challenge == nil {
		return nil, false
	}
	if time.Now().UTC().After(challenge.ExpiresAt) {
		_ = s.state.DeleteEphemeralState(adminPasswordChangeStateKind, id)
		return nil, false
	}
	copyChallenge := *challenge
	return &copyChallenge, true
}

func (s *adminPasswordChangeStore) consume(id string) {
	if s == nil || s.state == nil {
		return
	}
	_ = s.state.DeleteEphemeralState(adminPasswordChangeStateKind, strings.TrimSpace(id))
}

func (s *adminPasswordChangeStore) save(challenge *adminPasswordChangeChallenge) error {
	if s == nil || s.state == nil || challenge == nil {
		return fmt.Errorf("password change challenge store unavailable")
	}
	raw, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	return s.state.SaveEphemeralState(adminPasswordChangeStateKind, challenge.ID, raw, challenge.ExpiresAt)
}

func (s *adminPasswordChangeStore) load(id string) (*adminPasswordChangeChallenge, bool) {
	if s == nil || s.state == nil {
		return nil, false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false
	}
	raw, ok := s.state.GetEphemeralState(adminPasswordChangeStateKind, id)
	if !ok {
		return nil, false
	}
	var challenge adminPasswordChangeChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		_ = s.state.DeleteEphemeralState(adminPasswordChangeStateKind, id)
		return nil, false
	}
	return &challenge, true
}
