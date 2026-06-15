package redisstate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type loginAttemptState struct {
	FailedCount int       `json:"failed_count"`
	LastAttempt time.Time `json:"last_attempt"`
	LockedUntil time.Time `json:"locked_until"`
}

func (c *Client) RecordFailedLogin(username string, maxAttempts int, lockoutDuration time.Duration) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if lockoutDuration <= 0 {
		lockoutDuration = 5 * time.Minute
	}
	state, _ := c.loadLoginAttempt(username)
	now := time.Now().UTC()
	state.FailedCount++
	state.LastAttempt = now
	if state.FailedCount >= maxAttempts {
		state.LockedUntil = now.Add(lockoutDuration)
	}
	ttl := 24 * time.Hour
	if state.LockedUntil.After(now) {
		ttl = time.Until(state.LockedUntil)
	}
	return c.setJSON(loginAttemptKey(username), state, ttl)
}

func (c *Client) ResetLoginAttempts(username string) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	return c.rdb.Del(context.Background(), loginAttemptKey(username)).Err()
}

func (c *Client) IsLockedOut(username string) (bool, time.Time, error) {
	if c == nil || c.rdb == nil {
		return false, time.Time{}, ErrUnavailable
	}
	state, ok := c.loadLoginAttempt(strings.ToLower(strings.TrimSpace(username)))
	if !ok || state.LockedUntil.IsZero() {
		return false, time.Time{}, nil
	}
	if state.LockedUntil.After(time.Now().UTC()) {
		return true, state.LockedUntil, nil
	}
	_ = c.ResetLoginAttempts(username)
	return false, time.Time{}, nil
}

func (c *Client) GetFailedAttempts(username string) int {
	state, ok := c.loadLoginAttempt(strings.ToLower(strings.TrimSpace(username)))
	if !ok {
		return 0
	}
	return state.FailedCount
}

func (c *Client) loadLoginAttempt(username string) (loginAttemptState, bool) {
	var state loginAttemptState
	if c == nil || c.rdb == nil || strings.TrimSpace(username) == "" {
		return state, false
	}
	raw, err := c.rdb.Get(context.Background(), loginAttemptKey(username)).Bytes()
	if errors.Is(err, redis.Nil) || err != nil {
		return state, false
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, false
	}
	return state, true
}

func loginAttemptKey(username string) string {
	return keyPrefix + ":login-attempt:" + strings.ToLower(strings.TrimSpace(username))
}
