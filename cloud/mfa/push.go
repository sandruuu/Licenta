package mfa

import (
	"fmt"
	"log"
	"sync"
	"time"

	"cloud/models"
	"cloud/store"
	"cloud/util"
)

const (
	// PushChallengeTTL is how long a push challenge remains valid.
	PushChallengeTTL = 2 * time.Minute

	// PushPollInterval is the recommended client polling interval.
	PushPollInterval = 3 * time.Second
)

// PushProvider manages push-based MFA challenges.
// The browser initiates a challenge, the device-health-app polls for pending
// challenges and the user approves/denies on the device. The browser polls
// the challenge status until resolved or expired.
type PushProvider struct {
	store *store.Store

	mu         sync.Mutex
	challenges map[string]*models.PushChallenge // challengeID → challenge
}

// NewPushProvider creates a new push MFA provider.
func NewPushProvider(s *store.Store) *PushProvider {
	p := &PushProvider{
		store:      s,
		challenges: make(map[string]*models.PushChallenge),
	}
	go p.cleanupLoop()
	log.Println("[MFA] Push approval provider initialized")
	return p
}

// CreateChallenge creates a new push challenge for the given user/device.
// Returns the challenge so the browser can start polling its status.
func (p *PushProvider) CreateChallenge(userID, username, deviceID, sourceIP string) (*models.PushChallenge, error) {
	id, err := util.GenerateID("push")
	if err != nil {
		return nil, fmt.Errorf("generate push challenge ID: %w", err)
	}

	ch := &models.PushChallenge{
		ID:        id,
		UserID:    userID,
		Username:  username,
		DeviceID:  deviceID,
		SourceIP:  sourceIP,
		Status:    "pending",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(PushChallengeTTL),
	}

	p.mu.Lock()
	p.challenges[id] = ch
	p.mu.Unlock()

	// Also persist to DB so the device can poll via a separate request
	if err := p.store.SavePushChallenge(ch); err != nil {
		log.Printf("[MFA] Failed to persist push challenge %s: %v", id, err)
		// Continue — in-memory is sufficient for the flow
	}

	log.Printf("[MFA] Push challenge created: id=%s user=%s device=%s", id, username, deviceID)
	return ch, nil
}

// GetStatus returns the current status of a push challenge.
func (p *PushProvider) GetStatus(challengeID string) (*models.PushChallenge, error) {
	p.mu.Lock()
	ch, ok := p.challenges[challengeID]
	p.mu.Unlock()

	if !ok {
		// Try DB fallback
		dbCh, err := p.store.GetPushChallenge(challengeID)
		if err != nil {
			return nil, fmt.Errorf("challenge not found")
		}
		return dbCh, nil
	}

	// Check expiry
	if time.Now().After(ch.ExpiresAt) {
		ch.Status = "expired"
	}

	return ch, nil
}

// Respond records the device user's approve/deny decision.
func (p *PushProvider) Respond(challengeID, decision string) error {
	if decision != "approved" && decision != "denied" {
		return fmt.Errorf("invalid decision: %s (must be 'approved' or 'denied')", decision)
	}

	p.mu.Lock()
	ch, ok := p.challenges[challengeID]
	p.mu.Unlock()

	if !ok {
		// Try DB
		dbCh, err := p.store.GetPushChallenge(challengeID)
		if err != nil {
			return fmt.Errorf("challenge not found")
		}
		ch = dbCh
		p.mu.Lock()
		p.challenges[challengeID] = ch
		p.mu.Unlock()
	}

	if ch.Status != "pending" {
		return fmt.Errorf("challenge already resolved: %s", ch.Status)
	}

	if time.Now().After(ch.ExpiresAt) {
		ch.Status = "expired"
		p.store.UpdatePushChallengeStatus(challengeID, "expired")
		return fmt.Errorf("challenge expired")
	}

	ch.Status = decision
	ch.RespondedAt = time.Now()
	p.store.UpdatePushChallengeStatus(challengeID, decision)

	log.Printf("[MFA] Push challenge %s: %s by user %s", challengeID, decision, ch.Username)
	return nil
}

// GetPendingForDevice returns all pending push challenges for a device.
func (p *PushProvider) GetPendingForDevice(deviceID string) []*models.PushChallenge {
	p.mu.Lock()
	defer p.mu.Unlock()

	var pending []*models.PushChallenge
	now := time.Now()
	for _, ch := range p.challenges {
		if ch.DeviceID == deviceID && ch.Status == "pending" && now.Before(ch.ExpiresAt) {
			pending = append(pending, ch)
		}
	}
	return pending
}

// cleanupLoop removes expired challenges every minute.
func (p *PushProvider) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		for id, ch := range p.challenges {
			if time.Since(ch.ExpiresAt) > 5*time.Minute {
				delete(p.challenges, id)
			}
		}
		p.mu.Unlock()
	}
}
