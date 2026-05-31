package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

var errAgentSessionNotFound = errors.New("agent session transaction not found")

const (
	agentSessionStatusWaitingForUserLogin = "WAITING_FOR_USER_LOGIN"
	agentSessionStatusReadyToClaim        = "READY_TO_CLAIM"
	agentSessionStatusDenied              = "DENIED"
	agentSessionStatusClaimed             = "CLAIMED"
)

type agentSessionTransaction struct {
	ID                         string
	TenantID                   string
	DeviceID                   string
	DeviceCertThumbprint       string
	LocalUserSIDHash           string
	WindowsLogonSessionID      string
	WindowsSessionID           string
	DeviceDataRevision         string
	ClaimSecretHash            string
	AuthURL                    string
	Status                     string
	Reason                     string
	IDPProfileID               string
	ExpectedIssuer             string
	ExpectedClientID           string
	BrowserState               string
	BrowserNonce               string
	PKCEVerifier               string
	AuthenticatedUserSubject   string
	AuthenticatedUserEmail     string
	AuthenticatedUserIssuer    string
	AuthenticatedUserID        string
	AuthenticatedUsername      string
	AuthenticatedUserRole      string
	AgentSessionID             string
	AgentSessionToken          string
	AgentSessionTokenExpiresAt time.Time
	PolicyEpoch                int
	SingleUseConsumed          bool
	CreatedAt                  time.Time
	ExpiresAt                  time.Time
}

type agentSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*agentSessionTransaction
}

func newAgentSessionStore() *agentSessionStore {
	return &agentSessionStore{sessions: make(map[string]*agentSessionTransaction)}
}

func (store *agentSessionStore) save(session *agentSessionTransaction) {
	if store == nil || session == nil {
		return
	}
	store.mu.Lock()
	store.sessions[strings.TrimSpace(session.ID)] = session
	store.mu.Unlock()
}

func (store *agentSessionStore) get(id string) (*agentSessionTransaction, bool) {
	if store == nil {
		return nil, false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	session, ok := store.sessions[strings.TrimSpace(id)]
	if !ok || session == nil {
		return nil, false
	}
	copy := *session
	return &copy, true
}

func (store *agentSessionStore) update(id string, fn func(*agentSessionTransaction) error) (*agentSessionTransaction, error) {
	if store == nil {
		return nil, errAgentSessionNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	session, ok := store.sessions[strings.TrimSpace(id)]
	if !ok || session == nil {
		return nil, errAgentSessionNotFound
	}
	if err := fn(session); err != nil {
		return nil, err
	}
	copy := *session
	return &copy, nil
}

func (store *agentSessionStore) getByBrowserState(state string) (*agentSessionTransaction, bool) {
	if store == nil {
		return nil, false
	}
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, session := range store.sessions {
		if session != nil && session.BrowserState == state {
			copy := *session
			return &copy, true
		}
	}
	return nil, false
}

func (store *agentSessionStore) deleteByAgentSessionID(agentSessionID string) bool {
	if store == nil {
		return false
	}
	agentSessionID = strings.TrimSpace(agentSessionID)
	if agentSessionID == "" {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for id, session := range store.sessions {
		if session != nil && strings.TrimSpace(session.AgentSessionID) == agentSessionID {
			delete(store.sessions, id)
			return true
		}
	}
	return false
}

func randomSessionSecret(length int) (string, error) {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func hashSessionSecret(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}
