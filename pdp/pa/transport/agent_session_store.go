package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"pdp/runtime/redisstate"
)

var errAgentSessionNotFound = errors.New("agent session transaction not found")

const (
	agentSessionStatusWaitingForUserLogin = "WAITING_FOR_USER_LOGIN"
	agentSessionStatusReadyToClaim        = "READY_TO_CLAIM"
	agentSessionStatusDenied              = "DENIED"
	agentSessionStatusClaimed             = "CLAIMED"
	agentSessionStateKind                 = "agent_session_transaction"
)

type agentSessionTransaction struct {
	ID                       string
	OrganizationID           string
	DeviceID                 string
	DeviceCertThumbprint     string
	LocalUserSIDHash         string
	WindowsLogonSessionID    string
	WindowsSessionID         string
	DeviceDataRevision       string
	SessionRenewalRequired   bool
	ClaimSecretHash          string
	AuthURL                  string
	Status                   string
	Reason                   string
	IDPProfileID             string
	ExpectedIssuer           string
	ExpectedClientID         string
	BrowserState             string
	BrowserNonce             string
	PKCEVerifier             string
	AuthenticatedUserSubject string
	AuthenticatedUserEmail   string
	AuthenticatedUserIssuer  string
	AuthenticatedUserID      string
	AuthenticatedUsername    string
	AuthenticatedUserRole    string
	AgentSessionID           string
	PolicyEpoch              int
	SingleUseConsumed        bool
	CreatedAt                time.Time
	LastActivityAt           time.Time
	IdleExpiresAt            time.Time
	AbsoluteExpiresAt        time.Time
	ExpiresAt                time.Time
}

type agentSessionStore struct {
	state *redisstate.Client
}

func newAgentSessionStore(state *redisstate.Client) *agentSessionStore {
	return &agentSessionStore{state: state}
}

func (store *agentSessionStore) save(session *agentSessionTransaction) {
	if store == nil || store.state == nil || session == nil {
		return
	}
	_ = store.saveSession(session)
}

func (store *agentSessionStore) get(id string) (*agentSessionTransaction, bool) {
	session, ok := store.load(strings.TrimSpace(id))
	if !ok || session == nil || sessionExpired(session, time.Now().UTC()) {
		if store != nil && store.state != nil {
			_ = store.state.DeleteEphemeralState(agentSessionStateKind, id)
		}
		return nil, false
	}
	copy := *session
	return &copy, true
}

func (store *agentSessionStore) update(id string, fn func(*agentSessionTransaction) error) (*agentSessionTransaction, error) {
	session, ok := store.load(strings.TrimSpace(id))
	if !ok || session == nil || sessionExpired(session, time.Now().UTC()) {
		return nil, errAgentSessionNotFound
	}
	if err := fn(session); err != nil {
		return nil, err
	}
	if err := store.saveSession(session); err != nil {
		return nil, err
	}
	copy := *session
	return &copy, nil
}

func (store *agentSessionStore) getByBrowserState(state string) (*agentSessionTransaction, bool) {
	state = strings.TrimSpace(state)
	if store == nil || store.state == nil || state == "" {
		return nil, false
	}
	for key, raw := range store.listRaw() {
		var session agentSessionTransaction
		if err := json.Unmarshal(raw, &session); err != nil {
			_ = store.state.DeleteEphemeralState(agentSessionStateKind, key)
			continue
		}
		if sessionExpired(&session, time.Now().UTC()) {
			_ = store.state.DeleteEphemeralState(agentSessionStateKind, key)
			continue
		}
		if session.BrowserState == state {
			copy := session
			return &copy, true
		}
	}
	return nil, false
}

func (store *agentSessionStore) getByAgentSessionID(agentSessionID string) (*agentSessionTransaction, bool) {
	agentSessionID = strings.TrimSpace(agentSessionID)
	if store == nil || store.state == nil || agentSessionID == "" {
		return nil, false
	}
	for key, raw := range store.listRaw() {
		var session agentSessionTransaction
		if err := json.Unmarshal(raw, &session); err != nil {
			_ = store.state.DeleteEphemeralState(agentSessionStateKind, key)
			continue
		}
		if sessionExpired(&session, time.Now().UTC()) {
			_ = store.state.DeleteEphemeralState(agentSessionStateKind, key)
			continue
		}
		if strings.TrimSpace(session.AgentSessionID) == agentSessionID {
			copy := session
			return &copy, true
		}
	}
	return nil, false
}

func (store *agentSessionStore) updateByAgentSessionID(agentSessionID string, fn func(*agentSessionTransaction) error) (*agentSessionTransaction, error) {
	session, ok := store.getByAgentSessionID(agentSessionID)
	if !ok {
		return nil, errAgentSessionNotFound
	}
	return store.update(session.ID, fn)
}

func (store *agentSessionStore) deleteByAgentSessionID(agentSessionID string) bool {
	agentSessionID = strings.TrimSpace(agentSessionID)
	if store == nil || store.state == nil || agentSessionID == "" {
		return false
	}
	for key, raw := range store.listRaw() {
		var session agentSessionTransaction
		if err := json.Unmarshal(raw, &session); err != nil {
			_ = store.state.DeleteEphemeralState(agentSessionStateKind, key)
			continue
		}
		if strings.TrimSpace(session.AgentSessionID) == agentSessionID {
			_ = store.state.DeleteEphemeralState(agentSessionStateKind, key)
			return true
		}
	}
	return false
}

func (store *agentSessionStore) saveSession(session *agentSessionTransaction) error {
	raw, err := json.Marshal(session)
	if err != nil {
		return err
	}
	expiresAt := session.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(5 * time.Minute)
	}
	return store.state.SaveEphemeralState(agentSessionStateKind, session.ID, raw, expiresAt)
}

func (store *agentSessionStore) load(id string) (*agentSessionTransaction, bool) {
	if store == nil || store.state == nil || strings.TrimSpace(id) == "" {
		return nil, false
	}
	raw, ok := store.state.GetEphemeralState(agentSessionStateKind, id)
	if !ok {
		return nil, false
	}
	var session agentSessionTransaction
	if err := json.Unmarshal(raw, &session); err != nil {
		_ = store.state.DeleteEphemeralState(agentSessionStateKind, id)
		return nil, false
	}
	return &session, true
}

func (store *agentSessionStore) listRaw() map[string][]byte {
	values, err := store.state.ListEphemeralState(agentSessionStateKind)
	if err != nil {
		return nil
	}
	return values
}

func sessionExpired(session *agentSessionTransaction, now time.Time) bool {
	return session == nil || (!session.ExpiresAt.IsZero() && !now.Before(session.ExpiresAt))
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
