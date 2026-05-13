package auth

import (
	"crypto/rand"
	"encoding/hex"
	"log"
)

// CreateFederationSession stores a pending external IdP authentication session.
func (m *OIDCManager) CreateFederationSession(sess *FederationSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FederationSessions[sess.State] = sess
	log.Printf("[OIDC] Federation session created: state=%s oidc_session=%s tenant=%s idp=%s",
		sess.State, sess.OIDCSessionID, sess.TenantID, sess.IdPID)
}

// GetFederationSession retrieves and removes a federation session by state (one-time use).
func (m *OIDCManager) GetFederationSession(state string) (*FederationSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.FederationSessions[state]
	if ok {
		delete(m.FederationSessions, state)
	}
	return sess, ok
}

func generateOIDCID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

func generateOIDCCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
