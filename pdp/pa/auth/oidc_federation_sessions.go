package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
)

// CreateFederationSession records a pending external IdP authentication flow.
func (m *OIDCManager) CreateFederationSession(sess *FederationSession) {
	if sess == nil || m.state == nil {
		return
	}
	if err := saveOIDCState(m.state, oidcFederationStateKind, sess.State, sess, sess.ExpiresAt); err != nil {
		log.Printf("[OIDC] Failed to save federation session: state=%s err=%v", sess.State, err)
		return
	}
	log.Printf("[OIDC] Federation session created: state=%s oidc_session=%s organization=%s idp=%s",
		sess.State, sess.OIDCSessionID, sess.OrganizationID, sess.IdPID)
}

// GetFederationSession retrieves and removes a federation session by state (one-time use).
func (m *OIDCManager) GetFederationSession(state string) (*FederationSession, bool) {
	if m == nil || m.state == nil {
		return nil, false
	}
	raw, ok, err := m.state.TakeEphemeralState(oidcFederationStateKind, state)
	if err != nil || !ok {
		return nil, false
	}
	var sess FederationSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, false
	}
	return &sess, true
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
