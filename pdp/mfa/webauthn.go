package mfa

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/config"
	"pdp/models"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn User Adapter

// WebAuthnUser implements the webauthn.User interface by wrapping a
// models.User together with the stored WebAuthn credentials.
type WebAuthnUser struct {
	User        *models.User
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.User.ID)
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.User.Username
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.User.Username
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// Challenge storage (Redis-backed, short TTL)

type challengeSession struct {
	Data      *webauthn.SessionData
	CreatedAt time.Time
}

// WebAuthn Provider

// WebAuthnProvider wraps the go-webauthn library and manages challenge
// sessions for registration and authentication ceremonies.
type WebAuthnProvider struct {
	wa    *webauthn.WebAuthn
	state RuntimeStateStore

	challengeTTL    time.Duration
	cleanupInterval time.Duration
}

type RuntimeStateStore interface {
	SaveEphemeralState(kind, key string, value []byte, expiresAt time.Time) error
	GetEphemeralState(kind, key string) ([]byte, bool)
	DeleteEphemeralState(kind, key string) error
	CleanExpiredEphemeralState(now time.Time) int
}

const webAuthnSessionStateKind = "webauthn_session"

// NewWebAuthnProvider creates a WebAuthn relying party.
// Returns nil if WebAuthn is not configured (RPID is empty).
func NewWebAuthnProvider(cfg *config.Config, state RuntimeStateStore) *WebAuthnProvider {
	if cfg == nil {
		return nil
	}
	cfg.ApplyDefaults()
	if cfg.WebAuthnRPID == "" {
		log.Println("[MFA] WebAuthn disabled (webauthn_rp_id not configured)")
		return nil
	}

	rpName := cfg.WebAuthnRPName

	var origins []string
	for _, o := range strings.Split(cfg.WebAuthnRPOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:                   cfg.WebAuthnRPID,
		RPDisplayName:          rpName,
		RPOrigins:              origins,
		AuthenticatorSelection: passkeyAuthenticatorSelection(),
	})
	if err != nil {
		log.Printf("[MFA] WebAuthn init failed: %v", err)
		return nil
	}

	p := &WebAuthnProvider{
		wa:              wa,
		state:           state,
		challengeTTL:    cfg.Runtime.WebAuthnChallengeTTL,
		cleanupInterval: cfg.Runtime.WebAuthnCleanupInterval,
	}

	// Background cleanup of expired challenge sessions
	go p.cleanupLoop()

	log.Printf("[MFA] WebAuthn enabled (RPID=%s, origins=%v)", cfg.WebAuthnRPID, origins)
	return p
}

// Registration Ceremony

// BeginRegistration starts the WebAuthn credential registration ceremony.
// Returns the options JSON to send to the browser (navigator.credentials.create).
func (p *WebAuthnProvider) BeginRegistration(user *models.User, existingCreds []webauthn.Credential, contextID string) (json.RawMessage, error) {
	wUser := &WebAuthnUser{User: user, Credentials: existingCreds}

	creation, session, err := p.wa.BeginRegistration(wUser, webauthn.WithAuthenticatorSelection(passkeyAuthenticatorSelection()))
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}

	p.storeSession(user.ID, "register", contextID, session)

	opts, err := json.Marshal(creation)
	if err != nil {
		return nil, fmt.Errorf("marshal creation options: %w", err)
	}

	log.Printf("[MFA] WebAuthn registration started for user %s", user.Username)
	return opts, nil
}

func passkeyAuthenticatorSelection() protocol.AuthenticatorSelection {
	requireResidentKey := true
	return protocol.AuthenticatorSelection{
		RequireResidentKey: &requireResidentKey,
		ResidentKey:        protocol.ResidentKeyRequirementRequired,
		UserVerification:   protocol.VerificationRequired,
	}
}

// FinishRegistration completes the registration ceremony.
func (p *WebAuthnProvider) FinishRegistration(user *models.User, existingCreds []webauthn.Credential, contextID string, r *http.Request) (*webauthn.Credential, error) {
	session, ok := p.loadSession(user.ID, "register", contextID)
	if !ok {
		return nil, fmt.Errorf("no pending registration session")
	}
	p.deleteSession(user.ID, "register", contextID)

	wUser := &WebAuthnUser{User: user, Credentials: existingCreds}

	cred, err := p.wa.FinishRegistration(wUser, *session, r)
	if err != nil {
		return nil, fmt.Errorf("finish registration: %w", err)
	}

	log.Printf("[MFA] WebAuthn credential registered for user %s", user.Username)
	return cred, nil
}

// Authentication Ceremony

// BeginAuthentication starts the WebAuthn authentication ceremony.
// Returns the assertion options JSON to send to the browser (navigator.credentials.get).
func (p *WebAuthnProvider) BeginAuthentication(user *models.User, creds []webauthn.Credential, contextID string) (json.RawMessage, error) {
	if len(creds) == 0 {
		return nil, fmt.Errorf("user has no WebAuthn credentials")
	}

	wUser := &WebAuthnUser{User: user, Credentials: creds}

	assertion, session, err := p.wa.BeginLogin(wUser, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, fmt.Errorf("begin login: %w", err)
	}

	p.storeSession(user.ID, "authenticate", contextID, session)

	opts, err := json.Marshal(assertion)
	if err != nil {
		return nil, fmt.Errorf("marshal assertion options: %w", err)
	}

	log.Printf("[MFA] WebAuthn authentication started for user %s", user.Username)
	return opts, nil
}

// FinishAuthentication completes the authentication ceremony.
// Returns the matched Credential (with updated sign count).
func (p *WebAuthnProvider) FinishAuthentication(user *models.User, creds []webauthn.Credential, contextID string, r *http.Request) (*webauthn.Credential, error) {
	session, ok := p.loadSession(user.ID, "authenticate", contextID)
	if !ok {
		return nil, fmt.Errorf("no pending authentication session")
	}
	p.deleteSession(user.ID, "authenticate", contextID)

	wUser := &WebAuthnUser{User: user, Credentials: creds}

	cred, err := p.wa.FinishLogin(wUser, *session, r)
	if err != nil {
		return nil, fmt.Errorf("finish login: %w", err)
	}

	log.Printf("[MFA] WebAuthn authentication completed for user %s", user.Username)
	return cred, nil
}

// Session Management

func sessionKey(userID, ceremony, contextID string) string {
	return userID + ":" + ceremony + ":" + strings.TrimSpace(contextID)
}

func (p *WebAuthnProvider) storeSession(userID, ceremony, contextID string, data *webauthn.SessionData) {
	if p == nil || p.state == nil || data == nil {
		return
	}
	session := &challengeSession{
		Data:      data,
		CreatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(session)
	if err != nil {
		log.Printf("[MFA] WebAuthn session marshal failed: %v", err)
		return
	}
	key := sessionKey(userID, ceremony, contextID)
	if err := p.state.SaveEphemeralState(webAuthnSessionStateKind, key, raw, session.CreatedAt.Add(p.challengeTTL)); err != nil {
		log.Printf("[MFA] WebAuthn session save failed: %v", err)
	}
}

func (p *WebAuthnProvider) loadSession(userID, ceremony, contextID string) (*webauthn.SessionData, bool) {
	if p == nil || p.state == nil {
		return nil, false
	}
	key := sessionKey(userID, ceremony, contextID)
	raw, ok := p.state.GetEphemeralState(webAuthnSessionStateKind, key)
	if !ok {
		return nil, false
	}
	var s challengeSession
	if err := json.Unmarshal(raw, &s); err != nil {
		_ = p.state.DeleteEphemeralState(webAuthnSessionStateKind, key)
		return nil, false
	}
	if time.Since(s.CreatedAt) > p.challengeTTL {
		_ = p.state.DeleteEphemeralState(webAuthnSessionStateKind, key)
		return nil, false
	}
	return s.Data, true
}

func (p *WebAuthnProvider) deleteSession(userID, ceremony, contextID string) {
	if p == nil || p.state == nil {
		return
	}
	_ = p.state.DeleteEphemeralState(webAuthnSessionStateKind, sessionKey(userID, ceremony, contextID))
}

func (p *WebAuthnProvider) cleanupLoop() {
	ticker := time.NewTicker(p.cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		if p.state != nil {
			p.state.CleanExpiredEphemeralState(time.Now().UTC())
		}
	}
}
