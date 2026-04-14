package mfa

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"cloud/config"
	"cloud/models"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ─────────────────────────────────────────────
// WebAuthn User Adapter
// ─────────────────────────────────────────────

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

// ─────────────────────────────────────────────
// Challenge Session Store (in-memory, 5 min TTL)
// ─────────────────────────────────────────────

type challengeSession struct {
	Data      *webauthn.SessionData
	CreatedAt time.Time
}

// ─────────────────────────────────────────────
// WebAuthn Provider
// ─────────────────────────────────────────────

// WebAuthnProvider wraps the go-webauthn library and manages challenge
// sessions for registration and authentication ceremonies.
type WebAuthnProvider struct {
	wa *webauthn.WebAuthn

	mu       sync.Mutex
	sessions map[string]*challengeSession // key = userID + ceremony type
}

// NewWebAuthnProvider creates a WebAuthn relying party.
// Returns nil if WebAuthn is not configured (RPID is empty).
func NewWebAuthnProvider(cfg *config.Config) *WebAuthnProvider {
	if cfg.WebAuthnRPID == "" {
		log.Println("[MFA] WebAuthn disabled (webauthn_rp_id not configured)")
		return nil
	}

	rpName := cfg.WebAuthnRPName
	if rpName == "" {
		rpName = "ZTNA Cloud"
	}

	var origins []string
	for _, o := range strings.Split(cfg.WebAuthnRPOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}
	if len(origins) == 0 {
		origins = []string{fmt.Sprintf("https://%s", cfg.WebAuthnRPID)}
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.WebAuthnRPID,
		RPDisplayName: rpName,
		RPOrigins:     origins,
	})
	if err != nil {
		log.Printf("[MFA] WebAuthn init failed: %v", err)
		return nil
	}

	p := &WebAuthnProvider{
		wa:       wa,
		sessions: make(map[string]*challengeSession),
	}

	// Background cleanup of expired challenge sessions
	go p.cleanupLoop()

	log.Printf("[MFA] WebAuthn enabled (RPID=%s, origins=%v)", cfg.WebAuthnRPID, origins)
	return p
}

// ─────────────────────────────────────────────
// Registration Ceremony
// ─────────────────────────────────────────────

// BeginRegistration starts the WebAuthn credential registration ceremony.
// Returns the options JSON to send to the browser (navigator.credentials.create).
func (p *WebAuthnProvider) BeginRegistration(user *models.User, existingCreds []webauthn.Credential) (json.RawMessage, error) {
	wUser := &WebAuthnUser{User: user, Credentials: existingCreds}

	creation, session, err := p.wa.BeginRegistration(wUser)
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}

	p.storeSession(user.ID, "register", session)

	opts, err := json.Marshal(creation)
	if err != nil {
		return nil, fmt.Errorf("marshal creation options: %w", err)
	}

	log.Printf("[MFA] WebAuthn registration started for user %s", user.Username)
	return opts, nil
}

// FinishRegistration completes the registration ceremony.
// The request must be the raw HTTP request forwarding the browser's response.
// Returns the new Credential to be persisted.
func (p *WebAuthnProvider) FinishRegistration(user *models.User, existingCreds []webauthn.Credential, r *http.Request) (*webauthn.Credential, error) {
	session, ok := p.loadSession(user.ID, "register")
	if !ok {
		return nil, fmt.Errorf("no pending registration session")
	}
	p.deleteSession(user.ID, "register")

	wUser := &WebAuthnUser{User: user, Credentials: existingCreds}

	cred, err := p.wa.FinishRegistration(wUser, *session, r)
	if err != nil {
		return nil, fmt.Errorf("finish registration: %w", err)
	}

	log.Printf("[MFA] WebAuthn credential registered for user %s", user.Username)
	return cred, nil
}

// ─────────────────────────────────────────────
// Authentication Ceremony
// ─────────────────────────────────────────────

// BeginAuthentication starts the WebAuthn authentication ceremony.
// Returns the assertion options JSON to send to the browser (navigator.credentials.get).
func (p *WebAuthnProvider) BeginAuthentication(user *models.User, creds []webauthn.Credential) (json.RawMessage, error) {
	if len(creds) == 0 {
		return nil, fmt.Errorf("user has no WebAuthn credentials")
	}

	wUser := &WebAuthnUser{User: user, Credentials: creds}

	assertion, session, err := p.wa.BeginLogin(wUser)
	if err != nil {
		return nil, fmt.Errorf("begin login: %w", err)
	}

	p.storeSession(user.ID, "authenticate", session)

	opts, err := json.Marshal(assertion)
	if err != nil {
		return nil, fmt.Errorf("marshal assertion options: %w", err)
	}

	log.Printf("[MFA] WebAuthn authentication started for user %s", user.Username)
	return opts, nil
}

// FinishAuthentication completes the authentication ceremony.
// Returns the matched Credential (with updated sign count).
func (p *WebAuthnProvider) FinishAuthentication(user *models.User, creds []webauthn.Credential, r *http.Request) (*webauthn.Credential, error) {
	session, ok := p.loadSession(user.ID, "authenticate")
	if !ok {
		return nil, fmt.Errorf("no pending authentication session")
	}
	p.deleteSession(user.ID, "authenticate")

	wUser := &WebAuthnUser{User: user, Credentials: creds}

	cred, err := p.wa.FinishLogin(wUser, *session, r)
	if err != nil {
		return nil, fmt.Errorf("finish login: %w", err)
	}

	log.Printf("[MFA] WebAuthn authentication completed for user %s", user.Username)
	return cred, nil
}

// ─────────────────────────────────────────────
// Session Management
// ─────────────────────────────────────────────

func sessionKey(userID, ceremony string) string {
	return userID + ":" + ceremony
}

func (p *WebAuthnProvider) storeSession(userID, ceremony string, data *webauthn.SessionData) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions[sessionKey(userID, ceremony)] = &challengeSession{
		Data:      data,
		CreatedAt: time.Now(),
	}
}

func (p *WebAuthnProvider) loadSession(userID, ceremony string) (*webauthn.SessionData, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[sessionKey(userID, ceremony)]
	if !ok || time.Since(s.CreatedAt) > 5*time.Minute {
		return nil, false
	}
	return s.Data, true
}

func (p *WebAuthnProvider) deleteSession(userID, ceremony string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, sessionKey(userID, ceremony))
}

func (p *WebAuthnProvider) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		for k, s := range p.sessions {
			if time.Since(s.CreatedAt) > 5*time.Minute {
				delete(p.sessions, k)
			}
		}
		p.mu.Unlock()
	}
}
