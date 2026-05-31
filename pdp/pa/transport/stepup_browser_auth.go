package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"pdp/pa"
)

const stepUpAuthCookieName = "tc_stepup_auth"

type stepUpBrowserAuthStore struct {
	mu       sync.RWMutex
	sessions map[string]*stepUpBrowserAuthSession
	fed      map[string]*stepUpFederatedReauthSession
	ttl      time.Duration
}

type stepUpBrowserAuthSession struct {
	ID              string
	ChallengeID     string
	UserID          string
	TargetMethod    string
	RemoteIPHash    string
	UserAgentHash   string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}

type stepUpFederatedReauthSession struct {
	State        string
	ChallengeID  string
	UserID       string
	TargetMethod string
	TenantID     string
	IdPID        string
	PKCEVerifier string
	Nonce        string
	ExpiresAt    time.Time
}

func newStepUpBrowserAuthStore(ttl time.Duration) *stepUpBrowserAuthStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &stepUpBrowserAuthStore{
		sessions: make(map[string]*stepUpBrowserAuthSession),
		fed:      make(map[string]*stepUpFederatedReauthSession),
		ttl:      ttl,
	}
}

func (store *stepUpBrowserAuthStore) create(r *http.Request, challenge *pa.StepUpChallenge, targetMethod string, now time.Time) (*stepUpBrowserAuthSession, error) {
	if store == nil || challenge == nil {
		return nil, fmt.Errorf("step-up auth store is unavailable")
	}
	id, err := randomSessionSecret(32)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	session := &stepUpBrowserAuthSession{
		ID:              id,
		ChallengeID:     challenge.ID,
		UserID:          challenge.UserID,
		TargetMethod:    strings.ToLower(strings.TrimSpace(targetMethod)),
		RemoteIPHash:    stepUpHashValue(stepUpRemoteIP(r)),
		UserAgentHash:   stepUpHashValue(r.UserAgent()),
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(store.ttl),
	}
	store.mu.Lock()
	store.expireLocked(now)
	store.sessions[id] = session
	store.mu.Unlock()
	return session, nil
}

func (store *stepUpBrowserAuthStore) get(id string, now time.Time) (*stepUpBrowserAuthSession, bool) {
	if store == nil {
		return nil, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	session := store.sessions[strings.TrimSpace(id)]
	if session == nil || !now.Before(session.ExpiresAt) {
		return nil, false
	}
	copy := *session
	return &copy, true
}

func (store *stepUpBrowserAuthStore) saveFederated(session *stepUpFederatedReauthSession) {
	if store == nil || session == nil {
		return
	}
	store.mu.Lock()
	store.expireLocked(time.Now().UTC())
	store.fed[strings.TrimSpace(session.State)] = session
	store.mu.Unlock()
}

func (store *stepUpBrowserAuthStore) takeFederated(state string, now time.Time) (*stepUpFederatedReauthSession, bool) {
	if store == nil {
		return nil, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	state = strings.TrimSpace(state)
	session := store.fed[state]
	if session == nil || !now.Before(session.ExpiresAt) {
		delete(store.fed, state)
		return nil, false
	}
	delete(store.fed, state)
	copy := *session
	return &copy, true
}

func (store *stepUpBrowserAuthStore) expireLocked(now time.Time) {
	for id, session := range store.sessions {
		if session == nil || !now.Before(session.ExpiresAt) {
			delete(store.sessions, id)
		}
	}
	for state, session := range store.fed {
		if session == nil || !now.Before(session.ExpiresAt) {
			delete(store.fed, state)
		}
	}
}

func (s *Server) setStepUpAuthCookie(w http.ResponseWriter, session *stepUpBrowserAuthSession) {
	if session == nil {
		return
	}
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stepUpAuthCookieName,
		Value:    session.ID,
		Path:     "/browser/step-up/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (s *Server) hasStepUpEnrollmentAuth(r *http.Request, challenge *pa.StepUpChallenge, targetMethod string) bool {
	if s == nil || s.stepUpAuth == nil || r == nil || challenge == nil {
		return false
	}
	cookie, err := r.Cookie(stepUpAuthCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return false
	}
	session, ok := s.stepUpAuth.get(cookie.Value, time.Now().UTC())
	if !ok || session == nil {
		return false
	}
	return strings.EqualFold(session.ChallengeID, challenge.ID) &&
		strings.EqualFold(session.UserID, challenge.UserID) &&
		strings.EqualFold(session.TargetMethod, strings.TrimSpace(targetMethod)) &&
		session.RemoteIPHash == stepUpHashValue(stepUpRemoteIP(r)) &&
		session.UserAgentHash == stepUpHashValue(r.UserAgent())
}

func stepUpRemoteIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func stepUpHashValue(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}
