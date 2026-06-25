package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"pdp/pa"
	"pdp/runtime/redisstate"
)

const stepUpAuthCookieName = "tc_stepup_auth"
const (
	stepUpBrowserAuthStateKind = "step_up_browser_auth"
	stepUpFederatedStateKind   = "step_up_federated_reauth"
)

type stepUpBrowserAuthStore struct {
	state *redisstate.Client
	ttl   time.Duration
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
	State          string
	ChallengeID    string
	UserID         string
	TargetMethod   string
	OrganizationID string
	IdPID          string
	PKCEVerifier   string
	Nonce          string
	ExpiresAt      time.Time
}

func newStepUpBrowserAuthStore(state *redisstate.Client, ttl time.Duration) *stepUpBrowserAuthStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &stepUpBrowserAuthStore{
		state: state,
		ttl:   ttl,
	}
}

func (store *stepUpBrowserAuthStore) create(r *http.Request, challenge *pa.StepUpChallenge, targetMethod string, now time.Time) (*stepUpBrowserAuthSession, error) {
	if store == nil || store.state == nil || challenge == nil {
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
	raw, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}
	if err := store.state.SaveEphemeralState(stepUpBrowserAuthStateKind, id, raw, session.ExpiresAt); err != nil {
		return nil, err
	}
	return session, nil
}

func (store *stepUpBrowserAuthStore) get(id string, now time.Time) (*stepUpBrowserAuthSession, bool) {
	if store == nil || store.state == nil {
		return nil, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	raw, ok := store.state.GetEphemeralState(stepUpBrowserAuthStateKind, strings.TrimSpace(id))
	if !ok {
		return nil, false
	}
	var session stepUpBrowserAuthSession
	if err := json.Unmarshal(raw, &session); err != nil {
		_ = store.state.DeleteEphemeralState(stepUpBrowserAuthStateKind, id)
		return nil, false
	}
	if !now.Before(session.ExpiresAt) {
		_ = store.state.DeleteEphemeralState(stepUpBrowserAuthStateKind, id)
		return nil, false
	}
	copy := session
	return &copy, true
}

func (store *stepUpBrowserAuthStore) saveFederated(session *stepUpFederatedReauthSession) {
	if store == nil || store.state == nil || session == nil {
		return
	}
	raw, err := json.Marshal(session)
	if err != nil {
		return
	}
	_ = store.state.SaveEphemeralState(stepUpFederatedStateKind, strings.TrimSpace(session.State), raw, session.ExpiresAt)
}

func (store *stepUpBrowserAuthStore) takeFederated(state string, now time.Time) (*stepUpFederatedReauthSession, bool) {
	if store == nil || store.state == nil {
		return nil, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state = strings.TrimSpace(state)
	raw, ok, err := store.state.TakeEphemeralState(stepUpFederatedStateKind, state)
	if err != nil || !ok {
		return nil, false
	}
	var session stepUpFederatedReauthSession
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, false
	}
	if !now.Before(session.ExpiresAt) {
		return nil, false
	}
	copy := session
	return &copy, true
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
		Value:    "",
		Path:     publicStepUpPathPrefix,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     stepUpAuthCookieName,
		Value:    session.ID,
		Path:     "/",
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
