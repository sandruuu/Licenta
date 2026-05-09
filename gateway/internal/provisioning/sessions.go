package provisioning

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	CodeMissingSessionID = "missing_session_id"
	CodeSessionNotFound  = "session_not_found"
	CodeSessionExpired   = "session_expired"
	CodeSessionRevoked   = "session_revoked"
	CodeInvalidToken     = "invalid_session_token"
	CodeDeviceMismatch   = "device_mismatch"
	CodeResourceMismatch = "resource_mismatch"
	CodeProtocolMismatch = "protocol_mismatch"
	CodeBadRequest       = "bad_request"
)

type ValidationError struct {
	Code    string
	Message string
}

func (err *ValidationError) Error() string {
	if err == nil {
		return ""
	}
	return err.Message
}

type Session struct {
	ID               string
	TokenHash        string
	DeviceID         string
	UserID           string
	Username         string
	ResourceID       string
	ResourceName     string
	InternalHost     string
	InternalPort     int
	Protocol         string
	ExpiresAt        time.Time
	Constraints      []string
	PolicyVersion    string
	MaxBandwidthMbps int
	CreatedAt        time.Time
	Revoked          bool
	RevokedAt        time.Time
	RevocationReason string
}

type ConnectCheck struct {
	SessionID    string
	SessionToken string
	DeviceID     string
	ResourceID   string
	Protocol     string
	Port         int
}

type Store struct {
	mu       sync.RWMutex
	now      func() time.Time
	sessions map[string]Session
}

func NewStore() *Store {
	return NewStoreWithClock(time.Now)
}

func NewStoreWithClock(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, sessions: make(map[string]Session)}
}

func (store *Store) Provision(session Session, rawToken string) error {
	session.ID = strings.TrimSpace(session.ID)
	session.DeviceID = strings.TrimSpace(session.DeviceID)
	session.UserID = strings.TrimSpace(session.UserID)
	session.Username = strings.TrimSpace(session.Username)
	session.ResourceID = strings.TrimSpace(session.ResourceID)
	session.ResourceName = strings.TrimSpace(session.ResourceName)
	session.InternalHost = strings.TrimSpace(session.InternalHost)
	session.Protocol = normalizeProtocol(session.Protocol)
	session.PolicyVersion = strings.TrimSpace(session.PolicyVersion)

	if session.ID == "" {
		return validationError(CodeMissingSessionID, "session_id is required")
	}
	if strings.TrimSpace(rawToken) == "" && strings.TrimSpace(session.TokenHash) == "" {
		return validationError(CodeInvalidToken, "session token is required")
	}
	if session.DeviceID == "" {
		return validationError(CodeBadRequest, "device_id is required")
	}
	if session.ResourceID == "" {
		return validationError(CodeBadRequest, "resource_id is required")
	}
	if session.InternalHost == "" || session.InternalPort <= 0 {
		return validationError(CodeBadRequest, "internal resource host and port are required")
	}
	if session.ExpiresAt.IsZero() || !session.ExpiresAt.After(store.now()) {
		return validationError(CodeSessionExpired, "session expiry must be in the future")
	}
	if session.Protocol == "" {
		session.Protocol = "tcp"
	}
	if strings.TrimSpace(rawToken) != "" {
		session.TokenHash = hashToken(rawToken)
	} else {
		session.TokenHash = strings.TrimSpace(session.TokenHash)
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = store.now()
	}
	session.Constraints = append([]string(nil), session.Constraints...)

	store.mu.Lock()
	defer store.mu.Unlock()
	store.sessions[session.ID] = session
	return nil
}

func (store *Store) Validate(check ConnectCheck) (*Session, error) {
	check.SessionID = strings.TrimSpace(check.SessionID)
	check.SessionToken = strings.TrimSpace(check.SessionToken)
	check.DeviceID = strings.TrimSpace(check.DeviceID)
	check.ResourceID = strings.TrimSpace(check.ResourceID)
	check.Protocol = normalizeProtocol(check.Protocol)

	if check.SessionID == "" {
		return nil, validationError(CodeMissingSessionID, "session_id is required")
	}
	if check.SessionToken == "" {
		return nil, validationError(CodeInvalidToken, "session_token is required")
	}
	if check.DeviceID == "" {
		return nil, validationError(CodeDeviceMismatch, "device identity is required")
	}
	if check.ResourceID == "" {
		return nil, validationError(CodeResourceMismatch, "resource_id is required")
	}
	if check.Protocol == "" {
		return nil, validationError(CodeProtocolMismatch, "protocol is required")
	}
	if check.Port <= 0 {
		return nil, validationError(CodeBadRequest, "remote_port is required")
	}

	store.mu.RLock()
	session, ok := store.sessions[check.SessionID]
	store.mu.RUnlock()
	if !ok {
		return nil, validationError(CodeSessionNotFound, "session was not provisioned by the Policy Administrator")
	}
	if session.Revoked {
		return nil, validationError(CodeSessionRevoked, "session was revoked")
	}
	if !session.ExpiresAt.After(store.now()) {
		return nil, validationError(CodeSessionExpired, "session expired")
	}
	if subtle.ConstantTimeCompare([]byte(session.TokenHash), []byte(hashToken(check.SessionToken))) != 1 {
		return nil, validationError(CodeInvalidToken, "session token is invalid")
	}
	if check.DeviceID != session.DeviceID {
		return nil, validationError(CodeDeviceMismatch, "session device binding mismatch")
	}
	if check.ResourceID != session.ResourceID {
		return nil, validationError(CodeResourceMismatch, "session resource binding mismatch")
	}
	if check.Protocol != session.Protocol {
		return nil, validationError(CodeProtocolMismatch, "session protocol binding mismatch")
	}
	if check.Port != session.InternalPort {
		return nil, validationError(CodeResourceMismatch, "session port binding mismatch")
	}

	copy := session
	copy.Constraints = append([]string(nil), session.Constraints...)
	return &copy, nil
}

func (store *Store) Revoke(sessionID, reason string) (*Session, bool) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, false
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	session, ok := store.sessions[sessionID]
	if !ok {
		return nil, false
	}
	session.Revoked = true
	session.RevokedAt = store.now()
	session.RevocationReason = strings.TrimSpace(reason)
	store.sessions[sessionID] = session
	copy := session
	copy.Constraints = append([]string(nil), session.Constraints...)
	return &copy, true
}

func (store *Store) Delete(sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.sessions[sessionID]; !ok {
		return false
	}
	delete(store.sessions, sessionID)
	return true
}

func (store *Store) Count() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.sessions)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func normalizeProtocol(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

func validationError(code, message string) *ValidationError {
	return &ValidationError{Code: code, Message: message}
}

func AsValidationError(err error) (*ValidationError, bool) {
	if err == nil {
		return nil, false
	}
	if validationErr, ok := err.(*ValidationError); ok {
		return validationErr, true
	}
	return &ValidationError{Code: CodeBadRequest, Message: fmt.Sprintf("invalid session: %v", err)}, false
}
