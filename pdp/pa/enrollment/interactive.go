package enrollment

import (
	"fmt"
	"strings"
	"time"

	"pdp/models"
	"pdp/util"
)

const (
	InteractiveStatusWaitingForIDPDiscovery = "WAITING_FOR_IDP_DISCOVERY"
	InteractiveStatusWaitingForUserLogin    = "WAITING_FOR_USER_LOGIN"
	InteractiveStatusReadyForDeviceProof    = "READY_FOR_DEVICE_PROOF"
	InteractiveStatusDenied                 = "DENIED"
	InteractiveStatusEnrolled               = "ENROLLED"

	InteractiveProofType = "trustagent-device-enrollment-proof-v1"

	interactiveSessionStateKind         = "interactive_enroll"
	interactiveSessionExpiredStateGrace = 2 * time.Minute
	interactiveSessionLockTTL           = 2 * time.Minute
	interactiveSessionLockWait          = 15 * time.Second
)

type InteractiveStartRequest struct {
	CSRHash     string
	SPKIHash    string
	DeviceNonce string
	Hostname    string
	SourceIP    string
	AuthURL     string
}

type InteractiveStartResult struct {
	SessionID       string
	AuthURL         string
	DeviceChallenge string
	PollSecret      string
	ExpiresAt       time.Time
}

type InteractiveSession struct {
	ID              string
	CSRHash         string
	SPKIHash        string
	DeviceNonce     string
	Hostname        string
	SourceIP        string
	DeviceChallenge string
	PollSecretHash  string
	Status          string
	Reason          string
	AuthURL         string
	CreatedAt       time.Time
	ExpiresAt       time.Time

	AuthRealmID      string
	IDPProfileID     string
	ExpectedIssuer   string
	ExpectedClientID string
	BrowserState     string
	BrowserNonce     string
	PKCEVerifier     string

	AuthenticatedUserSubject string
	AuthenticatedUserEmail   string
	AuthenticatedUserIssuer  string
	AuthenticatedUserID      string
	AuthenticatedUsername    string

	DeviceID          string
	CertificatePEM    string
	CertificateChain  string
	CertThumbprint    string
	CertificateExpiry time.Time
	SingleUseConsumed bool
}

type InteractiveSessionExpiredHandler func(session InteractiveSession, now time.Time)

type InteractiveSessionStatus struct {
	Status string
	Reason string
}

type InteractiveCompleteRequest struct {
	SessionID      string
	DeviceNonce    string
	PollSecret     string
	CSRPEM         string
	ProofPayload   []byte
	ProofSignature []byte
	PDPOrigin      string
}

type InteractiveCompleteResult struct {
	DeviceID               string
	AuthRealmID            string
	IDPProfileID           string
	CertificatePEM         string
	CertificateChainPEM    string
	CertificateThumbprint  string
	ExpiresAt              time.Time
	PDPEndpoint            string
	EnrolledByIDPProfileID string
}

type EnrollmentProofPayload struct {
	Type                string `json:"typ"`
	EnrollmentSessionID string `json:"enrollment_session_id"`
	DeviceNonce         string `json:"device_nonce"`
	DeviceChallenge     string `json:"device_challenge"`
	CSRHash             string `json:"csr_sha256"`
	SPKIHash            string `json:"spki_sha256"`
	PDPOrigin           string `json:"pdp_origin"`
}

func (s *Service) StartInteractiveSession(req InteractiveStartRequest) (*InteractiveStartResult, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	s.CleanExpiredInteractiveSessions(time.Now().UTC())
	if strings.TrimSpace(req.CSRHash) == "" || strings.TrimSpace(req.SPKIHash) == "" || strings.TrimSpace(req.DeviceNonce) == "" {
		return nil, fmt.Errorf("%w: csr_sha256, spki_sha256 and device_nonce are required", ErrInvalidRequest)
	}
	authBase := strings.TrimRight(strings.TrimSpace(req.AuthURL), "/")
	if authBase == "" {
		return nil, fmt.Errorf("%w: enrollment auth URL base is required", ErrInvalidRequest)
	}
	sessionID, err := util.GenerateID("erq")
	if err != nil {
		return nil, fmt.Errorf("generate enrollment session ID: %w", err)
	}
	deviceChallenge, err := randomURLToken(32)
	if err != nil {
		return nil, err
	}
	pollSecret, err := randomURLToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(s.activeBrowserSessionTTL())

	session := &InteractiveSession{
		ID:              sessionID,
		CSRHash:         normalizeHex(req.CSRHash),
		SPKIHash:        normalizeHex(req.SPKIHash),
		DeviceNonce:     strings.TrimSpace(req.DeviceNonce),
		Hostname:        strings.TrimSpace(req.Hostname),
		SourceIP:        strings.TrimSpace(req.SourceIP),
		DeviceChallenge: deviceChallenge,
		PollSecretHash:  sha256HexString(pollSecret),
		Status:          InteractiveStatusWaitingForIDPDiscovery,
		AuthURL:         authBase + "/enroll/" + sessionID,
		CreatedAt:       now,
		ExpiresAt:       expiresAt,
	}

	if err := s.saveInteractiveSession(session); err != nil {
		return nil, err
	}

	return &InteractiveStartResult{
		SessionID:       sessionID,
		AuthURL:         session.AuthURL,
		DeviceChallenge: deviceChallenge,
		PollSecret:      pollSecret,
		ExpiresAt:       expiresAt,
	}, nil
}

func (s *Service) SetInteractiveSessionExpiredHandler(handler InteractiveSessionExpiredHandler) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.interactiveSessionExpiredHandler = handler
	s.mu.Unlock()
}

func (s *Service) StartCleanupLoop(interval time.Duration, stopChan <-chan struct{}) {
	if s == nil {
		return
	}
	if interval <= 0 {
		interval = defaultEnrollmentCleanupInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				s.CleanExpiredInteractiveSessions(time.Now().UTC())
			}
		}
	}()
}

func (s *Service) CleanExpiredInteractiveSessions(now time.Time) int {
	if s == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	var expired []InteractiveSession
	count := 0
	for _, session := range s.listInteractiveSessions() {
		sessionCopy := session
		if sessionCopy.ID == "" || (!sessionCopy.ExpiresAt.IsZero() && !now.Before(sessionCopy.ExpiresAt.UTC())) {
			count++
			if sessionCopy.ID != "" && sessionCopy.Status != InteractiveStatusDenied && sessionCopy.Status != InteractiveStatusEnrolled {
				expired = append(expired, sessionCopy)
			}
			s.deleteInteractiveSession(sessionCopy.ID)
		}
	}
	notifyInteractiveSessionsExpired(s.expiredHandler(), expired, now)
	return count
}

func (s *Service) ExpireInteractiveSessionIfExpired(sessionID string, now time.Time) bool {
	if s == nil {
		return false
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()

	session, ok := s.getInteractiveSession(sessionID)
	if !ok || session == nil || session.ExpiresAt.IsZero() || now.Before(session.ExpiresAt.UTC()) {
		return false
	}
	var expired *InteractiveSession
	if session.Status != InteractiveStatusDenied && session.Status != InteractiveStatusEnrolled {
		sessionCopy := *session
		expired = &sessionCopy
	}
	s.deleteInteractiveSession(sessionID)

	if expired != nil {
		notifyInteractiveSessionsExpired(s.expiredHandler(), []InteractiveSession{*expired}, now)
	}
	return true
}

func (s *Service) GetInteractiveSession(sessionID string) (*InteractiveSession, bool) {
	if s == nil {
		return nil, false
	}
	return s.getInteractiveSession(sessionID)
}

func (s *Service) HasInteractiveSession(sessionID string) bool {
	_, ok := s.GetInteractiveSession(sessionID)
	return ok
}

func (s *Service) GetInteractiveSessionByBrowserState(state string) (*InteractiveSession, bool) {
	if s == nil {
		return nil, false
	}
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, false
	}
	for _, session := range s.listInteractiveSessions() {
		if session.BrowserState == state {
			sessionCopy := session
			return &sessionCopy, true
		}
	}
	return nil, false
}

func (s *Service) BeginInteractiveIDPLogin(sessionID string, organization *models.Organization, idp *models.IdentityProviderConfig, pkceVerifier, nonce, browserState string) (*InteractiveSession, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	if organization == nil || strings.TrimSpace(organization.ID) == "" || idp == nil || strings.TrimSpace(idp.ID) == "" {
		return nil, fmt.Errorf("%w: identity provider is required", ErrInvalidRequest)
	}
	browserState = strings.TrimSpace(browserState)
	if browserState == "" {
		return nil, fmt.Errorf("%w: browser state is required", ErrInvalidRequest)
	}
	var updated *InteractiveSession
	err := s.withInteractiveSessionLock(sessionID, func() error {
		session, ok := s.getInteractiveSession(sessionID)
		if !ok || session == nil {
			return ErrNotFound
		}
		if time.Now().UTC().After(session.ExpiresAt) {
			s.deleteInteractiveSession(session.ID)
			return ErrExpiredSession
		}
		if session.AuthRealmID != "" && session.IDPProfileID != "" {
			if session.AuthRealmID != organization.ID || session.IDPProfileID != idp.ID {
				return fmt.Errorf("%w: identity provider cannot be changed for this enrollment session", ErrForbidden)
			}
		} else if session.Status != InteractiveStatusWaitingForIDPDiscovery {
			return fmt.Errorf("%w: enrollment is not waiting for IdP discovery", ErrInvalidState)
		}
		session.AuthRealmID = organization.ID
		session.IDPProfileID = idp.ID
		session.ExpectedIssuer = strings.TrimSpace(idp.Issuer)
		session.ExpectedClientID = strings.TrimSpace(idp.ClientID)
		session.BrowserState = browserState
		session.BrowserNonce = strings.TrimSpace(nonce)
		session.PKCEVerifier = strings.TrimSpace(pkceVerifier)
		session.Status = InteractiveStatusWaitingForUserLogin
		if err := s.saveInteractiveSession(session); err != nil {
			return err
		}
		sessionCopy := *session
		updated = &sessionCopy
		return nil
	})
	return updated, err
}

func (s *Service) CompleteInteractiveIDPLogin(sessionID, subject, email, issuer, userID, username string) (*InteractiveSession, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	if strings.TrimSpace(subject) == "" {
		return nil, fmt.Errorf("%w: authenticated subject is required", ErrInvalidRequest)
	}
	var updated *InteractiveSession
	err := s.withInteractiveSessionLock(sessionID, func() error {
		session, ok := s.getInteractiveSession(sessionID)
		if !ok || session == nil {
			return ErrNotFound
		}
		if time.Now().UTC().After(session.ExpiresAt) {
			s.deleteInteractiveSession(session.ID)
			return ErrExpiredSession
		}
		if session.Status != InteractiveStatusWaitingForUserLogin {
			return fmt.Errorf("%w: enrollment is not waiting for user login", ErrInvalidState)
		}
		session.AuthenticatedUserSubject = strings.TrimSpace(subject)
		session.AuthenticatedUserEmail = strings.TrimSpace(email)
		session.AuthenticatedUserIssuer = strings.TrimSpace(issuer)
		session.AuthenticatedUserID = strings.TrimSpace(userID)
		session.AuthenticatedUsername = strings.TrimSpace(username)
		session.Status = InteractiveStatusReadyForDeviceProof
		if err := s.saveInteractiveSession(session); err != nil {
			return err
		}
		sessionCopy := *session
		updated = &sessionCopy
		return nil
	})
	return updated, err
}

func (s *Service) DenyInteractiveSession(sessionID, reason string) (*InteractiveSession, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	var updated *InteractiveSession
	err := s.withInteractiveSessionLock(sessionID, func() error {
		session, ok := s.getInteractiveSession(sessionID)
		if !ok || session == nil {
			return ErrNotFound
		}
		if time.Now().UTC().After(session.ExpiresAt) {
			s.deleteInteractiveSession(session.ID)
			return ErrExpiredSession
		}
		if session.Status == InteractiveStatusEnrolled {
			return fmt.Errorf("%w: enrollment is already completed", ErrInvalidState)
		}
		session.Status = InteractiveStatusDenied
		session.Reason = strings.TrimSpace(reason)
		if err := s.saveInteractiveSession(session); err != nil {
			return err
		}
		sessionCopy := *session
		updated = &sessionCopy
		return nil
	})
	return updated, err
}

func (s *Service) InteractiveSessionStatus(sessionID, deviceNonce, pollSecret string) (*InteractiveSessionStatus, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	var result *InteractiveSessionStatus
	var expired *InteractiveSession
	err := s.withInteractiveSessionLock(sessionID, func() error {
		session, ok := s.getInteractiveSession(sessionID)
		if !ok || session == nil {
			return ErrNotFound
		}
		if err := validateInteractivePollSecrets(session, deviceNonce, pollSecret); err != nil {
			return err
		}
		now := time.Now().UTC()
		if now.After(session.ExpiresAt) && session.Status != InteractiveStatusEnrolled {
			if session.Status != InteractiveStatusDenied {
				expiredCopy := *session
				expired = &expiredCopy
			}
			s.deleteInteractiveSession(session.ID)
			result = &InteractiveSessionStatus{Status: InteractiveStatusDenied, Reason: "enrollment_session_expired"}
			return nil
		}
		result = &InteractiveSessionStatus{Status: session.Status, Reason: session.Reason}
		return nil
	})
	if expired != nil {
		notifyInteractiveSessionsExpired(s.expiredHandler(), []InteractiveSession{*expired}, time.Now().UTC())
	}
	return result, err
}

func notifyInteractiveSessionsExpired(handler InteractiveSessionExpiredHandler, sessions []InteractiveSession, now time.Time) {
	if handler == nil || len(sessions) == 0 {
		return
	}
	for _, session := range sessions {
		handler(session, now)
	}
}
