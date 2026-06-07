package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"pdp/certs"
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
)

type InteractiveStartRequest struct {
	CSRHash     string
	SPKIHash    string
	DeviceNonce string
	Hostname    string
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
		DeviceChallenge: deviceChallenge,
		PollSecretHash:  sha256HexString(pollSecret),
		Status:          InteractiveStatusWaitingForIDPDiscovery,
		AuthURL:         authBase + "/browser/enroll/" + sessionID,
		CreatedAt:       now,
		ExpiresAt:       expiresAt,
	}

	s.mu.Lock()
	s.interactiveSessions[sessionID] = session
	s.mu.Unlock()

	return &InteractiveStartResult{
		SessionID:       sessionID,
		AuthURL:         session.AuthURL,
		DeviceChallenge: deviceChallenge,
		PollSecret:      pollSecret,
		ExpiresAt:       expiresAt,
	}, nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for id, session := range s.interactiveSessions {
		if session == nil || (!session.ExpiresAt.IsZero() && !now.Before(session.ExpiresAt.UTC())) {
			delete(s.interactiveSessions, id)
			count++
		}
	}
	return count
}

func (s *Service) GetInteractiveSession(sessionID string) (*InteractiveSession, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.interactiveSessions[strings.TrimSpace(sessionID)]
	if !ok || session == nil {
		return nil, false
	}
	copy := *session
	return &copy, true
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.interactiveSessions {
		if session != nil && session.BrowserState == state {
			copy := *session
			return &copy, true
		}
	}
	return nil, false
}

func (s *Service) BeginInteractiveIDPLogin(sessionID string, tenant *models.Tenant, idp *models.IdentityProviderConfig, pkceVerifier, nonce, browserState string) (*InteractiveSession, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	if tenant == nil || strings.TrimSpace(tenant.ID) == "" || idp == nil || strings.TrimSpace(idp.ID) == "" {
		return nil, fmt.Errorf("%w: identity provider is required", ErrInvalidRequest)
	}
	browserState = strings.TrimSpace(browserState)
	if browserState == "" {
		return nil, fmt.Errorf("%w: browser state is required", ErrInvalidRequest)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.interactiveSessions[strings.TrimSpace(sessionID)]
	if !ok || session == nil {
		return nil, ErrNotFound
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		delete(s.interactiveSessions, session.ID)
		return nil, ErrExpiredSession
	}
	if session.AuthRealmID != "" && session.IDPProfileID != "" {
		if session.AuthRealmID != tenant.ID || session.IDPProfileID != idp.ID {
			return nil, fmt.Errorf("%w: identity provider cannot be changed for this enrollment session", ErrForbidden)
		}
	} else if session.Status != InteractiveStatusWaitingForIDPDiscovery {
		return nil, fmt.Errorf("%w: enrollment is not waiting for IdP discovery", ErrInvalidState)
	}
	session.AuthRealmID = tenant.ID
	session.IDPProfileID = idp.ID
	session.ExpectedIssuer = strings.TrimSpace(idp.Issuer)
	session.ExpectedClientID = strings.TrimSpace(idp.ClientID)
	session.BrowserState = browserState
	session.BrowserNonce = strings.TrimSpace(nonce)
	session.PKCEVerifier = strings.TrimSpace(pkceVerifier)
	session.Status = InteractiveStatusWaitingForUserLogin
	copy := *session
	return &copy, nil
}

func (s *Service) CompleteInteractiveIDPLogin(sessionID, subject, email, issuer, userID, username string) (*InteractiveSession, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.interactiveSessions[strings.TrimSpace(sessionID)]
	if !ok || session == nil {
		return nil, ErrNotFound
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		delete(s.interactiveSessions, session.ID)
		return nil, ErrExpiredSession
	}
	if session.Status != InteractiveStatusWaitingForUserLogin {
		return nil, fmt.Errorf("%w: enrollment is not waiting for user login", ErrInvalidState)
	}
	if strings.TrimSpace(subject) == "" {
		return nil, fmt.Errorf("%w: authenticated subject is required", ErrInvalidRequest)
	}
	session.AuthenticatedUserSubject = strings.TrimSpace(subject)
	session.AuthenticatedUserEmail = strings.TrimSpace(email)
	session.AuthenticatedUserIssuer = strings.TrimSpace(issuer)
	session.AuthenticatedUserID = strings.TrimSpace(userID)
	session.AuthenticatedUsername = strings.TrimSpace(username)
	session.Status = InteractiveStatusReadyForDeviceProof
	copy := *session
	return &copy, nil
}

func (s *Service) DenyInteractiveSession(sessionID, reason string) (*InteractiveSession, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.interactiveSessions[strings.TrimSpace(sessionID)]
	if !ok || session == nil {
		return nil, ErrNotFound
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		delete(s.interactiveSessions, session.ID)
		return nil, ErrExpiredSession
	}
	if session.Status == InteractiveStatusEnrolled {
		return nil, fmt.Errorf("%w: enrollment is already completed", ErrInvalidState)
	}
	session.Status = InteractiveStatusDenied
	session.Reason = strings.TrimSpace(reason)
	copy := *session
	return &copy, nil
}

func (s *Service) InteractiveSessionStatus(sessionID, deviceNonce, pollSecret string) (*InteractiveSessionStatus, error) {
	if s == nil {
		return nil, fmt.Errorf("enrollment service not initialized")
	}
	s.mu.Lock()
	session, ok := s.interactiveSessions[strings.TrimSpace(sessionID)]
	defer s.mu.Unlock()
	if !ok || session == nil {
		return nil, ErrNotFound
	}
	if err := validateInteractivePollSecrets(session, deviceNonce, pollSecret); err != nil {
		return nil, err
	}
	if time.Now().UTC().After(session.ExpiresAt) && session.Status != InteractiveStatusEnrolled {
		delete(s.interactiveSessions, session.ID)
		return &InteractiveSessionStatus{Status: InteractiveStatusDenied, Reason: "enrollment_session_expired"}, nil
	}
	return &InteractiveSessionStatus{Status: session.Status, Reason: session.Reason}, nil
}

func (s *Service) CompleteInteractiveSession(req InteractiveCompleteRequest) (*InteractiveCompleteResult, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	if s.interactiveIssuer == nil && s.signer == nil {
		return nil, fmt.Errorf("PKI signer not initialized")
	}

	session, err := s.interactiveSessionForCompletion(req)
	if err != nil {
		return nil, err
	}
	csrPEM, csr, csrDER, spkiHash, err := validateCompletionCSR(req.CSRPEM, session.CSRHash, session.SPKIHash)
	if err != nil {
		return nil, err
	}
	canonicalPayload, err := canonicalEnrollmentProof(EnrollmentProofPayload{
		Type:                InteractiveProofType,
		EnrollmentSessionID: session.ID,
		DeviceNonce:         session.DeviceNonce,
		DeviceChallenge:     session.DeviceChallenge,
		CSRHash:             session.CSRHash,
		SPKIHash:            session.SPKIHash,
		PDPOrigin:           strings.TrimSpace(req.PDPOrigin),
	})
	if err != nil {
		return nil, err
	}
	if len(req.ProofPayload) > 0 && string(req.ProofPayload) != string(canonicalPayload) {
		return nil, fmt.Errorf("%w: proof payload does not match transaction", ErrForbidden)
	}
	if err := verifyEnrollmentProof(csr, canonicalPayload, req.ProofSignature); err != nil {
		return nil, err
	}

	deviceID, err := s.newUniqueDeviceID()
	if err != nil {
		return nil, err
	}
	certBundle, err := s.issueInteractiveCertificate([]byte(csrPEM), deviceID)
	if err != nil {
		return nil, err
	}
	leafPEM, chainPEM := splitCertificateBundle(certBundle)
	if strings.TrimSpace(leafPEM) == "" {
		return nil, fmt.Errorf("%w: certificate bundle is empty", ErrSigning)
	}
	if issuedDeviceID := certificateDeviceID([]byte(leafPEM)); issuedDeviceID != deviceID {
		return nil, fmt.Errorf("%w: issued certificate identity %q does not match PDP device_id %q", ErrSigning, issuedDeviceID, deviceID)
	}
	certThumbprint, _ := certs.CertFingerprint([]byte(leafPEM))
	certSerial := certificateSerial([]byte(leafPEM))
	expiresAt := certificateExpiry([]byte(leafPEM))
	now := time.Now().UTC()
	enrollment := &models.DeviceEnrollment{
		ID:                   session.ID,
		DeviceID:             deviceID,
		Component:            "endpoint",
		Hostname:             session.Hostname,
		PublicKeyFingerprint: spkiHash,
		CertFingerprint:      certThumbprint,
		CertSerial:           certSerial,
		Status:               "approved",
		CSRPEM:               csrPEM,
		CertPEM:              string(certBundle),
		EnrolledAt:           now,
		ExpiresAt:            expiresAt,
		ApprovedBy:           session.AuthenticatedUsername,
		UserID:               session.AuthenticatedUserID,
		Username:             firstNonEmpty(session.AuthenticatedUserEmail, session.AuthenticatedUsername),
		TenantID:             session.AuthRealmID,
	}
	s.store.SaveDeviceEnrollment(enrollment)
	_ = csrDER // kept explicit: CSR DER was validated against session hash above.

	s.mu.Lock()
	delete(s.interactiveSessions, session.ID)
	s.mu.Unlock()

	return &InteractiveCompleteResult{
		DeviceID:               deviceID,
		AuthRealmID:            session.AuthRealmID,
		IDPProfileID:           session.IDPProfileID,
		CertificatePEM:         leafPEM,
		CertificateChainPEM:    chainPEM,
		CertificateThumbprint:  certThumbprint,
		ExpiresAt:              expiresAt,
		EnrolledByIDPProfileID: session.IDPProfileID,
	}, nil
}

func (s *Service) interactiveSessionForCompletion(req InteractiveCompleteRequest) (*InteractiveSession, error) {
	s.mu.RLock()
	session, ok := s.interactiveSessions[strings.TrimSpace(req.SessionID)]
	s.mu.RUnlock()
	if !ok || session == nil {
		return nil, ErrNotFound
	}
	if err := validateInteractivePollSecrets(session, req.DeviceNonce, req.PollSecret); err != nil {
		return nil, err
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, ErrExpiredSession
	}
	if session.Status != InteractiveStatusReadyForDeviceProof {
		return nil, fmt.Errorf("%w: enrollment is not ready for device proof", ErrInvalidState)
	}
	if session.SingleUseConsumed {
		return nil, fmt.Errorf("%w: enrollment session already consumed", ErrForbidden)
	}
	copy := *session
	return &copy, nil
}

func validateInteractivePollSecrets(session *InteractiveSession, deviceNonce, pollSecret string) error {
	if session == nil {
		return ErrNotFound
	}
	if session.DeviceNonce != strings.TrimSpace(deviceNonce) {
		return fmt.Errorf("%w: device_nonce does not match enrollment session", ErrForbidden)
	}
	if session.PollSecretHash != sha256HexString(strings.TrimSpace(pollSecret)) {
		return fmt.Errorf("%w: poll_secret does not match enrollment session", ErrForbidden)
	}
	return nil
}

func validateCompletionCSR(rawCSR, expectedCSRHash, expectedSPKIHash string) (string, *x509.CertificateRequest, []byte, string, error) {
	csrPEM, err := CanonicalCSRPEM(rawCSR)
	if err != nil {
		return "", nil, nil, "", fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	csr, csrDER, err := ParseCSR(csrPEM)
	if err != nil {
		return "", nil, nil, "", fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if hashBytes(csrDER) != normalizeHex(expectedCSRHash) {
		return "", nil, nil, "", fmt.Errorf("%w: CSR hash does not match enrollment session", ErrForbidden)
	}
	spkiHash, err := ComputeCSRFingerprint(csrPEM)
	if err != nil {
		return "", nil, nil, "", fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if normalizeHex(spkiHash) != normalizeHex(expectedSPKIHash) {
		return "", nil, nil, "", fmt.Errorf("%w: SPKI hash does not match enrollment session", ErrForbidden)
	}
	return csrPEM, csr, csrDER, spkiHash, nil
}

func verifyEnrollmentProof(csr *x509.CertificateRequest, payload, signature []byte) error {
	if csr == nil {
		return fmt.Errorf("%w: CSR is required for proof verification", ErrInvalidCSR)
	}
	if len(signature) == 0 {
		return fmt.Errorf("%w: proof signature is required", ErrInvalidRequest)
	}
	digest := sha256.Sum256(payload)
	switch publicKey := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if publicKey.Curve != elliptic.P256() {
			return fmt.Errorf("%w: CSR public key must be ECDSA P-256", ErrInvalidCSR)
		}
		if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
			return fmt.Errorf("%w: proof signature is invalid", ErrForbidden)
		}
	default:
		return fmt.Errorf("%w: unsupported CSR public key type", ErrInvalidCSR)
	}
	return nil
}

func (s *Service) issueInteractiveCertificate(csrPEM []byte, deviceID string) ([]byte, error) {
	role := s.resolveDeviceRole("endpoint")
	if s.interactiveIssuer != nil {
		certPEM, err := s.interactiveIssuer(csrPEM, s.certificateValidityDays, role, deviceID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSigning, err)
		}
		return certPEM, nil
	}
	certPEM, err := s.signer(csrPEM, s.certificateValidityDays, role)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigning, err)
	}
	return certPEM, nil
}

func (s *Service) newUniqueDeviceID() (string, error) {
	for i := 0; i < 8; i++ {
		deviceID, err := util.GenerateID("dev")
		if err != nil {
			return "", err
		}
		if _, found := s.store.GetDeviceEnrollmentByDeviceID(deviceID); !found {
			return deviceID, nil
		}
	}
	return "", fmt.Errorf("failed to allocate unique device_id")
}

func canonicalEnrollmentProof(payload EnrollmentProofPayload) ([]byte, error) {
	return json.Marshal(payload)
}

func randomURLToken(length int) (string, error) {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func sha256HexString(value string) string {
	return hashBytes([]byte(value))
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeHex(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func splitCertificateBundle(bundle []byte) (string, string) {
	remaining := bundle
	var leaf strings.Builder
	var chain strings.Builder
	first := true
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			encoded := string(pem.EncodeToMemory(block))
			if first {
				leaf.WriteString(encoded)
				first = false
			} else {
				chain.WriteString(encoded)
			}
		}
		remaining = rest
	}
	return leaf.String(), chain.String()
}

func certificateExpiry(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Now().UTC().Add(time.Duration(defaultCertificateValidityDays) * 24 * time.Hour)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Now().UTC().Add(time.Duration(defaultCertificateValidityDays) * 24 * time.Hour)
	}
	return cert.NotAfter.UTC()
}

func certificateDeviceID(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return CertificateDeviceID(cert)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
