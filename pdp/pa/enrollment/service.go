package enrollment

import (
	"errors"
	"sync"
	"time"

	"pdp/models"
	"pdp/store"
)

const (
	defaultCertificateValidityDays   = 1
	defaultBrowserSessionTTL         = 5 * time.Minute
	defaultEnrollmentCleanupInterval = time.Minute
)

var (
	ErrInvalidRequest      = errors.New("invalid enrollment request")
	ErrInvalidCSR          = errors.New("invalid CSR")
	ErrForbidden           = errors.New("forbidden enrollment operation")
	ErrInvalidState        = errors.New("invalid enrollment state")
	ErrExpiredSession      = errors.New("enrollment session expired")
	ErrNotFound            = errors.New("enrollment not found")
	ErrInvalidToken        = errors.New("invalid enrollment token")
	ErrInvalidParentToken  = errors.New("invalid parent token")
	ErrTokenRevoked        = errors.New("token has been revoked")
	ErrTokenAlreadyUsed    = errors.New("enrollment token has already been used")
	ErrNonceGeneration     = errors.New("failed to generate nonce")
	ErrTokenIssue          = errors.New("failed to generate enrollment token")
	ErrSigning             = errors.New("certificate signing failed")
	ErrAlreadyEnrolled     = errors.New("device already has a valid certificate for this component")
	ErrPendingDifferentKey = errors.New("enrollment already pending with a different device key")
)

type PendingEnrollmentAction string

const (
	PendingEnrollmentCreated         PendingEnrollmentAction = "created"
	PendingEnrollmentAlreadyPending  PendingEnrollmentAction = "already_pending"
	PendingEnrollmentAlreadyApproved PendingEnrollmentAction = "already_approved"
)

type PendingEnrollmentResult struct {
	Enrollment *models.DeviceEnrollment
	Action     PendingEnrollmentAction
}

type BrowserEnrollSessionCompletion struct {
	Session    *models.PendingEnrollSession
	Enrollment *models.DeviceEnrollment
	CertPEM    []byte
	Reused     bool
}

type BrowserEnrollSessionStatus struct {
	Status  string
	CertPEM string
	CAPEM   string
	Message string
}

type ESTEnrollmentIdentity struct {
	DeviceID       string
	UserID         string
	Username       string
	TokenID        string
	TokenExpiresAt time.Time
}

type ESTEnrollmentResult struct {
	Enrollment *models.DeviceEnrollment
	CertPEM    []byte
	Reused     bool
}

type EnrollmentTokenParent struct {
	TokenID  string
	Purpose  string
	UserID   string
	Username string
	Role     string
	DeviceID string
}

type EnrollmentTokenIssueRequest struct {
	DeviceID string
	Nonce    string
	UserSID  string
}

type EnrollmentTokenIssueResult struct {
	EnrollmentToken string
	TokenType       string
	ExpiresIn       int
	DeviceID        string
	Nonce           string
	UserSID         string
	UserEmail       string
}

type CertificateSigner func(csrPEM []byte, validDays int, role string) ([]byte, error)

type CertificateRevoker func(serial, certPEM, subjectID string, expiresOn time.Time)

type DeviceRoleResolver func(component string) string

type EnrollmentTokenIssuer func(userID, username, role, deviceID, nonce, userSID string) (string, time.Duration, error)

type InteractiveDeviceCertificateIssuer func(csrPEM []byte, validDays int, role, deviceID string) ([]byte, error)

type EventPublisher interface {
	PublishCAEPEvent(eventType string, fields map[string]string)
}

type Config struct {
	CertificateValidityDays int
	BrowserSessionTTL       time.Duration
}

type Service struct {
	mu                               sync.RWMutex
	store                            *store.Store
	signer                           CertificateSigner
	interactiveIssuer                InteractiveDeviceCertificateIssuer
	revoker                          CertificateRevoker
	deviceRole                       DeviceRoleResolver
	enrollmentTokenIssuer            EnrollmentTokenIssuer
	publisher                        EventPublisher
	certificateValidityDays          int
	browserSessionTTL                time.Duration
	interactiveSessions              map[string]*InteractiveSession
	interactiveSessionExpiredHandler InteractiveSessionExpiredHandler
}

func NewService(store *store.Store, cfgs ...Config) *Service {
	cfg := Config{
		CertificateValidityDays: defaultCertificateValidityDays,
		BrowserSessionTTL:       defaultBrowserSessionTTL,
	}
	if len(cfgs) > 0 {
		if cfgs[0].CertificateValidityDays > 0 {
			cfg.CertificateValidityDays = cfgs[0].CertificateValidityDays
		}
		if cfgs[0].BrowserSessionTTL > 0 {
			cfg.BrowserSessionTTL = cfgs[0].BrowserSessionTTL
		}
	}
	return &Service{
		store:                   store,
		certificateValidityDays: cfg.CertificateValidityDays,
		browserSessionTTL:       cfg.BrowserSessionTTL,
		interactiveSessions:     make(map[string]*InteractiveSession),
	}
}

func (s *Service) SetCertificateAuthority(signer CertificateSigner, revoker CertificateRevoker, deviceRole DeviceRoleResolver) {
	if s == nil {
		return
	}
	s.signer = signer
	s.revoker = revoker
	s.deviceRole = deviceRole
}

func (s *Service) SetEnrollmentTokenIssuer(issuer EnrollmentTokenIssuer) {
	if s == nil {
		return
	}
	s.enrollmentTokenIssuer = issuer
}

func (s *Service) SetInteractiveDeviceCertificateIssuer(issuer InteractiveDeviceCertificateIssuer) {
	if s == nil {
		return
	}
	s.interactiveIssuer = issuer
}

func (s *Service) SetEventPublisher(publisher EventPublisher) {
	if s == nil {
		return
	}
	s.publisher = publisher
}
