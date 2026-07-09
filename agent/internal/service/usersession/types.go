package usersession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"agent/internal/ipc"
	"agent/internal/service/enrollment"
)

const (
	StatusWaitingForUserLogin = "WAITING_FOR_USER_LOGIN"
	StatusReadyToClaim        = "READY_TO_CLAIM"
	StatusDenied              = "DENIED"
	StatusClaimed             = "CLAIMED"

	DefaultTimeout             = 10 * time.Minute
	DefaultExpiryRevokeLead    = 30 * time.Second
	DefaultExpiryRevokeTimeout = 10 * time.Second
	DefaultSessionRenewBefore  = 2 * time.Minute
	DefaultSessionRenewRetry   = 15 * time.Second
	DefaultSessionRenewTimeout = 10 * time.Second
)

type Config struct {
	LoginTimeout              time.Duration
	SessionRenewBefore        time.Duration
	SessionRenewRetryInterval time.Duration
	TrustedStepUpHosts        []string
}

type Dependencies struct {
	Logger             *slog.Logger
	Client             Client
	ClientFactory      ClientFactory
	Enrollment         EnrollmentProvider
	DeviceDataSnapshot func() ipc.DeviceDataReport
	OnSessionClaimed   func(context.Context, AuthenticatedSession) error
	OnCatalog          func(context.Context, ipc.PeerIdentity, ipc.CatalogInfo) error
	OnLogout           func(context.Context, ipc.PeerIdentity) error
	OnAuthenticated    func(context.Context, ipc.PeerIdentity)
	Clock              func() time.Time
}

type EnrollmentProvider interface {
	Record(context.Context) (enrollment.EnrollmentRecord, error)
}

type Client interface {
	StartSession(context.Context, StartSessionRequest) (StartSessionResponse, error)
	WatchSessionStatus(context.Context, SessionStatusRequest, func(SessionStatusResponse) bool) error
	ClaimSession(context.Context, ClaimSessionRequest) (ClaimSessionResponse, error)
	GetCatalog(context.Context, GetCatalogRequest) (CatalogResponse, error)
	RenewSession(context.Context, RenewSessionRequest) (RenewSessionResponse, error)
	RevokeSession(context.Context, RevokeSessionRequest) error
	Close() error
}

type ClientFactory func(context.Context, Config, enrollment.EnrollmentRecord) (Client, error)

type StartSessionRequest struct {
	DeviceID              string
	AgentVersion          string
	DeviceCertThumbprint  string
	DeviceDataRevision    string
	LocalUserSIDHash      string
	WindowsLogonSessionID string
	WindowsSessionID      string
}

type StartSessionResponse struct {
	SessionRequestID string
	AuthURL          string
	ClaimSecret      string
	ExpiresAt        time.Time
	Status           string
}

type SessionStatusRequest struct {
	SessionRequestID string
	ClaimSecret      string
}

type SessionStatusResponse struct {
	Status string
	Reason string
}

type ClaimSessionRequest struct {
	SessionRequestID      string
	ClaimSecret           string
	DeviceDataRevision    string
	LocalUserSIDHash      string
	WindowsLogonSessionID string
	WindowsSessionID      string
}

type ClaimSessionResponse struct {
	AgentSessionID    string
	AgentSessionToken string
	ExpiresAt         time.Time
	PolicyEpoch       int
	DisplayName       string
	Email             string
}

type RenewSessionRequest struct {
	AgentSessionToken string
	SessionID         string
}

type RenewSessionResponse struct {
	AgentSessionID    string
	AgentSessionToken string
	ExpiresAt         time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	PolicyEpoch       int
}

type GetCatalogRequest struct {
	AgentSessionToken string
	CurrentVersion    string
}

type CatalogResponse struct {
	Version          string
	Resources        []ipc.CatalogResource
	TTLSeconds       int
	PolicyEpoch      string
	DeviceDataPolicy ipc.DeviceDataPolicy
}

type RevokeSessionRequest struct {
	AgentSessionToken string
	SessionID         string
}

type RuntimeState struct {
	UserSession ipc.UserSessionInfo
	Catalog     ipc.CatalogInfo
}

type AuthenticatedSession struct {
	AgentSessionID    string
	AgentSessionToken string
	DisplayName       string
	Email             string
	ExpiresAt         time.Time
	Catalog           ipc.CatalogInfo
	Peer              ipc.PeerIdentity
}

type sessionState struct {
	key               string
	peer              ipc.PeerIdentity
	state             string
	sessionRequestID  string
	claimSecret       string
	authURL           string
	expiresAt         time.Time
	agentSessionID    string
	agentSessionToken string
	displayName       string
	email             string
	message           string
	messageAt         time.Time
	lastError         string
	stepUpURL         string
	stepUpResourceID  string
	stepUpTarget      string
	stepUpExpiresAt   time.Time
	stepUpCancel      context.CancelFunc
	catalog           ipc.CatalogInfo
	cancel            context.CancelFunc
}

type Manager struct {
	mu                 sync.RWMutex
	logger             *slog.Logger
	config             Config
	client             Client
	clientFactory      ClientFactory
	clientDeviceID     string
	clientThumbprint   string
	enrollment         EnrollmentProvider
	deviceDataSnapshot func() ipc.DeviceDataReport
	onSessionClaimed   func(context.Context, AuthenticatedSession) error
	onCatalog          func(context.Context, ipc.PeerIdentity, ipc.CatalogInfo) error
	onLogout           func(context.Context, ipc.PeerIdentity) error
	onAuthenticated    func(context.Context, ipc.PeerIdentity)
	clock              func() time.Time
	sessions           map[string]*sessionState
	signedOutMessages  map[string]string
}

func localUserKey(peer ipc.PeerIdentity) (string, error) {
	if !peer.Verified || strings.TrimSpace(peer.UserSID) == "" {
		return "", fmt.Errorf("verified IPC peer identity is required")
	}
	if strings.TrimSpace(peer.WindowsLogonSessionID) == "" {
		return "", fmt.Errorf("verified Windows logon session is required")
	}
	if strings.TrimSpace(peer.WindowsSessionID) == "" {
		return "", fmt.Errorf("verified Windows session is required")
	}
	return strings.Join([]string{
		strings.TrimSpace(peer.UserSID),
		strings.TrimSpace(peer.WindowsLogonSessionID),
		strings.TrimSpace(peer.WindowsSessionID),
	}, "|"), nil
}

func sidHash(sid string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(sid)))
	return hex.EncodeToString(sum[:])
}
