package enrollment

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent/internal/shared/ipc"
)

const (
	StatusWaitingForIDPDiscovery = "WAITING_FOR_IDP_DISCOVERY"
	StatusWaitingForUserLogin    = "WAITING_FOR_USER_LOGIN"
	StatusReadyForDeviceProof    = "READY_FOR_DEVICE_PROOF"
	StatusDenied                 = "DENIED"
	ProofType                    = "trustagent-device-enrollment-proof-v1"
)

const (
	DefaultDeviceKeyName = "TrustAgentDeviceKey"
	DefaultTimeout       = 10 * time.Minute
	DefaultPollInterval  = 3 * time.Second

	DefaultCertificateRenewBefore        = 12 * time.Hour
	DefaultCertificateRenewCheckInterval = time.Hour
	DefaultCertificateRenewTimeout       = 20 * time.Second
)

type Config struct {
	PDPGRPCEndpoint               string
	PDPTLSServerName              string
	PDPCAFile                     string
	EnrollmentTimeout             time.Duration
	EnrollmentPollInterval        time.Duration
	CertificateRenewBefore        time.Duration
	CertificateRenewCheckInterval time.Duration
	CertificateRenewTimeout       time.Duration
	EnrollmentStatePath           string
	DeviceKeyName                 string
}

type Dependencies struct {
	Logger         *slog.Logger
	Client         Client
	RenewalClient  RenewalClient
	DeviceIdentity DeviceIdentity
	Store          Store
	Clock          func() time.Time
	OnEnrolled     func()
}

type Client interface {
	StartSession(context.Context, EnrollmentStartSessionRequest) (EnrollmentStartSessionResponse, error)
	SessionStatus(context.Context, EnrollmentSessionStatusRequest) (EnrollmentSessionStatusResponse, error)
	CompleteSession(context.Context, EnrollmentCompleteSessionRequest) (EnrollmentCompleteSessionResponse, error)
	Close() error
}

type RenewalClient interface {
	RenewCertificate(context.Context, EnrollmentRecord, tls.Certificate, CertificateRenewalRequest) (CertificateRenewalResponse, error)
}

type DeviceIdentity interface {
	CreateEnrollmentCSR(context.Context, string) (EnrollmentCSR, error)
	CreateCertificateRenewalCSR(context.Context, string, string) (EnrollmentCSR, error)
	SignEnrollmentProof(context.Context, string, []byte) ([]byte, error)
	InstallDeviceCertificate(context.Context, InstallCertificateRequest) (InstalledCertificate, error)
	CheckLocalEnrollment(context.Context, EnrollmentRecord) (LocalEnrollmentCheck, error)
	ClientCertificate(context.Context, EnrollmentRecord) (tls.Certificate, func(), error)
}

type Store interface {
	Load(context.Context) (EnrollmentRecord, error)
	Save(context.Context, EnrollmentRecord) error
}

type RuntimeState struct {
	State               ipc.EnrollmentState
	DeviceID            string
	Message             string
	LastError           string
	AuthURL             string
	EnrollmentSessionID string
	ExpiresAt           time.Time
}

type EnrollmentRecord struct {
	EnrollmentState           ipc.EnrollmentState `json:"enrollment_state"`
	DeviceID                  string              `json:"device_id,omitempty"`
	DeviceKeyName             string              `json:"device_key_name,omitempty"`
	DeviceKeyProvider         string              `json:"device_key_provider,omitempty"`
	DeviceCertThumbprint      string              `json:"device_cert_thumbprint,omitempty"`
	DeviceCertificateChainPEM string              `json:"device_certificate_chain_pem,omitempty"`
	CertificateExpiry         time.Time           `json:"certificate_expiry,omitempty"`
	PDPEndpoint               string              `json:"pdp_endpoint,omitempty"`
	EnrolledByIDPProfileID    string              `json:"enrolled_by_idp_profile_id,omitempty"`
	UpdatedAt                 time.Time           `json:"updated_at"`
}

type LocalEnrollmentCheck struct {
	Enrolled bool
	Reason   string
}

type EnrollmentCSR struct {
	KeyName     string
	Provider    string
	CSRPEM      string
	CSRDER      []byte
	SPKIDER     []byte
	CSRHash     string
	SPKIHash    string
	DeviceNonce string
}

type EnrollmentStartSessionRequest struct {
	CSRHash       string
	SPKIHash      string
	DeviceNonce   string
	Hostname      string
	AgentPlatform string
	AgentName     string
}

type EnrollmentStartSessionResponse struct {
	EnrollmentSessionID string
	AuthURL             string
	DeviceChallenge     string
	PollSecret          string
	ExpiresAt           time.Time
	PollInterval        time.Duration
}

type EnrollmentSessionStatusRequest struct {
	EnrollmentSessionID string
	DeviceNonce         string
	PollSecret          string
}

type EnrollmentSessionStatusResponse struct {
	Status string
	Reason string
}

type EnrollmentCompleteSessionRequest struct {
	EnrollmentSessionID string
	DeviceNonce         string
	PollSecret          string
	CSRPEM              string
	ProofPayload        []byte
	ProofSignature      []byte
}

type EnrollmentCompleteSessionResponse struct {
	DeviceID               string
	AuthRealmID            string
	IDPProfileID           string
	OrganizationID         string
	CertificatePEM         string
	CertificateChainPEM    string
	CertificateThumbprint  string
	ExpiresAt              time.Time
	PDPEndpoint            string
	EnrolledByIDPProfileID string
}

type CertificateRenewalRequest struct {
	DeviceID             string
	Component            string
	Hostname             string
	CSRPEM               string
	PublicKeyFingerprint string
}

type CertificateRenewalResponse struct {
	CertificatePEM        string
	CertificateChainPEM   string
	CertificateThumbprint string
	ExpiresAt             time.Time
}

type InstallCertificateRequest struct {
	KeyName             string
	KeyProvider         string
	CertificatePEM      string
	CertificateChainPEM string
}

type InstalledCertificate struct {
	Thumbprint string
	ExpiresAt  time.Time
}

type enrollmentProofPayload struct {
	Type                string `json:"typ"`
	EnrollmentSessionID string `json:"enrollment_session_id"`
	DeviceNonce         string `json:"device_nonce"`
	DeviceChallenge     string `json:"device_challenge"`
	CSRHash             string `json:"csr_sha256"`
	SPKIHash            string `json:"spki_sha256"`
	PDPOrigin           string `json:"pdp_origin"`
}

type FileEnrollmentStore struct {
	path string
}

func NewFileEnrollmentStore(path string) *FileEnrollmentStore {
	return &FileEnrollmentStore{path: strings.TrimSpace(path)}
}

func (store *FileEnrollmentStore) Load(_ context.Context) (EnrollmentRecord, error) {
	path, err := store.pathOrDefault()
	if err != nil {
		return EnrollmentRecord{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return EnrollmentRecord{EnrollmentState: ipc.EnrollmentStateUnenrolled}, nil
		}
		return EnrollmentRecord{}, err
	}
	var record EnrollmentRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return EnrollmentRecord{}, fmt.Errorf("decode enrollment state %s: %w", path, err)
	}
	if record.EnrollmentState == "" {
		record.EnrollmentState = ipc.EnrollmentStateUnenrolled
	}
	return record, nil
}

func (store *FileEnrollmentStore) Save(_ context.Context, record EnrollmentRecord) error {
	path, err := store.pathOrDefault()
	if err != nil {
		return err
	}
	record.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode enrollment state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create enrollment state directory: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func (store *FileEnrollmentStore) pathOrDefault() (string, error) {
	if store != nil && strings.TrimSpace(store.path) != "" {
		return filepath.Clean(store.path), nil
	}
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		return "", fmt.Errorf("ProgramData is not set")
	}
	return filepath.Join(programData, "TrustAgent", "enrollment.json"), nil
}

func validateHTTPSURL(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("parse auth url: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("auth url must use https")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("auth url host is required")
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func firstPEMCertificate(rawPEM string) ([]byte, error) {
	remaining := []byte(strings.TrimSpace(rawPEM))
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
		remaining = rest
	}
	return nil, fmt.Errorf("certificate PEM is missing a CERTIFICATE block")
}

func canonicalEnrollmentProof(payload enrollmentProofPayload) ([]byte, error) {
	return json.Marshal(payload)
}
