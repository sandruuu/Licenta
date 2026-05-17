package enrollment

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

type KeyProvider interface {
	EnsureSigningKey(context.Context, string) (crypto.Signer, error)
}

type CertificateInstaller interface {
	InstallCertificate(context.Context, InstallRequest) (InstallResult, error)
}

type RemoteClient interface {
	EnrollDevice(context.Context, RemoteEnrollInput) (*RemoteCertificateResult, error)
	RenewDeviceCertificate(context.Context, RemoteRenewalInput) (*RemoteCertificateResult, error)
}

type EnrollmentValidator interface {
	ValidateEnrollmentAccessToken(context.Context, ValidationInput) (*ValidationResult, error)
}

type InstallRequest struct {
	CertPEM     []byte
	CAPEM       []byte
	KeyName     string
	KeyProvider string
}

type InstallResult struct {
	Installed bool
	LeafStore string
	CAStore   string
}

type RunnerConfig struct {
	Hostname    string
	Remote      RemoteClient
	KeyProvider KeyProvider
	Installer   CertificateInstaller
}

type ValidationInput struct {
	AccessToken string
	DeviceID    string
	Nonce       string
}

type ValidationResult struct {
	DeviceID  string
	Nonce     string
	UserEmail string
	ExpiresAt time.Time
}

type RunnerInput struct {
	AccessToken string
	Nonce       string
	DeviceID    string
	KeyName     string
	KeyProvider string
	Hostname    string
	UserEmail   string
}

type RenewalInput struct {
	DeviceID           string
	KeyName            string
	KeyProvider        string
	Hostname           string
	CurrentCertificate tls.Certificate
}

type RemoteEnrollInput struct {
	AccessToken          string
	Nonce                string
	DeviceID             string
	Hostname             string
	UserEmail            string
	CSRPEM               []byte
	PublicKeyFingerprint string
	KeyProof             string
}

type RemoteRenewalInput struct {
	DeviceID             string
	Hostname             string
	CSRPEM               []byte
	PublicKeyFingerprint string
	CurrentCertificate   tls.Certificate
}

type RemoteCertificateResult struct {
	ID      string
	CertPEM []byte
	CAPEM   []byte
}

type RunnerResult struct {
	EnrollmentID        string
	CertificateSHA256   string
	CertificateNotAfter time.Time
	Install             InstallResult
}

type Runner struct {
	hostname    string
	remote      RemoteClient
	keyProvider KeyProvider
	installer   CertificateInstaller
}

func ComputeKeyProof(signer crypto.Signer, deviceID, publicKeyFingerprint string) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("signer is required for key proof")
	}
	if deviceID == "" || publicKeyFingerprint == "" {
		return "", fmt.Errorf("device_id and public_key_fingerprint are required for key proof")
	}
	challenge := fmt.Sprintf("ztna-agent-enrollment:%s:%s", deviceID, publicKeyFingerprint)
	hash := sha256.Sum256([]byte(challenge))
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("sign key proof: %w", err)
	}
	return hex.EncodeToString(signature), nil
}

func NewRunner(config RunnerConfig) (*Runner, error) {
	if config.Remote == nil {
		return nil, fmt.Errorf("enrollment remote client is required")
	}
	if config.KeyProvider == nil {
		return nil, fmt.Errorf("key provider is required")
	}
	installer := config.Installer
	if installer == nil {
		installer = NoopCertificateInstaller{}
	}
	return &Runner{
		hostname:    strings.TrimSpace(config.Hostname),
		remote:      config.Remote,
		keyProvider: config.KeyProvider,
		installer:   installer,
	}, nil
}

func (runner *Runner) Enroll(ctx context.Context, input RunnerInput) (*RunnerResult, error) {
	if runner == nil {
		return nil, fmt.Errorf("enrollment runner is nil")
	}
	input.AccessToken = strings.TrimSpace(input.AccessToken)
	input.Nonce = strings.TrimSpace(input.Nonce)
	input.DeviceID = strings.TrimSpace(input.DeviceID)
	input.KeyName = strings.TrimSpace(input.KeyName)
	input.KeyProvider = strings.TrimSpace(input.KeyProvider)
	input.Hostname = strings.TrimSpace(input.Hostname)
	input.UserEmail = strings.TrimSpace(input.UserEmail)
	if input.AccessToken == "" {
		return nil, fmt.Errorf("access token is required")
	}
	if input.DeviceID == "" {
		return nil, fmt.Errorf("device_id is required")
	}
	if input.KeyName == "" {
		return nil, fmt.Errorf("key name is required")
	}
	hostname := firstNonEmpty(input.Hostname, runner.hostname, localHostname())
	signer, err := runner.keyProvider.EnsureSigningKey(ctx, input.KeyName)
	if err != nil {
		return nil, fmt.Errorf("ensure machine TPM key: %w", err)
	}
	csrPEM, err := CreateCSRWithIdentity(signer, CSRIdentity{DeviceID: input.DeviceID, Hostname: hostname, UserEmail: input.UserEmail})
	if err != nil {
		return nil, err
	}
	fingerprint, err := PublicKeyFingerprint(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}
	keyProof, err := ComputeKeyProof(signer, input.DeviceID, fingerprint)
	if err != nil {
		fmt.Printf("WARNING: failed to compute TPM key proof: %v\n", err)
	}
	remoteResult, err := runner.remote.EnrollDevice(ctx, RemoteEnrollInput{
		AccessToken:          input.AccessToken,
		Nonce:                input.Nonce,
		DeviceID:             input.DeviceID,
		Hostname:             hostname,
		UserEmail:            input.UserEmail,
		CSRPEM:               csrPEM,
		PublicKeyFingerprint: fingerprint,
		KeyProof:             keyProof,
	})
	if err != nil {
		return nil, err
	}
	return runner.installResult(ctx, remoteResult, input.KeyName, input.KeyProvider)
}

func (runner *Runner) Renew(ctx context.Context, input RenewalInput) (*RunnerResult, error) {
	if runner == nil {
		return nil, fmt.Errorf("enrollment runner is nil")
	}
	input.DeviceID = strings.TrimSpace(input.DeviceID)
	input.KeyName = strings.TrimSpace(input.KeyName)
	input.KeyProvider = strings.TrimSpace(input.KeyProvider)
	input.Hostname = strings.TrimSpace(input.Hostname)
	if input.DeviceID == "" {
		return nil, fmt.Errorf("device_id is required")
	}
	if input.KeyName == "" {
		return nil, fmt.Errorf("key name is required")
	}
	signer, ok := input.CurrentCertificate.PrivateKey.(crypto.Signer)
	if !ok || signer == nil {
		return nil, fmt.Errorf("current certificate private key must be a crypto.Signer")
	}
	hostname := firstNonEmpty(input.Hostname, runner.hostname, localHostname())
	csrPEM, err := CreateCSRWithIdentity(signer, CSRIdentity{DeviceID: input.DeviceID, Hostname: hostname})
	if err != nil {
		return nil, fmt.Errorf("create renewal CSR: %w", err)
	}
	fingerprint, err := PublicKeyFingerprint(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}
	remoteResult, err := runner.remote.RenewDeviceCertificate(ctx, RemoteRenewalInput{
		DeviceID:             input.DeviceID,
		Hostname:             hostname,
		CSRPEM:               csrPEM,
		PublicKeyFingerprint: fingerprint,
		CurrentCertificate:   input.CurrentCertificate,
	})
	if err != nil {
		return nil, err
	}
	return runner.installResult(ctx, remoteResult, input.KeyName, input.KeyProvider)
}

func (runner *Runner) installResult(ctx context.Context, remoteResult *RemoteCertificateResult, keyName, keyProvider string) (*RunnerResult, error) {
	if remoteResult == nil {
		return nil, fmt.Errorf("enrollment remote returned no result")
	}
	certificateSHA256, err := CertificateSHA256(remoteResult.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("fingerprint enrolled certificate: %w", err)
	}
	certificateNotAfter, err := CertificateNotAfter(remoteResult.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("read enrolled certificate expiry: %w", err)
	}
	installResult, err := runner.installer.InstallCertificate(ctx, InstallRequest{
		CertPEM:     remoteResult.CertPEM,
		CAPEM:       remoteResult.CAPEM,
		KeyName:     keyName,
		KeyProvider: keyProvider,
	})
	if err != nil {
		return nil, fmt.Errorf("install enrolled certificate: %w", err)
	}
	return &RunnerResult{
		EnrollmentID:        remoteResult.ID,
		CertificateSHA256:   certificateSHA256,
		CertificateNotAfter: certificateNotAfter,
		Install:             installResult,
	}, nil
}

type NoopCertificateInstaller struct{}

func (NoopCertificateInstaller) InstallCertificate(context.Context, InstallRequest) (InstallResult, error) {
	return InstallResult{}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func localHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(hostname)
}
