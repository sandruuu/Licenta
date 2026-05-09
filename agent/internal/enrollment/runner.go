package enrollment

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net/http"
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
	CloudURL    string
	CAFile      string
	Hostname    string
	HTTPClient  *http.Client
	KeyProvider KeyProvider
	Installer   CertificateInstaller
}

type RunnerInput struct {
	Token       string
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

type RunnerResult struct {
	EnrollmentID        string
	CertificateSHA256   string
	CertificateNotAfter time.Time
	Install             InstallResult
}

type Runner struct {
	cloudURL    string
	caFile      string
	hostname    string
	httpClient  *http.Client
	keyProvider KeyProvider
	installer   CertificateInstaller
}

func NewRunner(config RunnerConfig) (*Runner, error) {
	cloudURL := strings.TrimRight(strings.TrimSpace(config.CloudURL), "/")
	if cloudURL == "" {
		return nil, fmt.Errorf("cloud URL is required")
	}
	if config.KeyProvider == nil {
		return nil, fmt.Errorf("key provider is required")
	}
	installer := config.Installer
	if installer == nil {
		installer = NoopCertificateInstaller{}
	}
	return &Runner{
		cloudURL:    cloudURL,
		caFile:      strings.TrimSpace(config.CAFile),
		hostname:    strings.TrimSpace(config.Hostname),
		httpClient:  config.HTTPClient,
		keyProvider: config.KeyProvider,
		installer:   installer,
	}, nil
}

func (runner *Runner) Enroll(ctx context.Context, input RunnerInput) (*RunnerResult, error) {
	if runner == nil {
		return nil, fmt.Errorf("enrollment runner is nil")
	}
	input.Token = strings.TrimSpace(input.Token)
	input.Nonce = strings.TrimSpace(input.Nonce)
	input.DeviceID = strings.TrimSpace(input.DeviceID)
	input.KeyName = strings.TrimSpace(input.KeyName)
	input.KeyProvider = strings.TrimSpace(input.KeyProvider)
	input.Hostname = strings.TrimSpace(input.Hostname)
	input.UserEmail = strings.TrimSpace(input.UserEmail)
	if input.Token == "" {
		return nil, fmt.Errorf("enrollment token is required")
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
	estResult, err := SimpleEnrollWithToken(ctx, TokenEnrollmentConfig{
		CloudURL:   runner.cloudURL,
		CAFile:     runner.caFile,
		Token:      input.Token,
		Nonce:      input.Nonce,
		DeviceID:   input.DeviceID,
		Hostname:   hostname,
		HTTPClient: runner.httpClient,
	}, csrPEM, fingerprint)
	if err != nil {
		return nil, err
	}
	certificateSHA256, err := CertificateSHA256(estResult.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("fingerprint enrolled certificate: %w", err)
	}
	certificateNotAfter, err := CertificateNotAfter(estResult.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("read enrolled certificate expiry: %w", err)
	}
	installResult, err := runner.installer.InstallCertificate(ctx, InstallRequest{
		CertPEM:     estResult.CertPEM,
		CAPEM:       estResult.CAPEM,
		KeyName:     input.KeyName,
		KeyProvider: input.KeyProvider,
	})
	if err != nil {
		return nil, fmt.Errorf("install enrolled certificate: %w", err)
	}
	return &RunnerResult{EnrollmentID: estResult.ID, CertificateSHA256: certificateSHA256, CertificateNotAfter: certificateNotAfter, Install: installResult}, nil
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
	renewalResult, err := RenewWithMTLS(ctx, RenewalConfig{
		CloudURL:             runner.cloudURL,
		CAFile:               runner.caFile,
		DeviceID:             input.DeviceID,
		Hostname:             hostname,
		CSRPEM:               csrPEM,
		PublicKeyFingerprint: fingerprint,
		CurrentCertificate:   input.CurrentCertificate,
	})
	if err != nil {
		return nil, err
	}
	certificateSHA256, err := CertificateSHA256(renewalResult.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("fingerprint renewed certificate: %w", err)
	}
	certificateNotAfter, err := CertificateNotAfter(renewalResult.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("read renewed certificate expiry: %w", err)
	}
	installResult, err := runner.installer.InstallCertificate(ctx, InstallRequest{
		CertPEM:     renewalResult.CertPEM,
		CAPEM:       renewalResult.CAPEM,
		KeyName:     input.KeyName,
		KeyProvider: input.KeyProvider,
	})
	if err != nil {
		return nil, fmt.Errorf("install renewed certificate: %w", err)
	}
	return &RunnerResult{EnrollmentID: renewalResult.ID, CertificateSHA256: certificateSHA256, CertificateNotAfter: certificateNotAfter, Install: installResult}, nil
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
