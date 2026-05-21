package enrollment

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"agent/internal/shared/ipc"
)

type Manager struct {
	mu               sync.RWMutex
	logger           *slog.Logger
	config           Config
	client           Client
	deviceIdentity   DeviceIdentity
	store            Store
	clock            func() time.Time
	enrollment       RuntimeState
	enrollmentCancel context.CancelFunc
}

func NewManager(config Config, dependencies Dependencies) *Manager {
	config = normalizeConfig(config)
	dependencies = dependenciesWithDefaults(config, dependencies)
	return &Manager{
		logger:         dependencies.Logger,
		config:         config,
		client:         dependencies.Client,
		deviceIdentity: dependencies.DeviceIdentity,
		store:          dependencies.Store,
		clock:          dependencies.Clock,
		enrollment:     RuntimeState{State: ipc.EnrollmentStateUnenrolled},
	}
}

func normalizeConfig(config Config) Config {
	config.PDPGRPCEndpoint = strings.TrimSpace(config.PDPGRPCEndpoint)
	config.PDPTLSServerName = strings.TrimSpace(config.PDPTLSServerName)
	config.PDPCAFile = strings.TrimSpace(config.PDPCAFile)
	config.EnrollmentStatePath = strings.TrimSpace(config.EnrollmentStatePath)
	config.DeviceKeyName = strings.TrimSpace(config.DeviceKeyName)
	if config.DeviceKeyName == "" {
		config.DeviceKeyName = DefaultDeviceKeyName
	}
	if config.EnrollmentTimeout <= 0 {
		config.EnrollmentTimeout = DefaultTimeout
	}
	if config.EnrollmentPollInterval <= 0 {
		config.EnrollmentPollInterval = DefaultPollInterval
	}
	return config
}

func dependenciesWithDefaults(config Config, dependencies Dependencies) Dependencies {
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	if dependencies.Clock == nil {
		dependencies.Clock = time.Now
	}
	if strings.TrimSpace(config.EnrollmentStatePath) != "" {
		dependencies.Store = NewFileEnrollmentStore(config.EnrollmentStatePath)
	}
	if dependencies.Store == nil {
		dependencies.Store = NewFileEnrollmentStore("")
	}
	if dependencies.DeviceIdentity == nil {
		dependencies.DeviceIdentity = NewDefaultDeviceIdentity()
	}
	return dependencies
}

func (manager *Manager) Snapshot() RuntimeState {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.enrollment
}

func (manager *Manager) Record(ctx context.Context) (EnrollmentRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	record, err := manager.store.Load(ctx)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	if record.EnrollmentState != ipc.EnrollmentStateEnrolled {
		return EnrollmentRecord{}, fmt.Errorf("device is not enrolled")
	}
	check, err := manager.deviceIdentity.CheckLocalEnrollment(ctx, record)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	if !check.Enrolled {
		return EnrollmentRecord{}, fmt.Errorf("device enrollment is not usable: %s", strings.TrimSpace(check.Reason))
	}
	return record, nil
}

func (manager *Manager) ensureEnrollmentClient(ctx context.Context) (Client, error) {
	manager.mu.RLock()
	client := manager.client
	manager.mu.RUnlock()
	if client != nil {
		return client, nil
	}
	client, err := NewGRPCEnrollmentClient(ctx, manager.config)
	if err != nil {
		return nil, err
	}
	manager.mu.Lock()
	if manager.client == nil {
		manager.client = client
	} else {
		_ = client.Close()
		client = manager.client
	}
	manager.mu.Unlock()
	return client, nil
}

func (manager *Manager) StartInteractive(ctx context.Context) (ipc.StartEnrollmentInteractiveResponse, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := manager.clock().UTC()
	manager.mu.Lock()
	if manager.enrollment.State == ipc.EnrollmentStateEnrolling {
		response := ipc.StartEnrollmentInteractiveResponse{
			Started:             false,
			AuthURL:             manager.enrollment.AuthURL,
			EnrollmentSessionID: manager.enrollment.EnrollmentSessionID,
			State:               manager.enrollment.State,
			Message:             "Enrollment is already running",
			ExpiresAt:           manager.enrollment.ExpiresAt,
			PollIntervalSeconds: int(manager.config.EnrollmentPollInterval.Seconds()),
			ReportedAt:          now,
		}
		manager.mu.Unlock()
		return response, "", nil
	}
	manager.mu.Unlock()

	client, err := manager.ensureEnrollmentClient(ctx)
	if err != nil {
		manager.setEnrollmentFailure(err)
		return ipc.StartEnrollmentInteractiveResponse{}, ipc.ErrorCodeServiceUnavailable, err
	}
	csr, err := manager.deviceIdentity.CreateEnrollmentCSR(ctx, manager.config.DeviceKeyName)
	if err != nil {
		manager.setEnrollmentFailure(err)
		return ipc.StartEnrollmentInteractiveResponse{}, ipc.ErrorCodeInternal, err
	}
	if strings.TrimSpace(csr.DeviceNonce) == "" {
		csr.DeviceNonce, err = randomURLToken(32)
		if err != nil {
			manager.setEnrollmentFailure(err)
			return ipc.StartEnrollmentInteractiveResponse{}, ipc.ErrorCodeInternal, err
		}
	}
	startResponse, err := client.StartSession(ctx, EnrollmentStartSessionRequest{
		CSRHash:       csr.CSRHash,
		SPKIHash:      csr.SPKIHash,
		DeviceNonce:   csr.DeviceNonce,
		AgentPlatform: "windows",
		AgentName:     "TrustAgent",
	})
	if err != nil {
		manager.setEnrollmentFailure(err)
		return ipc.StartEnrollmentInteractiveResponse{}, ipc.ErrorCodeServiceUnavailable, err
	}
	if err := validateStartSessionResponse(startResponse); err != nil {
		manager.setEnrollmentFailure(err)
		return ipc.StartEnrollmentInteractiveResponse{}, ipc.ErrorCodeInvalidRequest, err
	}

	pollInterval := startResponse.PollInterval
	if pollInterval <= 0 {
		pollInterval = manager.config.EnrollmentPollInterval
	}
	enrollmentCtx, cancel := context.WithCancel(context.Background())
	manager.mu.Lock()
	if manager.enrollmentCancel != nil {
		manager.enrollmentCancel()
	}
	manager.enrollmentCancel = cancel
	manager.enrollment = RuntimeState{
		State:               ipc.EnrollmentStateEnrolling,
		Message:             "Open browser to complete identity verification",
		AuthURL:             startResponse.AuthURL,
		EnrollmentSessionID: startResponse.EnrollmentSessionID,
		ExpiresAt:           startResponse.ExpiresAt,
	}
	manager.mu.Unlock()

	session := enrollmentSession{
		CSR:                 csr,
		EnrollmentSessionID: startResponse.EnrollmentSessionID,
		DeviceChallenge:     startResponse.DeviceChallenge,
		PollSecret:          startResponse.PollSecret,
		AuthURL:             startResponse.AuthURL,
		ExpiresAt:           startResponse.ExpiresAt,
		PollInterval:        pollInterval,
	}
	go manager.runEnrollmentSession(enrollmentCtx, client, session)

	return ipc.StartEnrollmentInteractiveResponse{
		Started:             true,
		AuthURL:             startResponse.AuthURL,
		EnrollmentSessionID: startResponse.EnrollmentSessionID,
		State:               ipc.EnrollmentStateEnrolling,
		Message:             "Open browser to complete enrollment",
		ExpiresAt:           startResponse.ExpiresAt,
		PollIntervalSeconds: int(pollInterval.Seconds()),
		ReportedAt:          now,
	}, "", nil
}

type enrollmentSession struct {
	CSR                 EnrollmentCSR
	EnrollmentSessionID string
	DeviceChallenge     string
	PollSecret          string
	AuthURL             string
	ExpiresAt           time.Time
	PollInterval        time.Duration
}

func validateStartSessionResponse(response EnrollmentStartSessionResponse) error {
	if strings.TrimSpace(response.EnrollmentSessionID) == "" {
		return fmt.Errorf("enrollment_session_id is required")
	}
	if err := validateHTTPSURL(response.AuthURL); err != nil {
		return err
	}
	if strings.TrimSpace(response.DeviceChallenge) == "" {
		return fmt.Errorf("device_challenge is required")
	}
	if strings.TrimSpace(response.PollSecret) == "" {
		return fmt.Errorf("poll_secret is required")
	}
	if response.ExpiresAt.IsZero() {
		return fmt.Errorf("expires_at is required")
	}
	return nil
}

func (manager *Manager) runEnrollmentSession(ctx context.Context, client Client, session enrollmentSession) {
	ticker := time.NewTicker(session.PollInterval)
	defer ticker.Stop()
	deadline := session.ExpiresAt
	if deadline.IsZero() {
		deadline = manager.clock().UTC().Add(manager.config.EnrollmentTimeout)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if manager.clock().UTC().After(deadline) {
				manager.setEnrollmentFailure(fmt.Errorf("enrollment session expired"))
				return
			}
			if done := manager.pollEnrollmentSession(ctx, client, session); done {
				return
			}
		}
	}
}

func (manager *Manager) pollEnrollmentSession(ctx context.Context, client Client, session enrollmentSession) bool {
	status, err := client.SessionStatus(ctx, EnrollmentSessionStatusRequest{
		EnrollmentSessionID: session.EnrollmentSessionID,
		DeviceNonce:         session.CSR.DeviceNonce,
		PollSecret:          session.PollSecret,
	})
	if err != nil {
		manager.setEnrollmentMessage("Waiting for browser enrollment status")
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(status.Status)) {
	case StatusWaitingForIDPDiscovery:
		manager.setEnrollmentMessage("Waiting for organization discovery in browser")
		return false
	case StatusWaitingForUserLogin:
		manager.setEnrollmentMessage("Waiting for user login in browser")
		return false
	case StatusReadyForDeviceProof:
		if err := manager.completeEnrollmentSession(ctx, client, session); err != nil {
			manager.setEnrollmentFailure(err)
		}
		return true
	case StatusDenied:
		reason := strings.TrimSpace(status.Reason)
		if reason == "" {
			reason = "authentication_failed_or_policy_denied"
		}
		manager.setEnrollmentFailure(fmt.Errorf("%s", reason))
		return true
	default:
		manager.setEnrollmentMessage("Waiting for PDP enrollment decision")
		return false
	}
}

func (manager *Manager) completeEnrollmentSession(ctx context.Context, client Client, session enrollmentSession) error {
	origin, err := originFromURL(session.AuthURL)
	if err != nil {
		return err
	}
	payload, err := canonicalEnrollmentProof(enrollmentProofPayload{
		Type:                ProofType,
		EnrollmentSessionID: session.EnrollmentSessionID,
		DeviceNonce:         session.CSR.DeviceNonce,
		DeviceChallenge:     session.DeviceChallenge,
		CSRHash:             session.CSR.CSRHash,
		SPKIHash:            session.CSR.SPKIHash,
		PDPOrigin:           origin,
	})
	if err != nil {
		return err
	}
	signature, err := manager.deviceIdentity.SignEnrollmentProof(ctx, session.CSR.KeyName, payload)
	if err != nil {
		return err
	}
	response, err := client.CompleteSession(ctx, EnrollmentCompleteSessionRequest{
		EnrollmentSessionID: session.EnrollmentSessionID,
		DeviceNonce:         session.CSR.DeviceNonce,
		PollSecret:          session.PollSecret,
		CSRPEM:              session.CSR.CSRPEM,
		ProofPayload:        payload,
		ProofSignature:      signature,
	})
	if err != nil {
		return err
	}
	installed, err := manager.deviceIdentity.InstallDeviceCertificate(ctx, InstallCertificateRequest{
		KeyName:             session.CSR.KeyName,
		KeyProvider:         session.CSR.Provider,
		CertificatePEM:      response.CertificatePEM,
		CertificateChainPEM: response.CertificateChainPEM,
	})
	if err != nil {
		return err
	}
	thumbprint := strings.TrimSpace(response.CertificateThumbprint)
	if thumbprint == "" {
		thumbprint = installed.Thumbprint
	}
	expiresAt := response.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = installed.ExpiresAt
	}
	record := EnrollmentRecord{
		EnrollmentState:           ipc.EnrollmentStateEnrolled,
		DeviceID:                  strings.TrimSpace(response.DeviceID),
		DeviceKeyName:             session.CSR.KeyName,
		DeviceKeyProvider:         session.CSR.Provider,
		DeviceCertThumbprint:      thumbprint,
		DeviceCertificateChainPEM: strings.TrimSpace(response.CertificateChainPEM),
		CertificateExpiry:         expiresAt,
		PDPEndpoint:               strings.TrimSpace(response.PDPEndpoint),
		GatewayEndpoints:          response.GatewayEndpoints,
		EnrolledByIDPProfileID:    firstNonEmpty(response.EnrolledByIDPProfileID, response.IDPProfileID),
		UpdatedAt:                 manager.clock().UTC(),
	}
	if err := manager.store.Save(ctx, record); err != nil {
		return err
	}
	manager.setEnrollmentEnrolled(record)
	return nil
}

func originFromURL(rawURL string) (string, error) {
	if err := validateHTTPSURL(rawURL); err != nil {
		return "", err
	}
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func (manager *Manager) setEnrollmentMessage(message string) {
	manager.mu.Lock()
	if manager.enrollment.State == ipc.EnrollmentStateEnrolling {
		manager.enrollment.Message = strings.TrimSpace(message)
	}
	manager.mu.Unlock()
}

func (manager *Manager) setEnrollmentFailure(err error) {
	message := ""
	if err != nil {
		message = strings.TrimSpace(err.Error())
	}
	manager.mu.Lock()
	manager.enrollment.State = ipc.EnrollmentStateFailed
	manager.enrollment.LastError = message
	manager.enrollment.Message = "Enrollment failed"
	if manager.enrollmentCancel != nil {
		manager.enrollmentCancel()
		manager.enrollmentCancel = nil
	}
	manager.mu.Unlock()
}

func (manager *Manager) setEnrollmentEnrolled(record EnrollmentRecord) {
	manager.mu.Lock()
	manager.enrollment = RuntimeState{
		State:    ipc.EnrollmentStateEnrolled,
		DeviceID: record.DeviceID,
		Message:  "Device enrolled successfully",
	}
	if manager.enrollmentCancel != nil {
		manager.enrollmentCancel()
		manager.enrollmentCancel = nil
	}
	manager.mu.Unlock()
}

func (manager *Manager) Refresh(ctx context.Context) {
	record, err := manager.store.Load(ctx)
	if err != nil {
		manager.logger.Warn("Failed to load enrollment state", "error", err)
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "", err.Error())
		return
	}
	if record.EnrollmentState != ipc.EnrollmentStateEnrolled {
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "Device is not enrolled", "")
		return
	}
	check, err := manager.deviceIdentity.CheckLocalEnrollment(ctx, record)
	if err != nil {
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "Device is not enrolled", err.Error())
		return
	}
	if !check.Enrolled {
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "Device is not enrolled", check.Reason)
		return
	}
	manager.setEnrollmentRuntime(ipc.EnrollmentStateEnrolled, record.DeviceID, "Device enrolled", "")
}

func (manager *Manager) setEnrollmentRuntime(state ipc.EnrollmentState, deviceID, message, lastError string) {
	manager.mu.Lock()
	manager.enrollment = RuntimeState{State: state, DeviceID: strings.TrimSpace(deviceID), Message: strings.TrimSpace(message), LastError: strings.TrimSpace(lastError)}
	manager.mu.Unlock()
}

func randomURLToken(length int) (string, error) {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
