package enrollment

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"agent/internal/ipc"
)

type Manager struct {
	mu               sync.RWMutex
	logger           *slog.Logger
	config           Config
	client           Client
	renewalClient    RenewalClient
	deviceIdentity   DeviceIdentity
	store            Store
	clock            func() time.Time
	onEnrolled       func()
	enrollment       RuntimeState
	enrollmentCancel context.CancelFunc
	renewalMu        sync.Mutex
}

func NewManager(config Config, dependencies Dependencies) *Manager {
	config = normalizeConfig(config)
	dependencies = dependenciesWithDefaults(config, dependencies)
	return &Manager{
		logger:         dependencies.Logger,
		config:         config,
		client:         dependencies.Client,
		renewalClient:  dependencies.RenewalClient,
		deviceIdentity: dependencies.DeviceIdentity,
		store:          dependencies.Store,
		clock:          dependencies.Clock,
		onEnrolled:     dependencies.OnEnrolled,
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
	if config.CertificateRenewBefore <= 0 {
		config.CertificateRenewBefore = DefaultCertificateRenewBefore
	}
	if config.CertificateRenewCheckInterval <= 0 {
		config.CertificateRenewCheckInterval = DefaultCertificateRenewCheckInterval
	}
	if config.CertificateRenewTimeout <= 0 {
		config.CertificateRenewTimeout = DefaultCertificateRenewTimeout
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
	record, usable, reason, err := manager.usableEnrollmentRecord(ctx)
	if err != nil {
		return EnrollmentRecord{}, err
	}
	if !usable {
		if strings.TrimSpace(reason) != "" {
			return EnrollmentRecord{}, fmt.Errorf("device enrollment is not usable: %s", strings.TrimSpace(reason))
		}
		return EnrollmentRecord{}, fmt.Errorf("device is not enrolled")
	}
	return record, nil
}

func (manager *Manager) usableEnrollmentRecord(ctx context.Context) (EnrollmentRecord, bool, string, error) {
	record, err := manager.store.Load(ctx)
	if err != nil {
		return EnrollmentRecord{}, false, "", err
	}
	if record.EnrollmentState != ipc.EnrollmentStateEnrolled {
		return record, false, "", nil
	}
	check, err := manager.deviceIdentity.CheckLocalEnrollment(ctx, record)
	if err != nil {
		return record, false, err.Error(), nil
	}
	if !check.Enrolled {
		return record, false, strings.TrimSpace(check.Reason), nil
	}
	return record, true, "", nil
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

func (manager *Manager) ensureRenewalClient() RenewalClient {
	manager.mu.RLock()
	client := manager.renewalClient
	manager.mu.RUnlock()
	if client != nil {
		return client
	}
	client = NewHTTPRenewalClient(manager.config)
	manager.mu.Lock()
	if manager.renewalClient == nil {
		manager.renewalClient = client
	} else {
		client = manager.renewalClient
	}
	manager.mu.Unlock()
	return client
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
			ReportedAt:          now,
		}
		manager.mu.Unlock()
		return response, "", nil
	}
	manager.mu.Unlock()

	if record, usable, _, err := manager.usableEnrollmentRecord(ctx); err != nil {
		manager.setEnrollmentFailure(err)
		return ipc.StartEnrollmentInteractiveResponse{}, ipc.ErrorCodeInternal, err
	} else if usable {
		manager.setEnrollmentEnrolled(record)
		return ipc.StartEnrollmentInteractiveResponse{
			Started:    false,
			State:      ipc.EnrollmentStateEnrolled,
			Message:    "Device is already enrolled",
			ReportedAt: now,
		}, "", nil
	}

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
	hostname, _ := os.Hostname()
	startResponse, err := client.StartSession(ctx, EnrollmentStartSessionRequest{
		CSRHash:       csr.CSRHash,
		SPKIHash:      csr.SPKIHash,
		DeviceNonce:   csr.DeviceNonce,
		Hostname:      hostname,
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

	enrollmentCtx, cancel := context.WithCancel(context.Background())
	manager.mu.Lock()
	if manager.enrollmentCancel != nil {
		manager.enrollmentCancel()
	}
	manager.enrollmentCancel = cancel
	manager.enrollment = RuntimeState{
		State:               ipc.EnrollmentStateEnrolling,
		Message:             "Open your browser to verify your identity.",
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
	}
	go manager.runEnrollmentSession(enrollmentCtx, client, session)

	return ipc.StartEnrollmentInteractiveResponse{
		Started:             true,
		AuthURL:             startResponse.AuthURL,
		EnrollmentSessionID: startResponse.EnrollmentSessionID,
		State:               ipc.EnrollmentStateEnrolling,
		Message:             "Open your browser to enroll this device.",
		ExpiresAt:           startResponse.ExpiresAt,
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
	deadline := session.ExpiresAt
	if deadline.IsZero() {
		deadline = manager.clock().UTC().Add(manager.config.EnrollmentTimeout)
	}
	watchCtx, cancel := context.WithDeadline(ctx, deadline.Add(10*time.Second))
	defer cancel()
	completed := false
	err := client.WatchSessionStatus(watchCtx, EnrollmentSessionStatusRequest{
		EnrollmentSessionID: session.EnrollmentSessionID,
		DeviceNonce:         session.CSR.DeviceNonce,
		PollSecret:          session.PollSecret,
	}, func(status EnrollmentSessionStatusResponse) bool {
		completed = manager.handleEnrollmentStatus(ctx, client, session, status)
		return !completed
	})
	if completed || ctx.Err() != nil {
		return
	}
	if err != nil {
		manager.setEnrollmentFailure(err)
		return
	}
	manager.setEnrollmentFailure(fmt.Errorf("enrollment status stream ended before completion"))
}

func (manager *Manager) handleEnrollmentStatus(ctx context.Context, client Client, session enrollmentSession, status EnrollmentSessionStatusResponse) bool {
	switch strings.ToUpper(strings.TrimSpace(status.Status)) {
	case StatusWaitingForIDPDiscovery:
		return false
	case StatusWaitingForUserLogin:
		manager.setEnrollmentMessage("Identity verification is in progress.")
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
		manager.setEnrollmentMessage("Finalizing device enrollment...")
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
	manager.notifyEnrolled()
}

func (manager *Manager) Refresh(ctx context.Context) {
	if manager.isEnrollmentInProgress() {
		return
	}
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
		manager.logger.Warn("Failed to check local enrollment state", "error", err)
		if manager.keepEnrolledAfterTransientCheckFailure(record, err.Error()) {
			return
		}
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "Device is not enrolled", err.Error())
		return
	}
	if !check.Enrolled {
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "Device is not enrolled", check.Reason)
		return
	}
	manager.mu.RLock()
	previous := manager.enrollment
	manager.mu.RUnlock()
	if manager.setEnrollmentRuntime(ipc.EnrollmentStateEnrolled, record.DeviceID, "Device enrolled", "") &&
		(previous.State != ipc.EnrollmentStateEnrolled || previous.DeviceID != record.DeviceID) {
		manager.notifyEnrolled()
	}
}

func (manager *Manager) RunCertificateRenewal(ctx context.Context) {
	if manager == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	manager.renewCertificateWithLogging(ctx, "startup")
	ticker := time.NewTicker(manager.config.CertificateRenewCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			manager.renewCertificateWithLogging(ctx, "periodic")
		}
	}
}

func (manager *Manager) renewCertificateWithLogging(ctx context.Context, reason string) {
	renewed, err := manager.RenewCertificateIfNeeded(ctx)
	if err != nil {
		manager.logger.Warn("Device certificate renewal failed", "reason", strings.TrimSpace(reason), "error", err)
		return
	}
	if renewed {
		manager.logger.Info("Device certificate renewed", "reason", strings.TrimSpace(reason))
	}
}

func (manager *Manager) RenewCertificateIfNeeded(ctx context.Context) (bool, error) {
	if manager == nil {
		return false, fmt.Errorf("enrollment manager is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	manager.renewalMu.Lock()
	defer manager.renewalMu.Unlock()
	if manager.isEnrollmentInProgress() {
		return false, nil
	}

	record, err := manager.store.Load(ctx)
	if err != nil {
		return false, err
	}
	if record.EnrollmentState != ipc.EnrollmentStateEnrolled {
		return false, nil
	}
	check, err := manager.deviceIdentity.CheckLocalEnrollment(ctx, record)
	if err != nil {
		if manager.keepEnrolledAfterTransientCheckFailure(record, err.Error()) {
			return false, err
		}
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "Device is not enrolled", err.Error())
		return false, err
	}
	if !check.Enrolled {
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "Device is not enrolled", check.Reason)
		return false, nil
	}

	expiresAt := record.CertificateExpiry.UTC()
	if expiresAt.IsZero() {
		return false, nil
	}
	now := manager.clock().UTC()
	if !now.Before(expiresAt) {
		manager.setEnrollmentRuntime(ipc.EnrollmentStateUnenrolled, "", "Device is not enrolled", "device certificate is expired")
		return false, nil
	}
	if now.Before(expiresAt.Add(-manager.config.CertificateRenewBefore)) {
		return false, nil
	}

	callCtx, cancel := context.WithTimeout(ctx, manager.config.CertificateRenewTimeout)
	defer cancel()
	updated, err := manager.renewCertificate(callCtx, record)
	if err != nil {
		manager.setEnrollmentRuntime(ipc.EnrollmentStateEnrolled, record.DeviceID, "Device enrolled; certificate renewal failed", err.Error())
		return false, err
	}
	if manager.setEnrollmentRuntime(ipc.EnrollmentStateEnrolled, updated.DeviceID, "Device certificate renewed", "") {
		manager.notifyEnrolled()
	}
	return true, nil
}

func (manager *Manager) keepEnrolledAfterTransientCheckFailure(record EnrollmentRecord, reason string) bool {
	manager.mu.RLock()
	previous := manager.enrollment
	manager.mu.RUnlock()
	if previous.State != ipc.EnrollmentStateEnrolled {
		return false
	}
	deviceID := strings.TrimSpace(record.DeviceID)
	if deviceID == "" {
		deviceID = previous.DeviceID
	}
	if strings.TrimSpace(previous.DeviceID) != "" && deviceID != "" && previous.DeviceID != deviceID {
		return false
	}
	manager.setEnrollmentRuntime(
		ipc.EnrollmentStateEnrolled,
		deviceID,
		"Device enrollment check is temporarily unavailable",
		strings.TrimSpace(reason),
	)
	return true
}

func (manager *Manager) renewCertificate(ctx context.Context, record EnrollmentRecord) (EnrollmentRecord, error) {
	certificate, cleanup, err := manager.deviceIdentity.ClientCertificate(ctx, record)
	if err != nil {
		return EnrollmentRecord{}, fmt.Errorf("load current device certificate: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	keyName := firstNonEmpty(record.DeviceKeyName, manager.config.DeviceKeyName)
	csr, err := manager.deviceIdentity.CreateCertificateRenewalCSR(ctx, keyName, record.DeviceID)
	if err != nil {
		return EnrollmentRecord{}, fmt.Errorf("create renewal CSR: %w", err)
	}
	hostname, _ := os.Hostname()
	response, err := manager.ensureRenewalClient().RenewCertificate(ctx, record, certificate, CertificateRenewalRequest{
		DeviceID:             record.DeviceID,
		Component:            "endpoint",
		Hostname:             hostname,
		CSRPEM:               csr.CSRPEM,
		PublicKeyFingerprint: csr.SPKIHash,
	})
	if err != nil {
		return EnrollmentRecord{}, err
	}
	installed, err := manager.deviceIdentity.InstallDeviceCertificate(ctx, InstallCertificateRequest{
		KeyName:             csr.KeyName,
		KeyProvider:         csr.Provider,
		CertificatePEM:      response.CertificatePEM,
		CertificateChainPEM: response.CertificateChainPEM,
	})
	if err != nil {
		return EnrollmentRecord{}, fmt.Errorf("install renewed certificate: %w", err)
	}

	updated := record
	updated.DeviceKeyName = firstNonEmpty(csr.KeyName, record.DeviceKeyName, manager.config.DeviceKeyName)
	updated.DeviceKeyProvider = firstNonEmpty(csr.Provider, record.DeviceKeyProvider)
	updated.DeviceCertThumbprint = firstNonEmpty(response.CertificateThumbprint, installed.Thumbprint)
	updated.DeviceCertificateChainPEM = firstNonEmpty(response.CertificateChainPEM, record.DeviceCertificateChainPEM)
	updated.CertificateExpiry = response.ExpiresAt
	if updated.CertificateExpiry.IsZero() {
		updated.CertificateExpiry = installed.ExpiresAt
	}
	updated.UpdatedAt = manager.clock().UTC()
	if strings.TrimSpace(updated.DeviceCertThumbprint) == "" {
		return EnrollmentRecord{}, fmt.Errorf("renewed certificate thumbprint is missing")
	}
	if updated.CertificateExpiry.IsZero() {
		return EnrollmentRecord{}, fmt.Errorf("renewed certificate expiry is missing")
	}
	if err := manager.store.Save(ctx, updated); err != nil {
		return EnrollmentRecord{}, err
	}
	return updated, nil
}

func (manager *Manager) setEnrollmentRuntime(state ipc.EnrollmentState, deviceID, message, lastError string) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.enrollment.State == ipc.EnrollmentStateEnrolling {
		return false
	}
	manager.enrollment = RuntimeState{State: state, DeviceID: strings.TrimSpace(deviceID), Message: strings.TrimSpace(message), LastError: strings.TrimSpace(lastError)}
	return true
}

func (manager *Manager) isEnrollmentInProgress() bool {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.enrollment.State == ipc.EnrollmentStateEnrolling
}

func (manager *Manager) notifyEnrolled() {
	if manager != nil && manager.onEnrolled != nil {
		manager.onEnrolled()
	}
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
