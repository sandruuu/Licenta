package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"agent/internal/service/enrollment"
	"agent/internal/shared/ipc"
)

func (service *Service) startEnrollment(ctx context.Context, payload ipc.StartEnrollmentRequest) (ipc.StartEnrollmentResponse, string, error) {
	service.refreshIdentitySnapshot(ctx)
	now := service.clock().UTC()
	userSID, err := localUserSIDFromIPC(ctx, payload.UserSID)
	if err != nil {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	payload.UserSID = userSID
	if !service.rateLimiter.Allow(userSID, now) {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeRateLimited, errors.New("too many enrollment submissions")
	}
	if service.enrollmentValidator == nil {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeServiceUnavailable, errors.New("PA enrollment validator is not configured")
	}
	if err := validateEnrollmentRequest(payload, now); err != nil {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	service.mu.RLock()
	expectedSID := service.expectedUserSIDLocked()
	expectedKeyName := service.enrollment.KeyName
	expectedNonce := service.enrollment.Nonce
	expectedDeviceID := service.enrollment.DeviceID
	service.mu.RUnlock()
	if expectedSID != "" && userSID != expectedSID {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("local user SID does not match authorized user")
	}
	if expectedKeyName != "" && strings.TrimSpace(payload.KeyName) != expectedKeyName {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("key_name does not match service state")
	}
	if expectedNonce != "" && strings.TrimSpace(payload.Nonce) != expectedNonce {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("nonce does not match service state")
	}
	if expectedDeviceID != "" && strings.TrimSpace(payload.DeviceID) != expectedDeviceID {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("device_id does not match service state")
	}
	validation, err := service.enrollmentValidator.ValidateEnrollmentAccessToken(ctx, enrollment.ValidationInput{
		AccessToken: strings.TrimSpace(payload.AccessToken),
		DeviceID:    strings.TrimSpace(payload.DeviceID),
		Nonce:       strings.TrimSpace(payload.Nonce),
	})
	if err != nil {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, fmt.Errorf("validate enrollment access token: %w", err)
	}
	if validation.DeviceID != strings.TrimSpace(payload.DeviceID) {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("device_id does not match PA validation")
	}
	if validation.Nonce != strings.TrimSpace(payload.Nonce) {
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInvalidRequest, errors.New("nonce does not match PA validation")
	}
	service.mu.Lock()
	service.enrollment.State = ipc.EnrollmentStatePending
	service.enrollment.DeviceID = strings.TrimSpace(payload.DeviceID)
	service.enrollment.ActiveUserSID = userSID
	service.enrollment.KeyName = strings.TrimSpace(payload.KeyName)
	service.enrollment.LastError = ""
	service.enrollment.LastAcceptedAt = now
	service.mu.Unlock()
	service.setAccessToken(strings.TrimSpace(payload.AccessToken), payload.AccessTokenExpiresAt.UTC(), userSID, strings.TrimSpace(payload.DeviceID), now)
	service.setSessionUserEmail(firstNonEmptyString(strings.TrimSpace(validation.UserEmail), strings.TrimSpace(payload.UserEmail)))
	service.logger.Info("Enrollment access token accepted by PA", "device_id", strings.TrimSpace(payload.DeviceID), "local_user_sid", userSID, "key_name", strings.TrimSpace(payload.KeyName))
	if service.enrollmentRunner == nil {
		return ipc.StartEnrollmentResponse{
			Accepted:        true,
			Message:         "enrollment access token accepted",
			DeviceID:        strings.TrimSpace(payload.DeviceID),
			ActiveUserSID:   userSID,
			KeyName:         strings.TrimSpace(payload.KeyName),
			ReceivedAt:      now,
			EnrollmentState: ipc.EnrollmentStatePending,
		}, "", nil
	}
	result, err := service.enrollmentRunner.Enroll(ctx, enrollment.RunnerInput{
		AccessToken: strings.TrimSpace(payload.AccessToken),
		Nonce:       strings.TrimSpace(payload.Nonce),
		DeviceID:    strings.TrimSpace(payload.DeviceID),
		KeyName:     strings.TrimSpace(payload.KeyName),
		KeyProvider: expectedEnrollmentKeyProvider(service),
		UserEmail:   firstNonEmptyString(strings.TrimSpace(validation.UserEmail), strings.TrimSpace(payload.UserEmail)),
	})
	if err != nil {
		service.markEnrollmentFailed(err)
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInternal, fmt.Errorf("perform TPM/gRPC enrollment: %w", err)
	}
	if result == nil {
		err := errors.New("enrollment runner returned no result")
		service.markEnrollmentFailed(err)
		return ipc.StartEnrollmentResponse{}, ipc.ErrorCodeInternal, err
	}
	service.mu.Lock()
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.CertificateSHA256 = result.CertificateSHA256
	service.enrollment.CertificateNotAfter = result.CertificateNotAfter
	service.enrollment.KeyExists = true
	service.enrollment.LastError = ""
	service.mu.Unlock()
	service.refreshIdentitySnapshot(ctx)
	service.persistEnrollmentState(ctx)
	service.triggerPostureReportAfterEnrollment()
	service.triggerCatalogSyncAfterEnrollment()
	service.logger.Info("Endpoint certificate enrolled", "device_id", strings.TrimSpace(payload.DeviceID), "local_user_sid", userSID, "certificate_sha256", result.CertificateSHA256)
	return ipc.StartEnrollmentResponse{
		Accepted:        true,
		Message:         "endpoint certificate enrolled",
		DeviceID:        strings.TrimSpace(payload.DeviceID),
		ActiveUserSID:   userSID,
		KeyName:         strings.TrimSpace(payload.KeyName),
		ReceivedAt:      now,
		EnrollmentState: ipc.EnrollmentStateEnrolled,
	}, "", nil
}

func localUserSIDFromIPC(ctx context.Context, payloadSID string) (string, error) {
	payloadSID = strings.TrimSpace(payloadSID)
	peerIdentity, ok := ipc.PeerIdentityFromContext(ctx)
	if !ok {
		if payloadSID == "" {
			return "", errors.New("local user SID is required")
		}
		return payloadSID, nil
	}
	if strings.TrimSpace(peerIdentity.VerificationError) != "" {
		return "", fmt.Errorf("verify local IPC client SID: %s", strings.TrimSpace(peerIdentity.VerificationError))
	}
	peerSID := strings.TrimSpace(peerIdentity.UserSID)
	if !peerIdentity.Verified || peerSID == "" {
		return "", errors.New("local IPC client SID could not be verified")
	}
	if payloadSID != "" && payloadSID != peerSID {
		return "", errors.New("local user SID does not match IPC client")
	}
	return peerSID, nil
}

func (service *Service) triggerPostureReportAfterEnrollment() {
	if service.postureReporter == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), service.postureReportTimeout)
		defer cancel()
		_, _ = service.reportPostureIfReady(ctx, "enrollment")
	}()
}

func (service *Service) triggerCatalogSyncAfterEnrollment() {
	if service.catalogClient == nil || service.dnsConfigurator == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), service.postureReportTimeout)
		defer cancel()
		_, _ = service.syncDeviceCatalogIfReady(ctx)
	}()
}

func expectedEnrollmentKeyProvider(service *Service) string {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return strings.TrimSpace(service.enrollment.KeyProvider)
}
