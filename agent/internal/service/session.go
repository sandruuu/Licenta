package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"agent/internal/shared/ipc"
)

func (service *Service) setAccessToken(accessToken string, expiresAt time.Time, userSID, deviceID string, updatedAt time.Time) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.session.State = sessionStatusReady
	service.session.AccessToken = strings.TrimSpace(accessToken)
	service.session.ExpiresAt = expiresAt
	service.session.UserSID = strings.TrimSpace(userSID)
	service.session.DeviceID = strings.TrimSpace(deviceID)
	service.session.LastUpdatedAt = updatedAt.UTC()
	service.session.LastError = ""
	if service.catalog.Status == catalogStatusTokenRequired {
		service.catalog.LastError = ""
		service.catalog.NextRetryAt = time.Time{}
	}
}

func (service *Service) markSessionExpired(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.session.State = sessionStatusExpired
	service.session.LastError = strings.TrimSpace(message)
	service.appendAccessEventLocked(ipc.AccessEvent{Decision: "deny", Reason: service.session.LastError, Source: "local_session"})
}

func (service *Service) markSessionRejected(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.session.State = sessionStatusRejected
	service.session.LastError = strings.TrimSpace(message)
	service.appendAccessEventLocked(ipc.AccessEvent{Decision: "deny", Reason: service.session.LastError, Source: "local_session"})
}

func (service *Service) updateAccessToken(ctx context.Context, payload ipc.UpdateAccessTokenRequest) (ipc.UpdateAccessTokenResponse, string, error) {
	now := service.clock().UTC()
	userSID, err := localUserSIDFromIPC(ctx, payload.UserSID)
	if err != nil {
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	payload.UserSID = userSID
	if err := validateAccessTokenUpdate(payload, now); err != nil {
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	deviceID := strings.TrimSpace(payload.DeviceID)
	service.mu.RLock()
	expectedSID := service.expectedUserSIDLocked()
	expectedDeviceID := strings.TrimSpace(service.enrollment.DeviceID)
	enrolled := service.enrollment.State == ipc.EnrollmentStateEnrolled || service.enrollment.State == ipc.EnrollmentStatePending
	service.mu.RUnlock()
	if expectedSID != "" && userSID != expectedSID {
		err := errors.New("local user SID does not match authorized user")
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	if expectedDeviceID != "" && deviceID != expectedDeviceID {
		err := errors.New("device_id does not match service state")
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	if !enrolled {
		err := errors.New("service is not enrolled")
		service.markSessionRejected(err.Error())
		return ipc.UpdateAccessTokenResponse{}, ipc.ErrorCodeServiceUnavailable, err
	}
	service.setAccessToken(strings.TrimSpace(payload.AccessToken), payload.ExpiresAt.UTC(), userSID, deviceID, now)
	service.triggerCatalogSyncAfterEnrollment()
	return ipc.UpdateAccessTokenResponse{Accepted: true, DeviceID: deviceID, UserSID: userSID, ExpiresAt: payload.ExpiresAt.UTC(), ReceivedAt: now}, "", nil
}

func validateAccessTokenUpdate(payload ipc.UpdateAccessTokenRequest, now time.Time) error {
	if strings.TrimSpace(payload.AccessToken) == "" {
		return errors.New("access_token is required")
	}
	if len(payload.AccessToken) > maxAccessTokenBytes {
		return fmt.Errorf("access token exceeds %d bytes", maxAccessTokenBytes)
	}
	if strings.Count(payload.AccessToken, ".") != 2 {
		return errors.New("access token must be JWT-shaped")
	}
	if strings.TrimSpace(payload.DeviceID) == "" {
		return errors.New("device_id is required")
	}
	if strings.TrimSpace(payload.UserSID) == "" {
		return errors.New("local user SID is required")
	}
	if payload.ExpiresAt.IsZero() || !payload.ExpiresAt.After(now) {
		return errors.New("expires_at must be in the future")
	}
	return nil
}
