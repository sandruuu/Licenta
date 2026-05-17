package service

import (
	"context"
	"strings"
	"time"

	"agent/internal/service/deviceidentity"
	"agent/internal/shared/ipc"
)

func (service *Service) refreshIdentitySnapshot(ctx context.Context) {
	if service.identityProvider == nil {
		return
	}
	snapshot, err := service.identityProvider.Snapshot(ctx)
	if err != nil && snapshot.LastError == "" {
		snapshot.LastError = err.Error()
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if strings.TrimSpace(snapshot.ActiveUserSID) != "" {
		service.enrollment.ActiveUserSID = strings.TrimSpace(snapshot.ActiveUserSID)
	}
	if strings.TrimSpace(snapshot.KeyName) != "" {
		service.enrollment.KeyName = strings.TrimSpace(snapshot.KeyName)
	} else {
		service.enrollment.KeyName = deviceidentity.KeyNameForDevice()
	}
	if strings.TrimSpace(snapshot.DeviceID) != "" {
		service.enrollment.DeviceID = strings.TrimSpace(snapshot.DeviceID)
		service.enrollment.DeviceIDSource = strings.TrimSpace(snapshot.DeviceIDSource)
	}
	service.enrollment.KeyExists = snapshot.KeyExists
	service.enrollment.KeyProvider = strings.TrimSpace(snapshot.KeyProvider)
	service.enrollment.IdentityError = strings.TrimSpace(snapshot.LastError)
	if !snapshot.CollectedAt.IsZero() {
		service.enrollment.IdentityCheckedAt = snapshot.CollectedAt.UTC()
	}
}

func (service *Service) State() State {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.state
}

func (service *Service) AuthorizedUserSID() string {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.authorizedUserSID
}

func (service *Service) expectedUserSIDLocked() string {
	if strings.TrimSpace(service.authorizedUserSID) != "" {
		return strings.TrimSpace(service.authorizedUserSID)
	}
	if service.enrollment.State == ipc.EnrollmentStateEnrolled || service.enrollment.State == ipc.EnrollmentStatePending {
		return strings.TrimSpace(service.enrollment.ActiveUserSID)
	}
	return ""
}

func (service *Service) setStartedAt(startedAt time.Time) {
	service.mu.Lock()
	service.startedAt = startedAt
	service.mu.Unlock()
}

func (service *Service) transition(next State) {
	service.mu.Lock()
	service.state = next
	service.mu.Unlock()
	service.logger.Info("ZTNA Agent service state changed", "state", next)
}
