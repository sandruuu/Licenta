package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"agent/internal/service/certificates"
	"agent/internal/service/deviceidentity"
	servicestate "agent/internal/service/state"
	"agent/internal/shared/ipc"
)

func (service *Service) persistEnrollmentState(ctx context.Context) {
	if service.stateStore == nil {
		return
	}
	state, ok := service.persistedEnrollmentSnapshot()
	if !ok {
		return
	}
	if err := service.stateStore.Save(ctx, state); err != nil {
		service.setEnrollmentLastError("persist enrollment state: " + err.Error())
		service.logger.Warn("Failed to persist ZTNA Agent enrollment state", "error", err)
	}
}

func (service *Service) persistedEnrollmentSnapshot() (servicestate.Enrollment, bool) {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.enrollment.State != ipc.EnrollmentStateEnrolled {
		return servicestate.Enrollment{}, false
	}
	state := servicestate.Enrollment{
		Version:             servicestate.EnrollmentFileVersion,
		EnrollmentState:     ipc.EnrollmentStateEnrolled,
		DeviceID:            strings.TrimSpace(service.enrollment.DeviceID),
		DeviceIDSource:      strings.TrimSpace(service.enrollment.DeviceIDSource),
		ActiveUserSID:       strings.TrimSpace(service.enrollment.ActiveUserSID),
		KeyName:             strings.TrimSpace(service.enrollment.KeyName),
		KeyProvider:         strings.TrimSpace(service.enrollment.KeyProvider),
		CertificateSHA256:   strings.TrimSpace(service.enrollment.CertificateSHA256),
		CertificateNotAfter: service.enrollment.CertificateNotAfter,
		LastAcceptedAt:      service.enrollment.LastAcceptedAt,
	}
	return state, state.Validate() == nil
}

func (service *Service) restoreEnrollmentState(ctx context.Context) {
	if service.stateStore == nil {
		return
	}
	state, err := service.stateStore.Load(ctx)
	if errors.Is(err, servicestate.ErrEnrollmentNotFound) {
		return
	}
	if err != nil {
		service.setEnrollmentLastError("load enrollment state: " + err.Error())
		service.logger.Warn("Failed to load ZTNA Agent enrollment state", "error", err)
		return
	}
	if err := service.restorePersistedEnrollmentState(ctx, state); err != nil {
		service.setEnrollmentLastError("restore enrollment state: " + err.Error())
		service.logger.Warn("Failed to restore ZTNA Agent enrollment state", "error", err)
	}
}

func (service *Service) restorePersistedEnrollmentState(ctx context.Context, state servicestate.Enrollment) error {
	if err := state.Validate(); err != nil {
		return err
	}
	service.mu.RLock()
	expectedSID := strings.TrimSpace(service.authorizedUserSID)
	currentDeviceID := strings.TrimSpace(service.enrollment.DeviceID)
	currentKeyName := strings.TrimSpace(service.enrollment.KeyName)
	currentKeyProvider := strings.TrimSpace(service.enrollment.KeyProvider)
	service.mu.RUnlock()

	if expectedSID != "" && strings.TrimSpace(state.ActiveUserSID) != expectedSID {
		return fmt.Errorf("persisted active_user_sid does not match authorized user")
	}
	if currentDeviceID != "" && strings.TrimSpace(state.DeviceID) != currentDeviceID {
		return fmt.Errorf("persisted device_id does not match current device identity")
	}
	if currentKeyName != "" && strings.TrimSpace(state.KeyName) != currentKeyName {
		return fmt.Errorf("persisted key_name does not match current device identity")
	}
	keyProvider := firstNonEmptyString(state.KeyProvider, currentKeyProvider, deviceidentity.MicrosoftPlatformCryptoProvider)
	certificate, err := service.certificateLoader(ctx, deviceidentity.MachineCertificateOptions{
		DeviceID:    strings.TrimSpace(state.DeviceID),
		KeyName:     strings.TrimSpace(state.KeyName),
		KeyProvider: keyProvider,
		Clock:       service.clock,
	})
	if err != nil {
		return fmt.Errorf("load Machine Store endpoint certificate: %w", err)
	}
	certificateSHA256, err := certificates.SHA256(certificate)
	if err != nil {
		return err
	}
	certificateNotAfter, err := certificates.NotAfter(certificate)
	if err != nil {
		return err
	}
	if strings.TrimSpace(state.CertificateSHA256) != "" && !strings.EqualFold(strings.TrimSpace(state.CertificateSHA256), certificateSHA256) {
		return fmt.Errorf("persisted certificate_sha256 does not match Machine Store certificate")
	}

	service.mu.Lock()
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = strings.TrimSpace(state.DeviceID)
	service.enrollment.DeviceIDSource = strings.TrimSpace(state.DeviceIDSource)
	service.enrollment.ActiveUserSID = strings.TrimSpace(state.ActiveUserSID)
	service.enrollment.KeyName = strings.TrimSpace(state.KeyName)
	service.enrollment.KeyProvider = keyProvider
	service.enrollment.KeyExists = true
	service.enrollment.CertificateSHA256 = certificateSHA256
	service.enrollment.CertificateNotAfter = certificateNotAfter
	service.enrollment.LastAcceptedAt = state.LastAcceptedAt
	service.enrollment.LastError = ""
	service.mu.Unlock()

	if strings.TrimSpace(state.CertificateSHA256) == "" || !state.CertificateNotAfter.Equal(certificateNotAfter) {
		service.persistEnrollmentState(ctx)
	}
	service.logger.Info("ZTNA Agent enrollment state restored", "device_id", strings.TrimSpace(state.DeviceID), "key_name", strings.TrimSpace(state.KeyName), "certificate_sha256", certificateSHA256)
	return nil
}
