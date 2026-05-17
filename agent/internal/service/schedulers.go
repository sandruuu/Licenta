package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"agent/internal/service/certificates"
	"agent/internal/service/deviceidentity"
	"agent/internal/service/enrollment"
	"agent/internal/shared/ipc"
)

func (service *Service) startPostureReporting(ctx context.Context) {
	if service.postureReporter == nil {
		return
	}
	go service.runPostureReporting(ctx)
}

func (service *Service) runPostureReporting(ctx context.Context) {
	reportTicker := time.NewTicker(service.postureInterval)
	defer reportTicker.Stop()
	criticalTicker := time.NewTicker(service.criticalInterval)
	defer criticalTicker.Stop()
	heartbeatTicker := time.NewTicker(service.heartbeatInterval)
	defer heartbeatTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reportTicker.C:
			_, _ = service.reportPostureIfReady(ctx, "periodic")
		case <-criticalTicker.C:
			_, _ = service.reportCriticalPostureIfChanged(ctx)
		case <-heartbeatTicker.C:
			_ = service.sendHeartbeatIfReady(ctx)
		}
	}
}

func (service *Service) startCatalogSync(ctx context.Context) {
	if service.catalogClient == nil || service.dnsConfigurator == nil {
		return
	}
	go service.runCatalogSync(ctx)
}

func (service *Service) runCatalogSync(ctx context.Context) {
	ticker := time.NewTicker(service.catalogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = service.syncDeviceCatalogIfReady(ctx)
		}
	}
}

func (service *Service) startCertificateRenewal(ctx context.Context) {
	if service.enrollmentRenewer == nil {
		return
	}
	go service.runCertificateRenewal(ctx)
}

func (service *Service) runCertificateRenewal(ctx context.Context) {
	_, _ = service.renewCertificateIfNeeded(ctx, "startup")
	ticker := time.NewTicker(service.certificateRenewalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = service.renewCertificateIfNeeded(ctx, "periodic")
		}
	}
}

func (service *Service) renewCertificateIfNeeded(ctx context.Context, reason string) (bool, error) {
	if service.enrollmentRenewer == nil {
		return false, nil
	}
	service.mu.RLock()
	ready := service.enrollment.State == ipc.EnrollmentStateEnrolled && strings.TrimSpace(service.enrollment.DeviceID) != "" && strings.TrimSpace(service.enrollment.KeyName) != ""
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	keyName := strings.TrimSpace(service.enrollment.KeyName)
	keyProvider := strings.TrimSpace(service.enrollment.KeyProvider)
	service.mu.RUnlock()
	if !ready {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, service.certificateRenewalTimeout)
		defer cancel()
	}
	certificate, err := service.certificateLoader(ctx, deviceidentity.MachineCertificateOptions{
		DeviceID:    deviceID,
		KeyName:     keyName,
		KeyProvider: keyProvider,
		Clock:       service.clock,
	})
	if err != nil {
		service.setEnrollmentLastError("certificate renewal check: " + err.Error())
		return false, err
	}
	certificateNotAfter, err := certificates.NotAfter(certificate)
	if err != nil {
		service.setEnrollmentLastError("certificate renewal check: " + err.Error())
		return false, err
	}
	service.mu.Lock()
	service.enrollment.CertificateNotAfter = certificateNotAfter
	service.mu.Unlock()
	if !certificateNeedsRenewal(certificateNotAfter, service.clock().UTC(), service.certificateRenewBefore) {
		return false, nil
	}
	result, err := service.enrollmentRenewer.Renew(ctx, enrollment.RenewalInput{
		DeviceID:           deviceID,
		KeyName:            keyName,
		KeyProvider:        firstNonEmptyString(keyProvider, deviceidentity.MicrosoftPlatformCryptoProvider),
		CurrentCertificate: certificate,
	})
	if err != nil {
		service.setEnrollmentLastError("renew endpoint certificate: " + err.Error())
		service.logger.Warn("Endpoint certificate renewal failed", "device_id", deviceID, "reason", reason, "error", err)
		return false, err
	}
	if result == nil {
		err := errors.New("certificate renewal returned no result")
		service.setEnrollmentLastError("renew endpoint certificate: " + err.Error())
		return false, err
	}
	if strings.TrimSpace(result.CertificateSHA256) == "" {
		err := errors.New("certificate renewal returned no certificate fingerprint")
		service.setEnrollmentLastError("renew endpoint certificate: " + err.Error())
		return false, err
	}
	service.mu.Lock()
	service.enrollment.CertificateSHA256 = strings.TrimSpace(result.CertificateSHA256)
	service.enrollment.CertificateNotAfter = result.CertificateNotAfter
	service.enrollment.KeyExists = true
	service.enrollment.LastError = ""
	service.mu.Unlock()
	service.persistEnrollmentState(ctx)
	service.logger.Info("Endpoint certificate renewed", "device_id", deviceID, "reason", reason, "certificate_sha256", result.CertificateSHA256, "expires", result.CertificateNotAfter.Format(time.RFC3339))
	return true, nil
}

func certificateNeedsRenewal(notAfter, now time.Time, renewBefore time.Duration) bool {
	if notAfter.IsZero() {
		return false
	}
	if renewBefore <= 0 {
		return false
	}
	return !notAfter.After(now.Add(renewBefore))
}
