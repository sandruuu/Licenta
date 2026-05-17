package service

import (
	"context"
	"errors"
	"strings"

	"agent/internal/shared/ipc"
)

func (service *Service) sendHeartbeatIfReady(ctx context.Context) error {
	reporter, ok := service.postureReporter.(DeviceHeartbeatReporter)
	if !ok || reporter == nil {
		return nil
	}
	if !service.postureReportingReady() {
		service.setPostureStatus(postureStatusWaitingForEnrollment, "")
		return nil
	}
	service.mu.RLock()
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	service.mu.RUnlock()
	if deviceID == "" {
		return nil
	}
	if err := reporter.SendHeartbeat(ctx, deviceID); err != nil {
		service.mu.Lock()
		service.posture.LastReportError = err.Error()
		service.mu.Unlock()
		return err
	}
	return nil
}

func (service *Service) reportPostureIfReady(ctx context.Context, reason string) (bool, error) {
	if service.postureReporter == nil {
		return false, nil
	}
	if !service.postureReportingReady() {
		service.setPostureStatus(postureStatusWaitingForEnrollment, "")
		return false, nil
	}
	report, err := service.collectDevicePosture(ctx)
	if err != nil {
		return false, err
	}
	return service.sendPostureReport(ctx, report, reason)
}

func (service *Service) reportCriticalPostureIfChanged(ctx context.Context) (bool, error) {
	if service.postureReporter == nil {
		return false, nil
	}
	if !service.postureReportingReady() {
		service.setPostureStatus(postureStatusWaitingForEnrollment, "")
		return false, nil
	}
	previous := service.cachedPostureReport()
	report, err := service.collectDevicePosture(ctx)
	if err != nil {
		return false, err
	}
	if !hasNewCriticalPosture(previous, report) {
		return false, nil
	}
	return service.sendPostureReport(ctx, report, "critical_change")
}

func (service *Service) collectDevicePosture(ctx context.Context) (ipc.DevicePostureReport, error) {
	service.mu.RLock()
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	service.mu.RUnlock()
	report, err := service.postureCollector.Collect(ctx, deviceID)
	service.cachePostureReport(report, err)
	if err != nil {
		return ipc.DevicePostureReport{}, err
	}
	return report, nil
}

func (service *Service) cachePostureReport(report ipc.DevicePostureReport, err error) {
	now := service.clock().UTC()
	service.mu.Lock()
	defer service.mu.Unlock()
	if err != nil {
		service.posture.Status = postureStatusCollectError
		service.posture.LastError = err.Error()
		return
	}
	service.posture.Report = report
	service.posture.Status = postureStatusCollected
	service.posture.LastError = ""
	if !report.CollectedAt.IsZero() {
		service.posture.LastCollectedAt = report.CollectedAt.UTC()
	} else {
		service.posture.LastCollectedAt = now
	}
}

func (service *Service) sendPostureReport(ctx context.Context, report ipc.DevicePostureReport, reason string) (bool, error) {
	if service.postureReporter == nil {
		return false, nil
	}
	if strings.TrimSpace(report.DeviceID) == "" {
		return false, errors.New("device_id is required for posture reporting")
	}
	if err := service.postureReporter.ReportDevicePosture(ctx, report); err != nil {
		service.mu.Lock()
		service.posture.Status = postureStatusReportError
		service.posture.LastReportError = err.Error()
		service.mu.Unlock()
		return false, err
	}
	service.mu.Lock()
	service.posture.Status = postureStatusReported
	service.posture.LastReportError = ""
	service.posture.LastReportedAt = service.clock().UTC()
	service.mu.Unlock()
	service.logger.Info("Device posture reported", "device_id", report.DeviceID, "checks", len(report.Checks), "reason", reason)
	return true, nil
}

func (service *Service) cachedPostureReport() ipc.DevicePostureReport {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return clonePostureReport(service.posture.Report)
}

func (service *Service) postureReportingReady() bool {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.enrollment.State == ipc.EnrollmentStateEnrolled && strings.TrimSpace(service.enrollment.DeviceID) != ""
}

func (service *Service) setPostureStatus(status, lastError string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.posture.Status = status
	service.posture.LastError = strings.TrimSpace(lastError)
}

func clonePostureReport(report ipc.DevicePostureReport) ipc.DevicePostureReport {
	clone := report
	if report.Checks != nil {
		clone.Checks = make([]ipc.DevicePostureCheck, len(report.Checks))
		for index, check := range report.Checks {
			clone.Checks[index] = check
			if check.Details != nil {
				clone.Checks[index].Details = make(map[string]string, len(check.Details))
				for key, value := range check.Details {
					clone.Checks[index].Details[key] = value
				}
			}
		}
	}
	return clone
}

func hasNewCriticalPosture(previous, current ipc.DevicePostureReport) bool {
	previousStatuses := make(map[string]string, len(previous.Checks))
	for _, check := range previous.Checks {
		previousStatuses[strings.ToLower(strings.TrimSpace(check.Name))] = strings.ToLower(strings.TrimSpace(check.Status))
	}
	for _, check := range current.Checks {
		name := strings.ToLower(strings.TrimSpace(check.Name))
		if name != "firewall" && name != "antivirus" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(check.Status))
		if status == ipc.DevicePostureStatusCritical && previousStatuses[name] != ipc.DevicePostureStatusCritical {
			return true
		}
	}
	return false
}

func (service *Service) devicePosture(ctx context.Context) (ipc.DevicePostureReport, string, error) {
	if service.postureCollector == nil {
		return ipc.DevicePostureReport{}, ipc.ErrorCodeServiceUnavailable, errors.New("device posture collector is not configured")
	}
	report, err := service.collectDevicePosture(ctx)
	if err != nil {
		return ipc.DevicePostureReport{}, ipc.ErrorCodeInternal, err
	}
	return report, "", nil
}
