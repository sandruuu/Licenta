package service

import (
	"context"
	"errors"

	"agent/internal/shared/ipc"
)

func (service *Service) collectDevicePosture(ctx context.Context) (ipc.DevicePostureReport, error) {
	report, err := service.postureCollector.Collect(ctx, "")
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

func (service *Service) cachedPostureReport() ipc.DevicePostureReport {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return clonePostureReport(service.posture.Report)
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
