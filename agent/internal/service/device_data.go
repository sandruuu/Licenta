package service

import (
	"context"
	"errors"
	"strings"

	"agent/internal/shared/ipc"
)

func (service *Service) collectDeviceData(ctx context.Context, deviceID string) (ipc.DeviceDataReport, error) {
	report, err := service.deviceDataCollector.Collect(ctx, deviceID)
	deviceID = strings.TrimSpace(deviceID)
	if err == nil && deviceID != "" && strings.TrimSpace(report.DeviceID) == "" {
		report.DeviceID = deviceID
	}
	service.cacheDeviceDataReport(report, err)
	if err != nil {
		return ipc.DeviceDataReport{}, err
	}
	service.enforceLocalDevicePosture(ctx, report)
	return report, nil
}

func (service *Service) cacheDeviceDataReport(report ipc.DeviceDataReport, err error) {
	now := service.clock().UTC()
	service.mu.Lock()
	defer service.mu.Unlock()
	if err != nil {
		service.deviceData.Status = deviceDataStatusCollectError
		service.deviceData.LastError = err.Error()
		return
	}
	service.deviceData.Report = report
	service.deviceData.Status = deviceDataStatusCollected
	service.deviceData.LastError = ""
	if !report.CollectedAt.IsZero() {
		service.deviceData.LastCollectedAt = report.CollectedAt.UTC()
	} else {
		service.deviceData.LastCollectedAt = now
	}
}

func (service *Service) cachedDeviceDataReport() ipc.DeviceDataReport {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return cloneDeviceDataReport(service.deviceData.Report)
}

func cloneDeviceDataReport(report ipc.DeviceDataReport) ipc.DeviceDataReport {
	clone := report
	if report.Checks != nil {
		clone.Checks = make([]ipc.DeviceDataCheck, len(report.Checks))
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

func (service *Service) deviceDataReport(ctx context.Context) (ipc.DeviceDataReport, string, error) {
	if service.deviceDataCollector == nil {
		return ipc.DeviceDataReport{}, ipc.ErrorCodeServiceUnavailable, errors.New("device data collector is not configured")
	}
	report, err := service.collectDeviceData(ctx, "")
	if err != nil {
		return ipc.DeviceDataReport{}, ipc.ErrorCodeInternal, err
	}
	return report, "", nil
}
