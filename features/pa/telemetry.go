package pa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"licenta/features/contracts"

	"google.golang.org/protobuf/types/known/structpb"
)

func (client *Client) ReportDevicePosture(ctx context.Context, report contracts.DevicePostureReport) error {
	if client == nil {
		return errors.New("PA client is nil")
	}
	if strings.TrimSpace(report.DeviceID) == "" {
		return errors.New("device_id is required")
	}
	request, err := postureReportStruct(report)
	if err != nil {
		return err
	}
	var response structpb.Struct
	return client.invoke(ctx, deviceTelemetryReportPosturePath, request, &response, invokeOptions{UseMachineCertificate: true})
}

func (client *Client) SendHeartbeat(ctx context.Context, deviceID string) error {
	if client == nil {
		return errors.New("PA client is nil")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return errors.New("device_id is required")
	}
	request, err := structpb.NewStruct(map[string]interface{}{"device_id": deviceID})
	if err != nil {
		return fmt.Errorf("build heartbeat request: %w", err)
	}
	var response structpb.Struct
	return client.invoke(ctx, deviceTelemetryHeartbeatPath, request, &response, invokeOptions{UseMachineCertificate: true})
}
func postureReportStruct(report contracts.DevicePostureReport) (*structpb.Struct, error) {
	checks := make([]interface{}, 0, len(report.Checks))
	for _, check := range report.Checks {
		item := map[string]interface{}{
			"name":        check.Name,
			"status":      check.Status,
			"description": check.Description,
		}
		if len(check.Details) > 0 {
			details := make(map[string]interface{}, len(check.Details))
			for key, value := range check.Details {
				details[key] = value
			}
			item["details"] = details
		}
		checks = append(checks, item)
	}
	payload := map[string]interface{}{
		"device_id": report.DeviceID,
		"hostname":  report.Hostname,
		"os":        report.OS,
		"checks":    checks,
	}
	if !report.CollectedAt.IsZero() {
		payload["collected_at"] = report.CollectedAt.UTC().Format(time.RFC3339Nano)
	}
	return structpb.NewStruct(payload)
}
