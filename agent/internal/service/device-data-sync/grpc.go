package devicedatasync

import (
	"context"
	"fmt"

	"agent/internal/ipc"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	grpcServiceName          = "trustagent.device.DeviceDataService"
	grpcReportDeviceDataPath = "/" + grpcServiceName + "/ReportDeviceData"
)

type GRPCClient struct {
	connection *grpc.ClientConn
}

func NewGRPCClientFromConnection(connection *grpc.ClientConn) (Client, error) {
	if connection == nil {
		return nil, fmt.Errorf("PDP gRPC connection is required for device data sync")
	}
	return &GRPCClient{connection: connection}, nil
}

func (client *GRPCClient) ReportDeviceData(ctx context.Context, report ipc.DeviceDataReport, session SessionContext) error {
	payload, err := structpb.NewStruct(deviceDataPayload(report, session))
	if err != nil {
		return err
	}
	var response structpb.Struct
	return client.connection.Invoke(ctx, grpcReportDeviceDataPath, payload, &response)
}

func (client *GRPCClient) Close() error {
	return nil
}

func deviceDataPayload(report ipc.DeviceDataReport, session SessionContext) map[string]any {
	checks := make([]any, 0, len(report.Checks))
	for _, check := range report.Checks {
		entry := map[string]any{
			"name":        check.Name,
			"status":      check.Status,
			"description": check.Description,
		}
		if len(check.Details) > 0 {
			details := make(map[string]any, len(check.Details))
			for key, value := range check.Details {
				details[key] = value
			}
			entry["details"] = details
		}
		checks = append(checks, entry)
	}
	payload := map[string]any{
		"device_id":           report.DeviceID,
		"hostname":            report.Hostname,
		"os":                  report.OS,
		"checks":              checks,
		"agent_session_id":    session.AgentSessionID,
		"agent_session_token": session.AgentSessionToken,
	}
	if !report.CollectedAt.IsZero() {
		payload["collected_at"] = report.CollectedAt.UTC().Format(timeRFC3339Nano)
	}
	return payload
}

const timeRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
