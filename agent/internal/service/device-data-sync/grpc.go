package devicedatasync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"agent/internal/service/enrollment"
	"agent/internal/shared/ipc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	grpcServiceName          = "trustagent.device.DeviceDataService"
	grpcReportDeviceDataPath = "/" + grpcServiceName + "/ReportDeviceData"
)

type ClientConfig struct {
	PDPGRPCEndpoint  string
	PDPTLSServerName string
	PDPCAFile        string
}

type GRPCClient struct {
	connection *grpc.ClientConn
	cleanup    func()
}

func NewGRPCClient(ctx context.Context, config ClientConfig, record enrollment.EnrollmentRecord, identity enrollment.DeviceIdentity) (Client, error) {
	target := strings.TrimSpace(config.PDPGRPCEndpoint)
	if target == "" {
		return nil, fmt.Errorf("pdp_grpc_endpoint is required for device data sync")
	}
	if identity == nil {
		identity = enrollment.NewDefaultDeviceIdentity()
	}
	certificate, cleanup, err := identity.ClientCertificate(ctx, record)
	if err != nil {
		return nil, fmt.Errorf("load device client certificate: %w", err)
	}
	tlsConfig, err := tlsConfig(config, certificate)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	connection, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("create PDP device data gRPC client: %w", err)
	}
	return &GRPCClient{connection: connection, cleanup: cleanup}, nil
}

func tlsConfig(config ClientConfig, certificate tls.Certificate) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   strings.TrimSpace(config.PDPTLSServerName),
		Certificates: []tls.Certificate{certificate},
	}
	if strings.TrimSpace(config.PDPCAFile) == "" {
		return tlsConfig, nil
	}
	caPEM, err := os.ReadFile(strings.TrimSpace(config.PDPCAFile))
	if err != nil {
		return nil, fmt.Errorf("read pdp_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("pdp_ca_file contains no certificates")
	}
	tlsConfig.RootCAs = pool
	return tlsConfig, nil
}

func (client *GRPCClient) ReportDeviceData(ctx context.Context, report ipc.DeviceDataReport) error {
	payload, err := structpb.NewStruct(deviceDataPayload(report))
	if err != nil {
		return err
	}
	var response structpb.Struct
	return client.connection.Invoke(ctx, grpcReportDeviceDataPath, payload, &response)
}

func (client *GRPCClient) Close() error {
	if client == nil {
		return nil
	}
	if client.cleanup != nil {
		client.cleanup()
		client.cleanup = nil
	}
	if client.connection != nil {
		return client.connection.Close()
	}
	return nil
}

func deviceDataPayload(report ipc.DeviceDataReport) map[string]any {
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
		"device_id": report.DeviceID,
		"hostname":  report.Hostname,
		"os":        report.OS,
		"checks":    checks,
	}
	if !report.CollectedAt.IsZero() {
		payload["collected_at"] = report.CollectedAt.UTC().Format(timeRFC3339Nano)
	}
	return payload
}

const timeRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
