package deviceposture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"ztna.local/agent/internal/ipc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	deviceTelemetryGRPCReportPosturePath = "/ztna.device.v1.DeviceTelemetryService/ReportPosture"
	deviceTelemetryGRPCHeartbeatPath     = "/ztna.device.v1.DeviceTelemetryService/Heartbeat"
)

type GRPCReporterConfig struct {
	CloudURL                  string
	CAFile                    string
	ClientCertificateProvider ClientCertificateProvider
	Timeout                   time.Duration
	DialOptions               []grpc.DialOption
}

type GRPCReporter struct {
	cloudURL                  string
	caFile                    string
	clientCertificateProvider ClientCertificateProvider
	timeout                   time.Duration
	dialOptions               []grpc.DialOption
}

func NewGRPCReporter(config GRPCReporterConfig) (*GRPCReporter, error) {
	cloudURL := strings.TrimSpace(config.CloudURL)
	if cloudURL == "" {
		return nil, errors.New("cloud URL is required")
	}
	if config.ClientCertificateProvider == nil {
		return nil, errors.New("client certificate provider is required")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &GRPCReporter{
		cloudURL:                  cloudURL,
		caFile:                    strings.TrimSpace(config.CAFile),
		clientCertificateProvider: config.ClientCertificateProvider,
		timeout:                   timeout,
		dialOptions:               append([]grpc.DialOption(nil), config.DialOptions...),
	}, nil
}

func (reporter *GRPCReporter) ReportDevicePosture(ctx context.Context, report ipc.DevicePostureReport) error {
	if reporter == nil {
		return errors.New("posture gRPC reporter is nil")
	}
	if strings.TrimSpace(report.DeviceID) == "" {
		return errors.New("device_id is required")
	}
	request, err := postureReportStruct(report)
	if err != nil {
		return err
	}
	var response structpb.Struct
	return reporter.invoke(ctx, report, deviceTelemetryGRPCReportPosturePath, request, &response)
}

func (reporter *GRPCReporter) SendHeartbeat(ctx context.Context, deviceID string) error {
	if reporter == nil {
		return errors.New("posture gRPC reporter is nil")
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
	return reporter.invoke(ctx, ipc.DevicePostureReport{DeviceID: deviceID}, deviceTelemetryGRPCHeartbeatPath, request, &response)
}

func (reporter *GRPCReporter) invoke(ctx context.Context, report ipc.DevicePostureReport, method string, request *structpb.Struct, response *structpb.Struct) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, reporter.timeout)
		defer cancel()
	}
	clientCertificate, err := reporter.clientCertificateProvider(ctx, report)
	if err != nil {
		return fmt.Errorf("load posture gRPC mTLS credential: %w", err)
	}
	target, serverName, err := grpcTargetFromCloudURL(reporter.cloudURL)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCertificate},
	}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}
	if reporter.caFile != "" {
		pool, err := rootCAPool(reporter.caFile)
		if err != nil {
			return err
		}
		tlsConfig.RootCAs = pool
	}
	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	dialOptions = append(dialOptions, reporter.dialOptions...)
	conn, err := grpc.DialContext(ctx, target, dialOptions...)
	if err != nil {
		return fmt.Errorf("dial posture gRPC endpoint: %w", err)
	}
	defer conn.Close()
	if err := conn.Invoke(ctx, method, request, response); err != nil {
		return fmt.Errorf("invoke posture gRPC method %s: %w", method, err)
	}
	return nil
}

func postureReportStruct(report ipc.DevicePostureReport) (*structpb.Struct, error) {
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

func rootCAPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file does not contain PEM certificates")
	}
	return pool, nil
}

func grpcTargetFromCloudURL(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse cloud URL: %w", err)
	}
	host := parsed.Host
	if host == "" && parsed.Scheme == "" && parsed.Path != "" {
		host = parsed.Path
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", errors.New("cloud URL host is required")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			serverName = splitHost
		}
	}
	return host, serverName, nil
}
