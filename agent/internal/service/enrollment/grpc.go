package enrollment

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	pdptransport "agent/internal/service/pdp-transport"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	enrollmentGRPCServiceName         = "trustagent.enrollment.EnrollmentService"
	enrollmentGRPCStartSessionPath    = "/" + enrollmentGRPCServiceName + "/StartSession"
	enrollmentGRPCSessionStatusPath   = "/" + enrollmentGRPCServiceName + "/SessionStatus"
	enrollmentGRPCCompleteSessionPath = "/" + enrollmentGRPCServiceName + "/CompleteSession"
)

type GRPCEnrollmentClient struct {
	connection *grpc.ClientConn
}

func NewGRPCEnrollmentClient(ctx context.Context, config Config) (*GRPCEnrollmentClient, error) {
	connection, err := pdptransport.NewClient(pdptransport.Config{
		Endpoint:   config.PDPGRPCEndpoint,
		ServerName: config.PDPTLSServerName,
		CAFile:     config.PDPCAFile,
	}, "enrollment")
	if err != nil {
		return nil, err
	}
	return &GRPCEnrollmentClient{connection: connection}, nil
}

func (client *GRPCEnrollmentClient) StartSession(ctx context.Context, request EnrollmentStartSessionRequest) (EnrollmentStartSessionResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"csr_sha256":     request.CSRHash,
		"spki_sha256":    request.SPKIHash,
		"device_nonce":   request.DeviceNonce,
		"agent_platform": request.AgentPlatform,
		"agent_name":     request.AgentName,
	})
	if err != nil {
		return EnrollmentStartSessionResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, enrollmentGRPCStartSessionPath, payload, &response); err != nil {
		return EnrollmentStartSessionResponse{}, err
	}
	fields := response.AsMap()
	return EnrollmentStartSessionResponse{
		EnrollmentSessionID: stringField(fields, "enrollment_session_id", "session_id"),
		AuthURL:             stringField(fields, "auth_url"),
		DeviceChallenge:     stringField(fields, "device_challenge"),
		PollSecret:          stringField(fields, "poll_secret"),
		ExpiresAt:           timeField(fields, "expires_at"),
		PollInterval:        secondsField(fields, "poll_interval_seconds"),
	}, nil
}

func (client *GRPCEnrollmentClient) SessionStatus(ctx context.Context, request EnrollmentSessionStatusRequest) (EnrollmentSessionStatusResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"enrollment_session_id": request.EnrollmentSessionID,
		"device_nonce":          request.DeviceNonce,
		"poll_secret":           request.PollSecret,
	})
	if err != nil {
		return EnrollmentSessionStatusResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, enrollmentGRPCSessionStatusPath, payload, &response); err != nil {
		return EnrollmentSessionStatusResponse{}, err
	}
	fields := response.AsMap()
	return EnrollmentSessionStatusResponse{Status: stringField(fields, "status"), Reason: stringField(fields, "reason", "message")}, nil
}

func (client *GRPCEnrollmentClient) CompleteSession(ctx context.Context, request EnrollmentCompleteSessionRequest) (EnrollmentCompleteSessionResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"enrollment_session_id": request.EnrollmentSessionID,
		"device_nonce":          request.DeviceNonce,
		"poll_secret":           request.PollSecret,
		"csr_pem":               request.CSRPEM,
		"proof": map[string]any{
			"alg":          "ES256",
			"payload_type": ProofType,
			"payload":      string(request.ProofPayload),
			"signature":    base64.RawURLEncoding.EncodeToString(request.ProofSignature),
		},
	})
	if err != nil {
		return EnrollmentCompleteSessionResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, enrollmentGRPCCompleteSessionPath, payload, &response); err != nil {
		return EnrollmentCompleteSessionResponse{}, err
	}
	fields := response.AsMap()
	return EnrollmentCompleteSessionResponse{
		DeviceID:               stringField(fields, "device_id"),
		AuthRealmID:            stringField(fields, "auth_realm_id"),
		IDPProfileID:           stringField(fields, "idp_profile_id"),
		TenantID:               stringField(fields, "tenant_id"),
		CertificatePEM:         stringField(fields, "certificate_pem", "cert_pem"),
		CertificateChainPEM:    stringField(fields, "certificate_chain_pem", "ca_pem"),
		CertificateThumbprint:  stringField(fields, "certificate_thumbprint"),
		ExpiresAt:              timeField(fields, "expires_at"),
		PDPEndpoint:            stringField(fields, "pdp_endpoint"),
		GatewayEndpoints:       stringSliceField(fields, "gateway_endpoints"),
		EnrolledByIDPProfileID: stringField(fields, "enrolled_by_idp_profile_id"),
	}, nil
}

func (client *GRPCEnrollmentClient) Close() error {
	if client == nil || client.connection == nil {
		return nil
	}
	return client.connection.Close()
}

func stringField(fields map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := fields[name]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func timeField(fields map[string]any, name string) time.Time {
	value := stringField(fields, name)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func secondsField(fields map[string]any, name string) time.Duration {
	value, ok := fields[name]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return time.Duration(typed * float64(time.Second))
	case int:
		return time.Duration(typed) * time.Second
	case string:
		seconds, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return 0
}

func stringSliceField(fields map[string]any, name string) []string {
	value, ok := fields[name]
	if !ok || value == nil {
		return nil
	}
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(fmt.Sprint(item))
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
