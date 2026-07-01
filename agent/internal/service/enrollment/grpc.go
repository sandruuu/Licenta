package enrollment

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	pdptransport "agent/internal/service/pdp-transport"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	enrollmentGRPCServiceName         = "trustagent.enrollment.EnrollmentService"
	enrollmentGRPCStartSessionPath    = "/" + enrollmentGRPCServiceName + "/StartSession"
	enrollmentGRPCWatchStatusPath     = "/" + enrollmentGRPCServiceName + "/WatchSessionStatus"
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
		"hostname":       request.Hostname,
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
	}, nil
}

func (client *GRPCEnrollmentClient) WatchSessionStatus(ctx context.Context, request EnrollmentSessionStatusRequest, handler func(EnrollmentSessionStatusResponse) bool) error {
	if handler == nil {
		return fmt.Errorf("enrollment status handler is required")
	}
	payload, err := structpb.NewStruct(map[string]any{
		"enrollment_session_id": request.EnrollmentSessionID,
		"device_nonce":          request.DeviceNonce,
		"poll_secret":           request.PollSecret,
	})
	if err != nil {
		return err
	}
	stream, err := client.connection.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, enrollmentGRPCWatchStatusPath)
	if err != nil {
		return err
	}
	if err := stream.SendMsg(payload); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	for {
		message := &structpb.Struct{}
		if err := stream.RecvMsg(message); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		fields := message.AsMap()
		if !handler(EnrollmentSessionStatusResponse{Status: stringField(fields, "status"), Reason: stringField(fields, "reason", "message")}) {
			return nil
		}
	}
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
		OrganizationID:         stringField(fields, "organization_id"),
		CertificatePEM:         stringField(fields, "certificate_pem", "cert_pem"),
		CertificateChainPEM:    stringField(fields, "certificate_chain_pem", "ca_pem"),
		CertificateThumbprint:  stringField(fields, "certificate_thumbprint"),
		ExpiresAt:              timeField(fields, "expires_at"),
		PDPEndpoint:            stringField(fields, "pdp_endpoint"),
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
