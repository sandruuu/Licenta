package transport

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	paenrollment "pdp/pa/enrollment"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	agentEnrollmentGRPCServiceName         = "trustagent.enrollment.EnrollmentService"
	agentEnrollmentGRPCStartSessionPath    = "/trustagent.enrollment.EnrollmentService/StartSession"
	agentEnrollmentGRPCSessionStatusPath   = "/trustagent.enrollment.EnrollmentService/SessionStatus"
	agentEnrollmentGRPCCompleteSessionPath = "/trustagent.enrollment.EnrollmentService/CompleteSession"
)

type agentEnrollmentGRPCServer interface {
	StartSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	SessionStatus(context.Context, *structpb.Struct) (*structpb.Struct, error)
	CompleteSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

type agentEnrollmentGRPCService struct {
	server *Server
}

func (service *agentEnrollmentGRPCService) StartSession(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Enrollment == nil {
		return nil, status.Error(codes.Internal, "enrollment service is not initialized")
	}
	sourceIP := grpcPeerIP(ctx)
	if sourceIP != "" && !service.server.checkEnrollRateLimit(sourceIP) {
		return nil, status.Error(codes.ResourceExhausted, "too many enrollment attempts")
	}
	hostname := strings.TrimSpace(structFieldString(request, "hostname"))
	publicOrigin, err := service.server.publicOrigin()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	result, err := service.server.pa.Enrollment.StartInteractiveSession(paenrollment.InteractiveStartRequest{
		CSRHash:     strings.TrimSpace(structFieldString(request, "csr_sha256")),
		SPKIHash:    strings.TrimSpace(structFieldString(request, "spki_sha256")),
		DeviceNonce: strings.TrimSpace(structFieldString(request, "device_nonce")),
		Hostname:    hostname,
		SourceIP:    sourceIP,
		AuthURL:     publicOrigin,
	})
	if err != nil {
		return nil, enrollmentGRPCError(err)
	}
	return structpb.NewStruct(map[string]interface{}{
		"enrollment_session_id":  result.SessionID,
		"auth_url":               result.AuthURL,
		"device_challenge":       result.DeviceChallenge,
		"poll_secret":            result.PollSecret,
		"expires_at":             result.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"poll_interval_seconds":  float64(3),
		"status":                 paenrollment.InteractiveStatusWaitingForIDPDiscovery,
		"enrollment_flow":        "trustagent-device-enrollment",
		"browser_transport":      "https",
		"device_proof_required":  true,
		"service_principal_role": "device",
	})
}

func (service *agentEnrollmentGRPCService) SessionStatus(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Enrollment == nil {
		return nil, status.Error(codes.Internal, "enrollment service is not initialized")
	}
	result, err := service.server.pa.Enrollment.InteractiveSessionStatus(
		strings.TrimSpace(structFieldString(request, "enrollment_session_id")),
		strings.TrimSpace(structFieldString(request, "device_nonce")),
		strings.TrimSpace(structFieldString(request, "poll_secret")),
	)
	if err != nil {
		return nil, enrollmentGRPCError(err)
	}
	payload := map[string]interface{}{"status": result.Status}
	if strings.TrimSpace(result.Reason) != "" {
		payload["reason"] = result.Reason
	}
	return structpb.NewStruct(payload)
}

func (service *agentEnrollmentGRPCService) CompleteSession(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Enrollment == nil {
		return nil, status.Error(codes.Internal, "enrollment service is not initialized")
	}
	proof := structFieldStruct(request, "proof")
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(structFieldString(proof, "signature")))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "proof.signature must be base64url")
	}
	if payloadType := strings.TrimSpace(structFieldString(proof, "payload_type")); payloadType != "" && payloadType != paenrollment.InteractiveProofType {
		return nil, status.Error(codes.InvalidArgument, "unsupported proof payload_type")
	}
	publicOrigin, err := service.server.publicOrigin()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	result, err := service.server.pa.Enrollment.CompleteInteractiveSession(paenrollment.InteractiveCompleteRequest{
		SessionID:      strings.TrimSpace(structFieldString(request, "enrollment_session_id")),
		DeviceNonce:    strings.TrimSpace(structFieldString(request, "device_nonce")),
		PollSecret:     strings.TrimSpace(structFieldString(request, "poll_secret")),
		CSRPEM:         strings.TrimSpace(structFieldString(request, "csr_pem")),
		ProofPayload:   []byte(structFieldString(proof, "payload")),
		ProofSignature: signature,
		PDPOrigin:      publicOrigin,
	})
	if err != nil {
		return nil, enrollmentGRPCError(err)
	}
	return structpb.NewStruct(map[string]interface{}{
		"device_id":                  result.DeviceID,
		"auth_realm_id":              result.AuthRealmID,
		"idp_profile_id":             result.IDPProfileID,
		"certificate_pem":            result.CertificatePEM,
		"certificate_chain_pem":      result.CertificateChainPEM,
		"certificate_thumbprint":     result.CertificateThumbprint,
		"expires_at":                 result.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"pdp_endpoint":               publicOrigin,
		"gateway_endpoints":          []interface{}{},
		"enrolled_by_idp_profile_id": result.EnrolledByIDPProfileID,
	})
}

func enrollmentGRPCError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	switch {
	case strings.Contains(message, paenrollment.ErrInvalidRequest.Error()), strings.Contains(message, paenrollment.ErrInvalidCSR.Error()):
		return status.Error(codes.InvalidArgument, message)
	case strings.Contains(message, paenrollment.ErrForbidden.Error()):
		return status.Error(codes.PermissionDenied, message)
	case strings.Contains(message, paenrollment.ErrNotFound.Error()):
		return status.Error(codes.NotFound, message)
	case strings.Contains(message, paenrollment.ErrExpiredSession.Error()), strings.Contains(message, paenrollment.ErrInvalidState.Error()):
		return status.Error(codes.FailedPrecondition, message)
	default:
		return status.Error(codes.Internal, message)
	}
}

func structFieldStruct(value *structpb.Struct, key string) *structpb.Struct {
	if value == nil {
		return nil
	}
	field := value.GetFields()[key]
	if field == nil {
		return nil
	}
	return field.GetStructValue()
}

func (s *Server) publicOrigin() (string, error) {
	callback := strings.TrimSpace(s.appConfig().Public.FederatedCallbackURL)
	if callback != "" {
		if parsed, err := url.Parse(callback); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			return parsed.Scheme + "://" + parsed.Host, nil
		}
	}
	return "", fmt.Errorf("public.federated_callback_url must be configured with an absolute URL")
}

func agentEnrollmentGRPCStartSessionHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentEnrollmentGRPCServer).StartSession(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentEnrollmentGRPCStartSessionPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentEnrollmentGRPCServer).StartSession(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

func agentEnrollmentGRPCSessionStatusHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentEnrollmentGRPCServer).SessionStatus(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentEnrollmentGRPCSessionStatusPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentEnrollmentGRPCServer).SessionStatus(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

func agentEnrollmentGRPCCompleteSessionHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentEnrollmentGRPCServer).CompleteSession(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentEnrollmentGRPCCompleteSessionPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentEnrollmentGRPCServer).CompleteSession(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var agentEnrollmentGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: agentEnrollmentGRPCServiceName,
	HandlerType: (*agentEnrollmentGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "StartSession", Handler: agentEnrollmentGRPCStartSessionHandler},
		{MethodName: "SessionStatus", Handler: agentEnrollmentGRPCSessionStatusHandler},
		{MethodName: "CompleteSession", Handler: agentEnrollmentGRPCCompleteSessionHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "trustagent_enrollment.proto",
}
