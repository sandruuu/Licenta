package transport

import (
	"context"
	"strings"
	"time"

	"pdp/models"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	gatewayTrustGRPCServiceName            = "gateway.GatewayTrustService"
	gatewayTrustGRPCGetCACertificatePath   = "/gateway.GatewayTrustService/GetCACertificate"
	gatewayTrustGRPCGetRevokedSerialsPath  = "/gateway.GatewayTrustService/GetRevokedSerials"
	gatewayTrustGRPCRevalidateSessionsPath = "/gateway.GatewayTrustService/RevalidateSessions"
)

type gatewayTrustGRPCServer interface {
	GetCACertificate(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetRevokedSerials(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RevalidateSessions(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

type gatewayTrustGRPCService struct {
	server *Server
}

func (service *gatewayTrustGRPCService) GetCACertificate(ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil {
		return nil, status.Error(codes.Internal, "gateway trust service is not initialized")
	}
	if _, err := service.authenticateGateway(ctx); err != nil {
		return nil, err
	}
	caPEM, err := service.server.getCAPEM()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "CA certificate is not available")
	}
	return structpb.NewStruct(map[string]interface{}{"ca_pem": string(caPEM)})
}

func (service *gatewayTrustGRPCService) GetRevokedSerials(ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Store == nil {
		return nil, status.Error(codes.Internal, "gateway trust service is not initialized")
	}
	if _, err := service.authenticateGateway(ctx); err != nil {
		return nil, err
	}
	serials := service.server.pa.Store.GetRevokedSerials()
	values := make([]interface{}, 0, len(serials))
	for _, serial := range serials {
		values = append(values, serial)
	}
	return structpb.NewStruct(map[string]interface{}{"revoked_serials": values})
}

func (service *gatewayTrustGRPCService) RevalidateSessions(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Store == nil {
		return nil, status.Error(codes.Internal, "gateway trust service is not initialized")
	}
	gateway, err := service.authenticateGateway(ctx)
	if err != nil {
		return nil, err
	}
	invalid := service.invalidGatewaySessions(gateway, request)
	values := make([]interface{}, 0, len(invalid))
	for _, result := range invalid {
		values = append(values, map[string]interface{}{
			"session_id": result.SessionID,
			"status":     result.Status,
			"reason":     result.Reason,
		})
	}
	return structpb.NewStruct(map[string]interface{}{"invalid_sessions": values})
}

type gatewaySessionRevalidationResult struct {
	SessionID string
	Status    string
	Reason    string
}

func (service *gatewayTrustGRPCService) invalidGatewaySessions(gateway *models.Gateway, request *structpb.Struct) []gatewaySessionRevalidationResult {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Store == nil || gateway == nil || request == nil {
		return nil
	}
	field := request.GetFields()["sessions"]
	if field == nil || field.GetListValue() == nil {
		return nil
	}
	now := time.Now().UTC()
	var invalid []gatewaySessionRevalidationResult
	for _, value := range field.GetListValue().GetValues() {
		reported := value.GetStructValue()
		if reported == nil {
			continue
		}
		sessionID := strings.TrimSpace(structFieldString(reported, "session_id"))
		if sessionID == "" {
			continue
		}
		session, ok := service.server.pa.Store.GetSession(sessionID)
		statusValue, reason := validateReportedGatewaySession(gateway, session, ok, reported, now)
		if statusValue == "valid" {
			continue
		}
		invalid = append(invalid, gatewaySessionRevalidationResult{
			SessionID: sessionID,
			Status:    statusValue,
			Reason:    reason,
		})
	}
	return invalid
}

func validateReportedGatewaySession(gateway *models.Gateway, session *models.Session, found bool, reported *structpb.Struct, now time.Time) (string, string) {
	if !found || session == nil {
		return "not_found", "session_not_found_in_pa"
	}
	if session.Revoked {
		return "revoked", "session_revoked_in_pa"
	}
	if !session.ExpiresAt.After(now) {
		return "expired", "session_expired_in_pa"
	}
	if strings.TrimSpace(session.GatewayID) != strings.TrimSpace(gateway.ID) {
		return "gateway_mismatch", "session_belongs_to_different_gateway"
	}
	if reportedStringMismatch(reported, "device_id", session.DeviceID) {
		return "device_mismatch", "reported_device_does_not_match_pa_session"
	}
	if reportedStringMismatch(reported, "resource_id", session.Resource) {
		return "resource_mismatch", "reported_resource_does_not_match_pa_session"
	}
	if reportedStringMismatchFold(reported, "protocol", session.Protocol) {
		return "protocol_mismatch", "reported_protocol_does_not_match_pa_session"
	}
	return "valid", ""
}

func reportedStringMismatch(reported *structpb.Struct, field, expected string) bool {
	value := strings.TrimSpace(structFieldString(reported, field))
	return value != "" && value != strings.TrimSpace(expected)
}

func reportedStringMismatchFold(reported *structpb.Struct, field, expected string) bool {
	value := strings.TrimSpace(structFieldString(reported, field))
	return value != "" && !strings.EqualFold(value, strings.TrimSpace(expected))
}

func (service *gatewayTrustGRPCService) authenticateGateway(ctx context.Context) (*models.Gateway, error) {
	peerCert, ok := clientCertificateFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client certificate required for gateway trust service")
	}
	gateway, statusCode, errorMessage := service.server.authenticateGatewayCertificate(peerCert)
	if statusCode != 0 {
		return nil, status.Error(grpcCodeForHTTPStatus(statusCode), errorMessage)
	}
	return gateway, nil
}

func gatewayTrustGRPCGetCACertificateHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(gatewayTrustGRPCServer).GetCACertificate(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: gatewayTrustGRPCGetCACertificatePath}
	return interceptor(ctx, request, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(gatewayTrustGRPCServer).GetCACertificate(ctx, req.(*structpb.Struct))
	})
}

func gatewayTrustGRPCGetRevokedSerialsHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(gatewayTrustGRPCServer).GetRevokedSerials(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: gatewayTrustGRPCGetRevokedSerialsPath}
	return interceptor(ctx, request, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(gatewayTrustGRPCServer).GetRevokedSerials(ctx, req.(*structpb.Struct))
	})
}

func gatewayTrustGRPCRevalidateSessionsHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(gatewayTrustGRPCServer).RevalidateSessions(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: gatewayTrustGRPCRevalidateSessionsPath}
	return interceptor(ctx, request, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(gatewayTrustGRPCServer).RevalidateSessions(ctx, req.(*structpb.Struct))
	})
}

var gatewayTrustGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: gatewayTrustGRPCServiceName,
	HandlerType: (*gatewayTrustGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "GetCACertificate", Handler: gatewayTrustGRPCGetCACertificateHandler},
		{MethodName: "GetRevokedSerials", Handler: gatewayTrustGRPCGetRevokedSerialsHandler},
		{MethodName: "RevalidateSessions", Handler: gatewayTrustGRPCRevalidateSessionsHandler},
	},
	Metadata: "gateway_trust.proto",
}
