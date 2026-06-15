package transport

import (
	"context"
	"errors"
	"net"
	"strings"

	"pdp/models"
	pagateway "pdp/pa/gateway"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	gatewayEnrollmentGRPCServiceName      = "gateway.GatewayEnrollmentService"
	gatewayEnrollmentGRPCEnrollPath       = "/gateway.GatewayEnrollmentService/Enroll"
	gatewayEnrollmentGRPCRenewCertPath    = "/gateway.GatewayEnrollmentService/RenewCertificate"
	gatewayEnrollmentResponseStatusEnroll = "enrolled"
	gatewayEnrollmentResponseStatusRenew  = "renewed"
)

type gatewayEnrollmentGRPCServer interface {
	Enroll(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RenewCertificate(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

type gatewayEnrollmentGRPCService struct {
	server *Server
}

func (service *gatewayEnrollmentGRPCService) Enroll(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Gateways == nil {
		return nil, status.Error(codes.Internal, "gateway enrollment service is not initialized")
	}
	if ip := grpcPeerIP(ctx); ip != "" && !service.server.checkEnrollRateLimit(ip) {
		return nil, status.Error(codes.ResourceExhausted, "too many enrollment attempts")
	}
	req := gatewayEnrollRequestFromStruct(request)
	result, err := service.server.pa.Gateways.EnrollGateway(req)
	if err != nil {
		return nil, gatewayEnrollmentGRPCError(err)
	}
	caPEM, err := service.server.getCAPEM()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "CA certificate is not available")
	}
	payload := map[string]interface{}{
		"status":          gatewayEnrollmentResponseStatusEnroll,
		"gateway_id":      result.Gateway.ID,
		"organization_id": result.Gateway.OrganizationID,
		"cert_pem":        string(result.CertPEM),
		"ca_pem":          string(caPEM),
		"message":         "Gateway enrolled successfully. Certificate valid for 7 days.",
	}
	return structpb.NewStruct(payload)
}

func (service *gatewayEnrollmentGRPCService) RenewCertificate(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Gateways == nil {
		return nil, status.Error(codes.Internal, "gateway enrollment service is not initialized")
	}
	peerCert, ok := clientCertificateFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client certificate required for gateway renewal")
	}
	gateway, statusCode, errorMessage := service.server.authenticateGatewayCertificate(peerCert)
	if statusCode != 0 {
		return nil, status.Error(grpcCodeForHTTPStatus(statusCode), errorMessage)
	}
	csrPEM := strings.TrimSpace(structFieldString(request, "csr_pem"))
	result, err := service.server.pa.Gateways.RenewGatewayCertificate(gateway, csrPEM)
	if err != nil {
		return nil, gatewayEnrollmentGRPCError(err)
	}
	caPEM, err := service.server.getCAPEM()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "CA certificate is not available")
	}
	payload := map[string]interface{}{
		"status":          gatewayEnrollmentResponseStatusRenew,
		"gateway_id":      result.Gateway.ID,
		"organization_id": result.Gateway.OrganizationID,
		"cert_pem":        string(result.CertPEM),
		"ca_pem":          string(caPEM),
		"message":         "Certificate renewed (7-day validity)",
	}
	return structpb.NewStruct(payload)
}

func gatewayEnrollRequestFromStruct(value *structpb.Struct) models.GatewayEnrollRequest {
	if value == nil {
		return models.GatewayEnrollRequest{}
	}
	return models.GatewayEnrollRequest{
		Token:  strings.TrimSpace(structFieldString(value, "token")),
		CSRPEM: strings.TrimSpace(structFieldString(value, "csr_pem")),
	}
}

func gatewayEnrollmentGRPCError(err error) error {
	switch {
	case errors.Is(err, pagateway.ErrInvalidEnrollmentToken):
		return status.Error(codes.Unauthenticated, "invalid enrollment token")
	case errors.Is(err, pagateway.ErrEnrollmentTokenExpired):
		return status.Error(codes.DeadlineExceeded, "enrollment token has expired")
	case errors.Is(err, pagateway.ErrGatewayAlreadyEnrolled):
		return status.Error(codes.AlreadyExists, "gateway is already enrolled")
	case errors.Is(err, pagateway.ErrInvalidRequest), errors.Is(err, pagateway.ErrInvalidCSR):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, pagateway.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, pagateway.ErrGatewaySigning):
		return status.Error(codes.Internal, "failed to sign gateway certificate")
	default:
		return status.Error(codes.Internal, "failed to process gateway enrollment")
	}
}

func grpcPeerIP(ctx context.Context) string {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo == nil || peerInfo.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(peerInfo.Addr.String())
	if err == nil {
		return host
	}
	return strings.TrimSpace(peerInfo.Addr.String())
}

func gatewayEnrollmentGRPCEnrollHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(gatewayEnrollmentGRPCServer).Enroll(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: gatewayEnrollmentGRPCEnrollPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(gatewayEnrollmentGRPCServer).Enroll(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

func gatewayEnrollmentGRPCRenewHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(gatewayEnrollmentGRPCServer).RenewCertificate(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: gatewayEnrollmentGRPCRenewCertPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(gatewayEnrollmentGRPCServer).RenewCertificate(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var gatewayEnrollmentGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: gatewayEnrollmentGRPCServiceName,
	HandlerType: (*gatewayEnrollmentGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Enroll", Handler: gatewayEnrollmentGRPCEnrollHandler},
		{MethodName: "RenewCertificate", Handler: gatewayEnrollmentGRPCRenewHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "gateway_enrollment.proto",
}
