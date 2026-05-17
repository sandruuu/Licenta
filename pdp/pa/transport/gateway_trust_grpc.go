package transport

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	gatewayTrustGRPCServiceName           = "gateway.GatewayTrustService"
	gatewayTrustGRPCGetCACertificatePath  = "/gateway.GatewayTrustService/GetCACertificate"
	gatewayTrustGRPCGetRevokedSerialsPath = "/gateway.GatewayTrustService/GetRevokedSerials"
)

type gatewayTrustGRPCServer interface {
	GetCACertificate(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetRevokedSerials(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

type gatewayTrustGRPCService struct {
	server *Server
}

func (service *gatewayTrustGRPCService) GetCACertificate(ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil {
		return nil, status.Error(codes.Internal, "gateway trust service is not initialized")
	}
	if err := service.authenticateGateway(ctx); err != nil {
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
	if err := service.authenticateGateway(ctx); err != nil {
		return nil, err
	}
	serials := service.server.pa.Store.GetRevokedSerials()
	values := make([]interface{}, 0, len(serials))
	for _, serial := range serials {
		values = append(values, serial)
	}
	return structpb.NewStruct(map[string]interface{}{"revoked_serials": values})
}

func (service *gatewayTrustGRPCService) authenticateGateway(ctx context.Context) error {
	peerCert, ok := clientCertificateFromGRPCContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "client certificate required for gateway trust service")
	}
	_, statusCode, errorMessage := service.server.authenticateGatewayCertificate(peerCert)
	if statusCode != 0 {
		return status.Error(grpcCodeForHTTPStatus(statusCode), errorMessage)
	}
	return nil
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

var gatewayTrustGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: gatewayTrustGRPCServiceName,
	HandlerType: (*gatewayTrustGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "GetCACertificate", Handler: gatewayTrustGRPCGetCACertificateHandler},
		{MethodName: "GetRevokedSerials", Handler: gatewayTrustGRPCGetRevokedSerialsHandler},
	},
	Metadata: "gateway_trust.proto",
}
