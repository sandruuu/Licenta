package transport

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	deviceCatalogGRPCServiceName    = "trustcloud.catalog.DeviceCatalogService"
	deviceCatalogGRPCGetCatalogPath = "/" + deviceCatalogGRPCServiceName + "/GetCatalog"
)

type deviceCatalogGRPCServer interface {
	GetCatalog(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

type deviceCatalogGRPCService struct {
	server *Server
}

func (service *deviceCatalogGRPCService) GetCatalog(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil {
		return nil, status.Error(codes.Internal, "catalog service is not initialized")
	}
	enrollment, ok := deviceEnrollmentFromContextValue(ctx)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		return nil, status.Error(codes.PermissionDenied, "missing client certificate identity")
	}
	peerCert, ok := clientCertificateFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client certificate required for catalog")
	}
	token, err := catalogBearerTokenFromGRPC(ctx, request)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	claims, statusCode, err := service.server.validateDeviceCatalogToken(token, enrollment.DeviceID, clientCertificateFingerprint(peerCert))
	if err != nil {
		return nil, status.Error(grpcCodeForHTTPStatus(statusCode), err.Error())
	}
	currentVersion := strings.TrimSpace(structFieldString(request, "current_version"))
	snapshot := service.server.deviceCatalogSnapshot(claims)
	if currentVersion != "" && currentVersion == snapshot.Version {
		response, err := structpb.NewStruct(map[string]interface{}{
			"version":      snapshot.Version,
			"not_modified": true,
			"policy_epoch": snapshot.PolicyEpoch,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "build catalog not-modified response: %v", err)
		}
		return response, nil
	}

	resourceValues := make([]interface{}, 0, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		resourceValues = append(resourceValues, map[string]interface{}{
			"fqdn":        resource.FQDN,
			"resource_id": resource.ResourceID,
			"protocol":    resource.Protocol,
			"port":        float64(resource.Port),
		})
	}
	deviceDataChecks := make([]interface{}, 0, len(snapshot.DeviceDataPolicy.RequiredChecks))
	for _, check := range snapshot.DeviceDataPolicy.RequiredChecks {
		deviceDataChecks = append(deviceDataChecks, check)
	}

	response, err := structpb.NewStruct(map[string]interface{}{
		"version":      snapshot.Version,
		"resources":    resourceValues,
		"ttl_seconds":  float64(snapshot.TTLSeconds),
		"not_modified": snapshot.NotModified,
		"policy_epoch": snapshot.PolicyEpoch,
		"device_data_policy": map[string]interface{}{
			"required_checks":       deviceDataChecks,
			"required_check_status": snapshot.DeviceDataPolicy.RequiredCheckStatus,
		},
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "build catalog response: %v", err)
	}
	return response, nil
}

func catalogBearerTokenFromGRPC(ctx context.Context, request *structpb.Struct) (string, error) {
	if token := strings.TrimSpace(structFieldString(request, "access_token")); token != "" {
		return token, nil
	}
	metadataValues, ok := metadata.FromIncomingContext(ctx)
	if ok {
		for _, value := range metadataValues.Get("authorization") {
			parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") && strings.TrimSpace(parts[1]) != "" {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "", fmt.Errorf("authorization bearer token required")
}

func (s *Server) initDeviceCatalogGRPC() {
	if s.gatewayControl == nil {
		s.gatewayControl = NewGatewayControlRegistry()
	}
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(s.deviceCatalogGRPCAuthInterceptor()))
	grpcServer.RegisterService(&agentEnrollmentGRPCServiceDesc, &agentEnrollmentGRPCService{server: s})
	grpcServer.RegisterService(&agentSessionGRPCServiceDesc, &agentSessionGRPCService{server: s})
	grpcServer.RegisterService(&deviceCatalogGRPCServiceDesc, &deviceCatalogGRPCService{server: s})
	grpcServer.RegisterService(&deviceDataGRPCServiceDesc, &deviceDataGRPCService{server: s})
	grpcServer.RegisterService(&agentAuthorizationGRPCServiceDesc, &agentAuthorizationGRPCService{server: s})
	grpcServer.RegisterService(&agentEventsGRPCServiceDesc, &agentEventsGRPCService{server: s})
	grpcServer.RegisterService(&gatewayEnrollmentGRPCServiceDesc, &gatewayEnrollmentGRPCService{server: s})
	grpcServer.RegisterService(&gatewayTrustGRPCServiceDesc, &gatewayTrustGRPCService{server: s})
	grpcServer.RegisterService(&gatewayControlGRPCServiceDesc, &gatewayControlGRPCService{server: s})
	s.grpcHandler = grpcServer
}

func (s *Server) deviceCatalogGRPCAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if info != nil && (isGatewayGRPCMethod(info.FullMethod) || isAgentEnrollmentGRPCMethod(info.FullMethod)) {
			return handler(ctx, req)
		}
		peerCert, ok := clientCertificateFromGRPCContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "client certificate required for device authentication")
		}
		enrollment, statusCode, errorMessage := s.authenticateDeviceCertificate(peerCert)
		if statusCode != 0 {
			return nil, status.Error(grpcCodeForHTTPStatus(statusCode), errorMessage)
		}
		ctx = context.WithValue(ctx, deviceEnrollmentContextKey, enrollment)
		return handler(ctx, req)
	}
}

func isGatewayGRPCMethod(fullMethod string) bool {
	fullMethod = strings.TrimSpace(fullMethod)
	return strings.HasPrefix(fullMethod, "/"+gatewayEnrollmentGRPCServiceName+"/") ||
		strings.HasPrefix(fullMethod, "/"+gatewayTrustGRPCServiceName+"/")
}

func isAgentEnrollmentGRPCMethod(fullMethod string) bool {
	return strings.HasPrefix(strings.TrimSpace(fullMethod), "/"+agentEnrollmentGRPCServiceName+"/")
}

func clientCertificateFromGRPCContext(ctx context.Context) (*x509.Certificate, bool) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo == nil || peerInfo.AuthInfo == nil {
		return nil, false
	}

	var state *tlsConnectionState
	switch info := peerInfo.AuthInfo.(type) {
	case credentials.TLSInfo:
		state = &tlsConnectionState{peer: info.State.PeerCertificates, verified: info.State.VerifiedChains}
	case *credentials.TLSInfo:
		if info != nil {
			state = &tlsConnectionState{peer: info.State.PeerCertificates, verified: info.State.VerifiedChains}
		}
	}
	if state == nil {
		return nil, false
	}
	if len(state.peer) > 0 && state.peer[0] != nil {
		return state.peer[0], true
	}
	if len(state.verified) > 0 && len(state.verified[0]) > 0 && state.verified[0][0] != nil {
		return state.verified[0][0], true
	}
	return nil, false
}

type tlsConnectionState struct {
	peer     []*x509.Certificate
	verified [][]*x509.Certificate
}

func grpcCodeForHTTPStatus(statusCode int) codes.Code {
	switch statusCode {
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusForbidden:
		return codes.PermissionDenied
	case http.StatusNotFound:
		return codes.NotFound
	case http.StatusBadRequest:
		return codes.InvalidArgument
	case http.StatusConflict, http.StatusPreconditionFailed, http.StatusPreconditionRequired:
		return codes.FailedPrecondition
	case http.StatusServiceUnavailable:
		return codes.Unavailable
	default:
		return codes.Internal
	}
}

func structFieldString(value *structpb.Struct, key string) string {
	if value == nil {
		return ""
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return ""
	}
	return field.GetStringValue()
}

func isGRPCRequest(request *http.Request) bool {
	if request == nil {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(request.Header.Get("Content-Type")))
	return request.ProtoMajor == 2 && strings.HasPrefix(contentType, "application/grpc")
}

func deviceCatalogGRPCGetCatalogHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(deviceCatalogGRPCServer).GetCatalog(ctx, request)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: deviceCatalogGRPCGetCatalogPath,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(deviceCatalogGRPCServer).GetCatalog(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var deviceCatalogGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: deviceCatalogGRPCServiceName,
	HandlerType: (*deviceCatalogGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCatalog",
			Handler:    deviceCatalogGRPCGetCatalogHandler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "device_catalog.proto",
}
