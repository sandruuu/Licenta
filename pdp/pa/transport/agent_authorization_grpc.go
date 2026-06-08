package transport

import (
	"context"
	"strings"

	"pdp/models"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	agentAuthorizationGRPCServiceName   = "trustcloud.agent.AgentAuthorizationService"
	agentAuthorizationGRPCAuthorizePath = "/" + agentAuthorizationGRPCServiceName + "/AuthorizeResource"
)

type agentAuthorizationGRPCServer interface {
	AuthorizeResource(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

type agentAuthorizationGRPCService struct {
	server *Server
}

func (service *agentAuthorizationGRPCService) AuthorizeResource(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil {
		return nil, status.Error(codes.Internal, "agent authorization service is not initialized")
	}
	enrollment, ok := deviceEnrollmentFromContextValue(ctx)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		return nil, status.Error(codes.PermissionDenied, "missing client certificate identity")
	}
	peerCert, ok := clientCertificateFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	token, err := catalogBearerTokenFromGRPC(ctx, request)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	authorizeRequest, err := agentAuthorizeRequestFromStruct(request)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	response, statusCode, err := service.server.authorizeAgentResource(ctx, enrollment, clientCertificateFingerprint(peerCert), token, authorizeRequest, grpcPeerIP(ctx))
	if err != nil {
		return nil, status.Error(grpcCodeForHTTPStatus(statusCode), err.Error())
	}
	return agentAuthorizeResponseToStruct(response)
}

func agentAuthorizeRequestFromStruct(value *structpb.Struct) (agentAuthorizeRequest, error) {
	if value == nil {
		return agentAuthorizeRequest{}, nil
	}
	request := agentAuthorizeRequest{
		ResourceID: strings.TrimSpace(structFieldString(value, "resource_id")),
		Protocol:   strings.TrimSpace(structFieldString(value, "protocol")),
	}
	if portValue := value.GetFields()["port"]; portValue != nil {
		request.Port = int(portValue.GetNumberValue())
	}
	if processValue := value.GetFields()["process"]; processValue != nil && processValue.GetStructValue() != nil {
		request.Process = processIdentityFromStruct(processValue.GetStructValue())
	}
	return request, nil
}

func processIdentityFromStruct(value *structpb.Struct) *models.ProcessIdentity {
	if value == nil {
		return nil
	}
	process := &models.ProcessIdentity{
		Name:   strings.TrimSpace(structFieldString(value, "name")),
		Path:   strings.TrimSpace(structFieldString(value, "path")),
		SHA256: strings.TrimSpace(structFieldString(value, "sha256")),
		Signer: strings.TrimSpace(structFieldString(value, "signer")),
	}
	if pidValue := value.GetFields()["pid"]; pidValue != nil {
		process.PID = int(pidValue.GetNumberValue())
	}
	if process.PID == 0 && process.Name == "" && process.Path == "" && process.SHA256 == "" && process.Signer == "" {
		return nil
	}
	return process
}

func agentAuthorizeResponseToStruct(response agentAuthorizeResponse) (*structpb.Struct, error) {
	policies := make([]interface{}, 0, len(response.Policies))
	for _, policy := range response.Policies {
		policies = append(policies, policy)
	}
	payload := map[string]interface{}{
		"decision":     response.Decision,
		"reason":       response.Reason,
		"risk_score":   float64(response.RiskScore),
		"matched_rule": response.MatchedRule,
		"policies":     policies,
	}
	if response.SessionID != "" {
		payload["session_id"] = response.SessionID
	}
	if response.SessionToken != "" {
		payload["session_token"] = response.SessionToken
	}
	if response.GatewayID != "" {
		payload["gateway_id"] = response.GatewayID
	}
	if response.GatewayEndpoint != "" {
		payload["gateway_endpoint"] = response.GatewayEndpoint
	}
	if response.GatewayServerName != "" {
		payload["gateway_server_name"] = response.GatewayServerName
	}
	if response.ResourceID != "" {
		payload["resource_id"] = response.ResourceID
	}
	if response.Protocol != "" {
		payload["protocol"] = response.Protocol
	}
	if response.Port != 0 {
		payload["port"] = float64(response.Port)
	}
	if response.ExpiresAt != "" {
		payload["expires_at"] = response.ExpiresAt
	}
	if response.StepUpChallengeID != "" {
		payload["step_up_challenge_id"] = response.StepUpChallengeID
	}
	if response.StepUpURL != "" {
		payload["step_up_url"] = response.StepUpURL
	}
	if len(response.StepUpMethods) > 0 {
		methods := make([]interface{}, 0, len(response.StepUpMethods))
		for _, method := range response.StepUpMethods {
			methods = append(methods, method)
		}
		payload["step_up_methods"] = methods
	}
	if response.StepUpRequiredACR != "" {
		payload["step_up_required_acr"] = response.StepUpRequiredACR
	}
	if response.StepUpExpiresAt != "" {
		payload["step_up_expires_at"] = response.StepUpExpiresAt
	}
	return structpb.NewStruct(payload)
}

func agentAuthorizationGRPCAuthorizeHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentAuthorizationGRPCServer).AuthorizeResource(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentAuthorizationGRPCAuthorizePath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentAuthorizationGRPCServer).AuthorizeResource(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var agentAuthorizationGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: agentAuthorizationGRPCServiceName,
	HandlerType: (*agentAuthorizationGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "AuthorizeResource", Handler: agentAuthorizationGRPCAuthorizeHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "agent_authorization.proto",
}
