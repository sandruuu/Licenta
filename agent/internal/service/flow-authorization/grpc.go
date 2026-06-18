package flowauthorization

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	authorizationGRPCServiceName   = "trustcloud.agent.AgentAuthorizationService"
	authorizationGRPCAuthorizePath = "/" + authorizationGRPCServiceName + "/AuthorizeResource"
)

type GRPCClient struct {
	connection *grpc.ClientConn
}

func NewGRPCClientFromConnection(connection *grpc.ClientConn) (*GRPCClient, error) {
	if connection == nil {
		return nil, fmt.Errorf("PDP gRPC connection is required for flow authorization")
	}
	return &GRPCClient{connection: connection}, nil
}

func (client *GRPCClient) AuthorizeResource(ctx context.Context, request AuthorizeRequest) (AuthorizeResponse, error) {
	payload, err := authorizePayload(request)
	if err != nil {
		return AuthorizeResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, authorizationGRPCAuthorizePath, payload, &response); err != nil {
		return AuthorizeResponse{}, err
	}
	return authorizeResponseFromStruct(&response), nil
}

func (client *GRPCClient) Close() error {
	return nil
}

func authorizePayload(request AuthorizeRequest) (*structpb.Struct, error) {
	fields := map[string]any{
		"access_token": request.AgentSessionToken,
		"resource_id":  request.ResourceID,
		"protocol":     request.Protocol,
		"port":         request.Port,
	}
	if request.Process != nil {
		process := map[string]any{
			"pid":    request.Process.PID,
			"name":   request.Process.Name,
			"path":   request.Process.Path,
			"sha256": request.Process.SHA256,
			"signer": request.Process.Signer,
		}
		fields["process"] = process
	}
	return structpb.NewStruct(fields)
}

func authorizeResponseFromStruct(value *structpb.Struct) AuthorizeResponse {
	if value == nil {
		return AuthorizeResponse{}
	}
	fields := value.AsMap()
	return AuthorizeResponse{
		Decision:          stringField(fields, "decision"),
		Reason:            stringField(fields, "reason"),
		RiskSignals:       stringListField(fields["risk_signals"]),
		MatchedRule:       stringField(fields, "matched_rule"),
		Policies:          stringListField(fields["policies"]),
		SessionID:         stringField(fields, "session_id"),
		SessionToken:      stringField(fields, "session_token"),
		GatewayID:         stringField(fields, "gateway_id"),
		GatewayEndpoint:   stringField(fields, "gateway_endpoint"),
		GatewayServerName: stringField(fields, "gateway_server_name"),
		ResourceID:        stringField(fields, "resource_id"),
		Protocol:          stringField(fields, "protocol"),
		Port:              int(numberField(fields, "port")),
		ExpiresAt:         timeField(fields, "expires_at"),
		StepUpChallengeID: stringField(fields, "step_up_challenge_id"),
		StepUpURL:         stringField(fields, "step_up_url"),
		StepUpMethods:     stringListField(fields["step_up_methods"]),
		StepUpRequiredACR: stringField(fields, "step_up_required_acr"),
		StepUpExpiresAt:   timeField(fields, "step_up_expires_at"),
	}
}

func stringField(fields map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := fields[name]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func numberField(fields map[string]any, name string) float64 {
	value, ok := fields[name]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed
	default:
		return 0
	}
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

func stringListField(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" {
			values = append(values, text)
		}
	}
	return values
}
