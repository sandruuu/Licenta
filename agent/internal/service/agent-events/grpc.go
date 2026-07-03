package agentevents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	grpcServiceName = "trustagent.events.AgentEventsService"
	grpcWatchPath   = "/" + grpcServiceName + "/Watch"
)

type GRPCClient struct {
	connection *grpc.ClientConn
}

func NewGRPCClientFromConnection(connection *grpc.ClientConn) (Client, error) {
	if connection == nil {
		return nil, fmt.Errorf("PDP gRPC connection is required for agent events")
	}
	return &GRPCClient{connection: connection}, nil
}

func (client *GRPCClient) Watch(ctx context.Context, request WatchRequest, handler Handler) error {
	if handler == nil {
		return fmt.Errorf("event handler is required")
	}
	payload, err := structpb.NewStruct(map[string]any{
		"access_token": strings.TrimSpace(request.AgentSessionToken),
		"session_id":   strings.TrimSpace(request.SessionID),
	})
	if err != nil {
		return err
	}
	stream, err := client.connection.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, grpcWatchPath)
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
			return err
		}
		if !handler(ctx, eventFromStruct(message)) {
			return nil
		}
	}
}

func (client *GRPCClient) Close() error {
	return nil
}

func eventFromStruct(value *structpb.Struct) Event {
	fields := map[string]any{}
	if value != nil {
		fields = value.AsMap()
	}
	return Event{
		Type:           stringField(fields, "type", "event_type"),
		Time:           timeField(fields, "time", "event_time"),
		Message:        stringField(fields, "message"),
		Reason:         stringField(fields, "reason"),
		SessionID:      stringField(fields, "session_id"),
		DeviceID:       stringField(fields, "device_id"),
		UserID:         stringField(fields, "user_id"),
		OrganizationID: stringField(fields, "organization_id"),
		ResourceID:     stringField(fields, "resource_id"),
		GatewayID:      stringField(fields, "gateway_id"),
		PolicyID:       stringField(fields, "policy_id"),
		Action:         stringField(fields, "action"),
	}
}

func timeField(fields map[string]any, names ...string) time.Time {
	for _, name := range names {
		value, ok := fields[name]
		if !ok {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(fmt.Sprint(value)))
		if err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func stringField(fields map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := fields[name]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}
