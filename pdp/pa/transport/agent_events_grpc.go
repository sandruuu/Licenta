package transport

import (
	"context"
	"fmt"
	"strings"
	"time"

	"pdp/pa/auth"
	"pdp/pa/events"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	agentEventsGRPCServiceName = "trustagent.events.AgentEventsService"
	agentEventsGRPCWatchPath   = "/" + agentEventsGRPCServiceName + "/Watch"

	agentEventAccessRevoked      = "access.revoked"
	agentEventCatalogInvalidated = "catalog.invalidated"
	agentEventStepUpCompleted    = "step_up.completed"
)

type agentEventsGRPCServer interface {
	Watch(*structpb.Struct, grpc.ServerStream) error
}

type agentEventsGRPCService struct {
	server *Server
}

func (service *agentEventsGRPCService) Watch(request *structpb.Struct, stream grpc.ServerStream) error {
	if service == nil || service.server == nil || service.server.events == nil {
		return status.Error(codes.Internal, "agent event service is not initialized")
	}
	claims, err := service.authenticate(stream.Context(), request)
	if err != nil {
		return err
	}
	sub := service.server.events.Subscribe(
		events.TopicSessionDeleted,
		events.TopicStepUpCompleted,
		events.TopicPolicyUpdated,
		events.TopicResourcesUpdated,
		events.TopicDeviceRevoked,
		events.TopicGatewayRevoked,
	)
	defer service.server.events.Unsubscribe(sub)

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case evt, ok := <-sub.C:
			if !ok {
				return nil
			}
			payload, ok := service.agentEventForClaims(evt, claims)
			if !ok {
				continue
			}
			message, err := structpb.NewStruct(payload)
			if err != nil {
				return status.Errorf(codes.Internal, "build event payload: %v", err)
			}
			if err := stream.SendMsg(message); err != nil {
				return err
			}
		}
	}
}

func (service *agentEventsGRPCService) authenticate(ctx context.Context, request *structpb.Struct) (*auth.CustomClaims, error) {
	peerCert, ok := clientCertificateFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client certificate required for agent events")
	}
	enrollment, statusCode, errorMessage := service.server.authenticateDeviceCertificate(peerCert)
	if statusCode != 0 {
		return nil, status.Error(grpcCodeForHTTPStatus(statusCode), errorMessage)
	}
	token, err := catalogBearerTokenFromGRPC(ctx, request)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	claims, err := service.server.pa.ValidateDeviceUserTokenBoundForScope(token, enrollment.DeviceID, clientCertificateFingerprint(peerCert), "events:read")
	if err != nil {
		return nil, status.Error(grpcCodeForHTTPStatus(httpStatusForAccessError(err)), err.Error())
	}
	if requestedSessionID := strings.TrimSpace(structFieldString(request, "session_id")); requestedSessionID != "" && requestedSessionID != strings.TrimSpace(claims.SessionID) {
		return nil, status.Error(codes.PermissionDenied, "session_id does not match agent session token")
	}
	return claims, nil
}

func (service *agentEventsGRPCService) agentEventForClaims(evt events.Event, claims *auth.CustomClaims) (map[string]interface{}, bool) {
	if claims == nil {
		return nil, false
	}
	fields := eventPayloadFields(evt)
	switch evt.Type {
	case events.TopicSessionDeleted:
		if !sameEventField(fields, "device_id", claims.DeviceID) || !sameEventField(fields, "user_id", claims.UserID) {
			return nil, false
		}
		if !organizationMatches(fields["organization_id"], claims.OrganizationID) {
			return nil, false
		}
		return agentEventPayload(agentEventAccessRevoked, claims, fields, evt.Time, "Access to protected resources was revoked."), true
	case events.TopicDeviceRevoked:
		if !sameEventField(fields, "device_id", claims.DeviceID) {
			return nil, false
		}
		if !organizationMatches(fields["organization_id"], claims.OrganizationID) {
			return nil, false
		}
		fields["session_id"] = claims.SessionID
		return agentEventPayload(agentEventAccessRevoked, claims, fields, evt.Time, "This device enrollment was revoked."), true
	case events.TopicStepUpCompleted:
		if !sameEventField(fields, "session_id", claims.SessionID) ||
			!sameEventField(fields, "device_id", claims.DeviceID) ||
			!sameEventField(fields, "user_id", claims.UserID) {
			return nil, false
		}
		if !organizationMatches(fields["organization_id"], claims.OrganizationID) {
			return nil, false
		}
		return agentEventPayload(agentEventStepUpCompleted, claims, fields, evt.Time, "Security verification completed."), true
	case events.TopicResourcesUpdated, events.TopicPolicyUpdated, events.TopicGatewayRevoked:
		if !organizationMatches(fields["organization_id"], claims.OrganizationID) {
			return nil, false
		}
		return agentEventPayload(agentEventCatalogInvalidated, claims, fields, evt.Time, "Protected resource access changed."), true
	default:
		return nil, false
	}
}

func agentEventPayload(eventType string, claims *auth.CustomClaims, fields map[string]string, eventTime time.Time, defaultMessage string) map[string]interface{} {
	reason := strings.TrimSpace(fields["reason"])
	message := agentEventMessage(eventType, reason, defaultMessage)
	payload := map[string]interface{}{
		"type":            eventType,
		"event_type":      eventType,
		"message":         message,
		"reason":          reason,
		"session_id":      firstNonEmptyAgentEvent(fields["session_id"], claims.SessionID),
		"device_id":       claims.DeviceID,
		"user_id":         claims.UserID,
		"organization_id": claims.OrganizationID,
	}
	if !eventTime.IsZero() {
		timestamp := eventTime.UTC().Format(time.RFC3339Nano)
		payload["time"] = timestamp
		payload["event_time"] = timestamp
	}
	for _, key := range []string{"resource_id", "gateway_id", "policy_id", "action"} {
		if value := strings.TrimSpace(fields[key]); value != "" {
			payload[key] = value
		}
	}
	return payload
}

func agentEventMessage(eventType, reason, defaultMessage string) string {
	switch strings.TrimSpace(reason) {
	case "agent_logout":
		return "You signed out. Protected resource access was removed."
	case "device_posture_changed":
		return "Protected resource access was revoked because device posture no longer satisfies policy."
	case "policy_updated":
		return "Protected resource access changed because policy was updated."
	case "resource_deleted":
		return "Protected resource access was revoked because the resource was deleted."
	case "resource_updated":
		return "Protected resource access changed because a resource was updated."
	case "resource_disabled":
		return "Protected resource access was revoked because the resource was disabled."
	case "device_revoked", "device_enrollment_revoked":
		return "Protected resource access was revoked because this device enrollment was revoked."
	case "gateway_revoked", "gateway_deleted":
		return "Protected resource access changed because the gateway was revoked."
	case "expired":
		return "Your protected resource session expired."
	}
	if strings.TrimSpace(defaultMessage) != "" {
		return defaultMessage
	}
	if eventType == agentEventCatalogInvalidated {
		return "Protected resource catalog changed."
	}
	return "Protected resource access was revoked."
}

func eventPayloadFields(evt events.Event) map[string]string {
	result := map[string]string{}
	switch payload := evt.Payload.(type) {
	case map[string]string:
		for key, value := range payload {
			result[key] = strings.TrimSpace(value)
		}
	case map[string]interface{}:
		for key, value := range payload {
			result[key] = strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return result
}

func sameEventField(fields map[string]string, key, expected string) bool {
	value := strings.TrimSpace(fields[key])
	return value != "" && strings.EqualFold(value, strings.TrimSpace(expected))
}

func organizationMatches(eventOrganizationID, claimsOrganizationID string) bool {
	eventOrganizationID = strings.TrimSpace(eventOrganizationID)
	if eventOrganizationID == "" {
		return true
	}
	return strings.EqualFold(eventOrganizationID, strings.TrimSpace(claimsOrganizationID))
}

func firstNonEmptyAgentEvent(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func agentEventsGRPCWatchHandler(server interface{}, stream grpc.ServerStream) error {
	request := &structpb.Struct{}
	if err := stream.RecvMsg(request); err != nil {
		return err
	}
	return server.(agentEventsGRPCServer).Watch(request, stream)
}

var agentEventsGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: agentEventsGRPCServiceName,
	HandlerType: (*agentEventsGRPCServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{StreamName: "Watch", Handler: agentEventsGRPCWatchHandler, ServerStreams: true},
	},
	Metadata: "agent_events.proto",
}
