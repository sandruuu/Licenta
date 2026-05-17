package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gateway/internal/provisioning"

	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ServiceName       = "gateway.GatewayControlService"
	ControlStreamPath = "/gateway.GatewayControlService/ControlStream"

	CommandProvisionSession = "provision_session"
	CommandRevokeSession    = "revoke_session"
	CommandHeartbeat        = "heartbeat"

	MessageGatewayHello = "gateway_hello"
	MessageAck          = "ack"

	ackStatusOK    = "ok"
	ackStatusError = "error"
)

type SessionHandler interface {
	ProvisionSession(session provisioning.Session, sessionToken string) error
	RevokeProvisionedSession(sessionID, reason string) bool
}

type Stream interface {
	SendMsg(message interface{}) error
	RecvMsg(message interface{}) error
}

type Handler struct {
	gatewayID string
	handler   SessionHandler
	now       func() time.Time
}

func NewHandler(gatewayID string, handler SessionHandler, now func() time.Time) (*Handler, error) {
	gatewayID = strings.TrimSpace(gatewayID)
	if gatewayID == "" {
		return nil, errors.New("gateway_id is required")
	}
	if handler == nil {
		return nil, errors.New("session handler is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Handler{gatewayID: gatewayID, handler: handler, now: now}, nil
}

func (handler *Handler) Run(ctx context.Context, stream Stream) error {
	if handler == nil {
		return errors.New("gateway control handler is nil")
	}
	if stream == nil {
		return errors.New("gateway control stream is nil")
	}
	if err := stream.SendMsg(handler.helloMessage()); err != nil {
		return fmt.Errorf("send gateway control hello: %w", err)
	}
	for {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		command := &structpb.Struct{}
		err := stream.RecvMsg(command)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("receive gateway control command: %w", err)
		}
		ack := handler.HandleCommand(command)
		if err := stream.SendMsg(ack); err != nil {
			return fmt.Errorf("send gateway control ack: %w", err)
		}
	}
}

func (handler *Handler) helloMessage() *structpb.Struct {
	message, _ := structpb.NewStruct(map[string]interface{}{
		"type":       MessageGatewayHello,
		"gateway_id": handler.gatewayID,
		"sent_at":    handler.now().UTC().Format(time.RFC3339Nano),
	})
	return message
}

func (handler *Handler) HandleCommand(command *structpb.Struct) *structpb.Struct {
	commandID := structFieldString(command, "command_id")
	commandType := strings.ToLower(strings.TrimSpace(structFieldString(command, "type")))
	switch commandType {
	case CommandProvisionSession:
		session, token, err := sessionFromCommand(command)
		if err != nil {
			return handler.ack(commandID, ackStatusError, "invalid_argument", err.Error())
		}
		if err := handler.handler.ProvisionSession(session, token); err != nil {
			return handler.ack(commandID, ackStatusError, "provision_failed", err.Error())
		}
		return handler.ack(commandID, ackStatusOK, "", "session provisioned")
	case CommandRevokeSession:
		sessionID := firstNonEmpty(structFieldString(command, "session_id"), nestedString(command, "session", "session_id"), nestedString(command, "session", "id"))
		reason := firstNonEmpty(structFieldString(command, "reason"), nestedString(command, "session", "reason"))
		if strings.TrimSpace(sessionID) == "" {
			return handler.ack(commandID, ackStatusError, "invalid_argument", "session_id is required")
		}
		if !handler.handler.RevokeProvisionedSession(sessionID, reason) {
			return handler.ack(commandID, ackStatusError, provisioning.CodeSessionNotFound, "session was not provisioned")
		}
		return handler.ack(commandID, ackStatusOK, "", "session revoked")
	case CommandHeartbeat:
		return handler.ack(commandID, ackStatusOK, "", "heartbeat received")
	default:
		return handler.ack(commandID, ackStatusError, "unsupported_command", fmt.Sprintf("unsupported command type %q", commandType))
	}
}

func (handler *Handler) ack(commandID, statusValue, code, message string) *structpb.Struct {
	fields := map[string]interface{}{
		"type":       MessageAck,
		"gateway_id": handler.gatewayID,
		"command_id": strings.TrimSpace(commandID),
		"status":     statusValue,
		"message":    strings.TrimSpace(message),
		"sent_at":    handler.now().UTC().Format(time.RFC3339Nano),
	}
	if strings.TrimSpace(code) != "" {
		fields["code"] = strings.TrimSpace(code)
	}
	ack, _ := structpb.NewStruct(fields)
	return ack
}

func sessionFromCommand(command *structpb.Struct) (provisioning.Session, string, error) {
	sessionValue := command.GetFields()["session"]
	if sessionValue == nil || sessionValue.GetStructValue() == nil {
		return provisioning.Session{}, "", errors.New("session object is required")
	}
	sessionStruct := sessionValue.GetStructValue()
	expiresAt, err := timeField(sessionStruct, "expires_at")
	if err != nil {
		return provisioning.Session{}, "", err
	}
	internalPort, err := intField(sessionStruct, "internal_port")
	if err != nil {
		return provisioning.Session{}, "", err
	}
	maxBandwidth, err := optionalIntField(sessionStruct, "max_bandwidth_mbps")
	if err != nil {
		return provisioning.Session{}, "", err
	}
	constraints, err := stringListField(sessionStruct, "constraints", false)
	if err != nil {
		return provisioning.Session{}, "", err
	}
	session := provisioning.Session{
		ID:               firstNonEmpty(structFieldString(sessionStruct, "session_id"), structFieldString(sessionStruct, "id")),
		DeviceID:         structFieldString(sessionStruct, "device_id"),
		UserID:           structFieldString(sessionStruct, "user_id"),
		Username:         structFieldString(sessionStruct, "username"),
		ResourceID:       structFieldString(sessionStruct, "resource_id"),
		ResourceName:     structFieldString(sessionStruct, "resource_name"),
		InternalHost:     structFieldString(sessionStruct, "internal_host"),
		InternalPort:     internalPort,
		Protocol:         structFieldString(sessionStruct, "protocol"),
		ExpiresAt:        expiresAt,
		Constraints:      constraints,
		PolicyVersion:    structFieldString(sessionStruct, "policy_version"),
		MaxBandwidthMbps: maxBandwidth,
	}
	token := structFieldString(sessionStruct, "session_token")
	return session, token, nil
}
