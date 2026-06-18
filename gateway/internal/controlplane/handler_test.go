package controlplane

import (
	"testing"
	"time"

	"gateway/internal/provisioning"

	"google.golang.org/protobuf/types/known/structpb"
)

type recordingHandler struct {
	provisioned []provisioning.Session
	tokens      []string
	revoked     []string
	reasons     []string
	revokeOK    bool
}

func (handler *recordingHandler) ProvisionSession(session provisioning.Session, sessionToken string) error {
	handler.provisioned = append(handler.provisioned, session)
	handler.tokens = append(handler.tokens, sessionToken)
	return nil
}

func (handler *recordingHandler) RevokeProvisionedSession(sessionID, reason string) bool {
	handler.revoked = append(handler.revoked, sessionID)
	handler.reasons = append(handler.reasons, reason)
	return handler.revokeOK
}

func TestHandleProvisionSessionCommand(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	sessionHandler := &recordingHandler{revokeOK: true}
	handler, err := NewHandler("gw-1", sessionHandler, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	command := mustStruct(t, map[string]interface{}{
		"type":       CommandProvisionSession,
		"command_id": "cmd-1",
		"session": map[string]interface{}{
			"session_id":         "sess-1",
			"session_token":      "session-secret",
			"device_id":          "device-1",
			"user_id":            "user-1",
			"username":           "alice",
			"resource_id":        "res-ssh",
			"resource_name":      "SSH Server",
			"internal_host":      "10.10.0.10",
			"external_port":      float64(2222),
			"internal_port":      float64(22),
			"protocol":           "ssh",
			"expires_at":         now.Add(time.Hour).Format(time.RFC3339Nano),
			"constraints":        []interface{}{"managed_device", "healthy_device_data"},
			"policy_version":     "policy-7",
			"max_bandwidth_mbps": float64(25),
		},
	})

	ack := handler.HandleCommand(command)
	if got := structFieldString(ack, "status"); got != ackStatusOK {
		t.Fatalf("ack status = %q, want %q", got, ackStatusOK)
	}
	if len(sessionHandler.provisioned) != 1 {
		t.Fatalf("provisioned sessions = %d, want 1", len(sessionHandler.provisioned))
	}
	session := sessionHandler.provisioned[0]
	if session.ID != "sess-1" || session.DeviceID != "device-1" || session.ResourceID != "res-ssh" || session.InternalHost != "10.10.0.10" || session.ExternalPort != 2222 || session.InternalPort != 22 {
		t.Fatalf("provisioned session = %+v", session)
	}
	if session.ExpiresAt.IsZero() || session.MaxBandwidthMbps != 25 || len(session.Constraints) != 2 {
		t.Fatalf("provisioned session details = %+v", session)
	}
	if len(sessionHandler.tokens) != 1 || sessionHandler.tokens[0] != "session-secret" {
		t.Fatalf("token = %v", sessionHandler.tokens)
	}
}

func TestHelloMessageIncludesPublicEndpoint(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	handler, err := NewHandlerWithOptions("gw-1", &recordingHandler{}, HandlerOptions{
		PublicEndpoint: "localhost:9443",
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewHandlerWithOptions() error = %v", err)
	}

	hello := handler.helloMessage()
	if got := structFieldString(hello, "type"); got != MessageGatewayHello {
		t.Fatalf("hello type = %q, want %q", got, MessageGatewayHello)
	}
	if got := structFieldString(hello, "gateway_endpoint"); got != "localhost:9443" {
		t.Fatalf("gateway_endpoint = %q, want localhost:9443", got)
	}
}

func TestHandleRevokeSessionCommand(t *testing.T) {
	sessionHandler := &recordingHandler{revokeOK: true}
	handler, err := NewHandler("gw-1", sessionHandler, nil)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	ack := handler.HandleCommand(mustStruct(t, map[string]interface{}{
		"type":       CommandRevokeSession,
		"command_id": "cmd-2",
		"session_id": "sess-1",
		"reason":     "policy.updated",
	}))
	if got := structFieldString(ack, "status"); got != ackStatusOK {
		t.Fatalf("ack status = %q, want %q", got, ackStatusOK)
	}
	if len(sessionHandler.revoked) != 1 || sessionHandler.revoked[0] != "sess-1" || sessionHandler.reasons[0] != "policy.updated" {
		t.Fatalf("revocations = %v reasons = %v", sessionHandler.revoked, sessionHandler.reasons)
	}
}

func TestHandleProvisionSessionRejectsMalformedCommand(t *testing.T) {
	handler, err := NewHandler("gw-1", &recordingHandler{}, nil)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	ack := handler.HandleCommand(mustStruct(t, map[string]interface{}{
		"type":       CommandProvisionSession,
		"command_id": "cmd-3",
		"session": map[string]interface{}{
			"session_id": "sess-1",
			"expires_at": "not-a-time",
		},
	}))
	if got := structFieldString(ack, "status"); got != ackStatusError {
		t.Fatalf("ack status = %q, want %q", got, ackStatusError)
	}
	if got := structFieldString(ack, "code"); got != "invalid_argument" {
		t.Fatalf("ack code = %q, want invalid_argument", got)
	}
}

func mustStruct(t *testing.T, fields map[string]interface{}) *structpb.Struct {
	t.Helper()
	value, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("NewStruct() error = %v", err)
	}
	return value
}
