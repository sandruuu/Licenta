package transport

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGatewayControlStreamSendsCommandsAndValidatesAcks(t *testing.T) {
	server, cert := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	ctx, cancel := context.WithCancel(gatewayControlPeerContext(cert))
	defer cancel()
	stream := newTestGatewayControlStream(ctx)
	stream.queueRecv(mustGatewayControlStruct(t, map[string]interface{}{
		"type":             gatewayControlMessageHello,
		"gateway_id":       "gw-1",
		"gateway_endpoint": "gateway.example.test:9443",
	}))

	done := make(chan error, 1)
	go func() {
		done <- (&gatewayControlGRPCService{server: server}).ControlStream(stream)
	}()
	waitGatewayControlConnected(t, server, "gw-1")

	provisionDone := make(chan error, 1)
	go func() {
		provisionDone <- server.gatewayControl.ProvisionSession(context.Background(), "gw-1", GatewayControlSession{
			ID:               "sess-1",
			SessionToken:     "session-secret",
			DeviceID:         "device-1",
			UserID:           "user-1",
			Username:         "alice",
			ResourceID:       "res-ssh",
			ResourceName:     "SSH Server",
			InternalHost:     "10.10.0.10",
			InternalPort:     22,
			Protocol:         "ssh",
			ExpiresAt:        time.Now().Add(time.Hour),
			Constraints:      []string{"managed_device", "healthy_device_data"},
			PolicyVersion:    "policy-7",
			MaxBandwidthMbps: 25,
		})
	}()
	provisionCommand := stream.nextSent(t)
	if got := structFieldString(provisionCommand, "type"); got != gatewayControlCommandProvisionSession {
		t.Fatalf("provision command type = %q", got)
	}
	sessionValue := provisionCommand.GetFields()["session"].GetStructValue()
	if sessionValue == nil || structFieldString(sessionValue, "session_id") != "sess-1" || structFieldString(sessionValue, "session_token") != "session-secret" {
		t.Fatalf("provision session payload = %+v", provisionCommand.AsMap())
	}
	stream.queueRecv(gatewayControlAckFor(t, provisionCommand, gatewayControlAckStatusOK, "", "provisioned"))
	if err := <-provisionDone; err != nil {
		t.Fatalf("ProvisionSession() error = %v", err)
	}

	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- server.gatewayControl.RevokeSession(context.Background(), "gw-1", "sess-1", "admin_revoked")
	}()
	revokeCommand := stream.nextSent(t)
	if got := structFieldString(revokeCommand, "type"); got != gatewayControlCommandRevokeSession {
		t.Fatalf("revoke command type = %q", got)
	}
	if got := structFieldString(revokeCommand, "session_id"); got != "sess-1" {
		t.Fatalf("revoke session_id = %q", got)
	}
	stream.queueRecv(gatewayControlAckFor(t, revokeCommand, gatewayControlAckStatusOK, "", "revoked"))
	if err := <-revokeDone; err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}

	heartbeatDone := make(chan error, 1)
	go func() {
		heartbeatDone <- server.gatewayControl.Heartbeat(context.Background(), "gw-1")
	}()
	heartbeatCommand := stream.nextSent(t)
	if got := structFieldString(heartbeatCommand, "type"); got != gatewayControlCommandHeartbeat {
		t.Fatalf("heartbeat command type = %q", got)
	}
	stream.queueRecv(gatewayControlAckFor(t, heartbeatCommand, gatewayControlAckStatusOK, "", "heartbeat"))
	if err := <-heartbeatDone; err != nil {
		t.Fatalf("Heartbeat() error = %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ControlStream did not stop after context cancellation")
	}
}

func TestGatewayControlStreamRejectsMismatchedHelloIdentity(t *testing.T) {
	server, cert := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	stream := newTestGatewayControlStream(gatewayControlPeerContext(cert))
	stream.queueRecv(mustGatewayControlStruct(t, map[string]interface{}{
		"type":       gatewayControlMessageHello,
		"gateway_id": "gw-other",
	}))

	err := (&gatewayControlGRPCService{server: server}).ControlStream(stream)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ControlStream() code = %v, err=%v", status.Code(err), err)
	}
	if connected := server.gatewayControl.ConnectedGatewayIDs(); len(connected) != 0 {
		t.Fatalf("connected gateways = %v", connected)
	}
}
