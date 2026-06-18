package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	"pdp/internal/testredis"
)

func TestGatewayControlRegistryReturnsGatewayAckErrors(t *testing.T) {
	server, cert := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	ctx, cancel := context.WithCancel(gatewayControlPeerContext(cert))
	defer cancel()
	stream := newTestGatewayControlStream(ctx)
	stream.queueRecv(mustGatewayControlStruct(t, map[string]interface{}{
		"type":       gatewayControlMessageHello,
		"gateway_id": "gw-1",
	}))
	done := make(chan error, 1)
	go func() {
		done <- (&gatewayControlGRPCService{server: server}).ControlStream(stream)
	}()
	waitGatewayControlConnected(t, server, "gw-1")

	provisionDone := make(chan error, 1)
	go func() {
		provisionDone <- server.gatewayControl.ProvisionSession(context.Background(), "gw-1", GatewayControlSession{
			ID:           "sess-1",
			SessionToken: "session-secret",
			DeviceID:     "device-1",
			ResourceID:   "res-ssh",
			InternalHost: "10.10.0.10",
			ExternalPort: 2222,
			InternalPort: 22,
			Protocol:     "ssh",
			ExpiresAt:    time.Now().Add(time.Hour),
		})
	}()
	command := stream.nextSent(t)
	stream.queueRecv(gatewayControlAckFor(t, command, "error", "invalid_argument", "bad session"))
	err := <-provisionDone
	if err == nil || !strings.Contains(err.Error(), "invalid_argument") {
		t.Fatalf("ProvisionSession() error = %v, want gateway ack error", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ControlStream did not stop after context cancellation")
	}
}

func TestGatewayControlRegistryRequiresConnectedGateway(t *testing.T) {
	registry := NewGatewayControlRegistry(testredis.NewClient(t))
	err := registry.Heartbeat(context.Background(), "gw-missing")
	if err == nil || !strings.Contains(err.Error(), ErrGatewayControlNotConnected.Error()) {
		t.Fatalf("Heartbeat() error = %v, want not connected", err)
	}
}
