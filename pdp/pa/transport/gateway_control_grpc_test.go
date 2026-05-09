package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"strings"
	"testing"
	"time"

	"pdp/models"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
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
			Constraints:      []string{"managed_device", "healthy_posture"},
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
	registry := NewGatewayControlRegistry()
	err := registry.Heartbeat(context.Background(), "gw-missing")
	if err == nil || !strings.Contains(err.Error(), ErrGatewayControlNotConnected.Error()) {
		t.Fatalf("Heartbeat() error = %v, want not connected", err)
	}
}

type testGatewayControlStream struct {
	grpc.ServerStream
	ctx  context.Context
	recv chan *structpb.Struct
	sent chan *structpb.Struct
}

func newTestGatewayControlStream(ctx context.Context) *testGatewayControlStream {
	return &testGatewayControlStream{
		ctx:  ctx,
		recv: make(chan *structpb.Struct, 16),
		sent: make(chan *structpb.Struct, 16),
	}
}

func (stream *testGatewayControlStream) Context() context.Context {
	return stream.ctx
}

func (stream *testGatewayControlStream) RecvMsg(message interface{}) error {
	select {
	case <-stream.ctx.Done():
		return stream.ctx.Err()
	case value, ok := <-stream.recv:
		if !ok {
			return io.EOF
		}
		structMessage, ok := message.(*structpb.Struct)
		if !ok {
			return io.ErrUnexpectedEOF
		}
		proto.Reset(structMessage)
		proto.Merge(structMessage, value)
		return nil
	}
}

func (stream *testGatewayControlStream) SendMsg(message interface{}) error {
	value, ok := message.(*structpb.Struct)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	select {
	case <-stream.ctx.Done():
		return stream.ctx.Err()
	case stream.sent <- value:
		return nil
	}
}

func (stream *testGatewayControlStream) queueRecv(value *structpb.Struct) {
	stream.recv <- value
}

func (stream *testGatewayControlStream) nextSent(t *testing.T) *structpb.Struct {
	t.Helper()
	select {
	case value := <-stream.sent:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for gateway control command")
	}
	return nil
}

func newGatewayControlTestServer(t *testing.T, gatewayID, fqdn string) (*Server, *x509.Certificate) {
	t.Helper()
	server, dataStore := newDeviceAPITestServer(t)
	certPEM, cert := newDeviceAPICertificate(t, fqdn, time.Now().Add(time.Hour))
	server.gatewayControl = NewGatewayControlRegistry()
	dataStore.SaveGateway(&models.Gateway{
		ID:              gatewayID,
		Name:            "Test Gateway",
		FQDN:            fqdn,
		Status:          "enrolled",
		CertPEM:         string(certPEM),
		CertFingerprint: clientCertificateFingerprint(cert),
		CreatedAt:       time.Now().Add(-time.Hour),
		UpdatedAt:       time.Now().Add(-time.Hour),
	})
	return server, cert
}

func gatewayControlPeerContext(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})
}

func waitGatewayControlConnected(t *testing.T, server *Server, gatewayID string) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatalf("gateway %s did not connect", gatewayID)
		case <-ticker.C:
			for _, connectedID := range server.gatewayControl.ConnectedGatewayIDs() {
				if connectedID == gatewayID {
					return
				}
			}
		}
	}
}

func gatewayControlAckFor(t *testing.T, command *structpb.Struct, statusValue, code, message string) *structpb.Struct {
	t.Helper()
	fields := map[string]interface{}{
		"type":       gatewayControlMessageAck,
		"gateway_id": "gw-1",
		"command_id": structFieldString(command, "command_id"),
		"status":     statusValue,
		"message":    message,
	}
	if code != "" {
		fields["code"] = code
	}
	return mustGatewayControlStruct(t, fields)
}

func mustGatewayControlStruct(t *testing.T, fields map[string]interface{}) *structpb.Struct {
	t.Helper()
	value, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("NewStruct() error = %v", err)
	}
	return value
}
