package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"pdp/models"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAgentAuthorizationGRPCProvisionsConnectedGateway(t *testing.T) {
	server, gatewayCert := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	store := server.pa.Store
	store.SaveResource(&models.Resource{
		ID:           "res-ssh",
		TenantID:     transportTestTenantID,
		GatewayID:    "gw-1",
		Name:         "SSH Server",
		Type:         "ssh",
		Host:         "10.10.0.10",
		Port:         22,
		Enabled:      true,
		AllowedRoles: []string{"admin"},
		CreatedAt:    time.Now().Add(-time.Hour),
		UpdatedAt:    time.Now().Add(-time.Hour),
	})
	deviceCertPEM, deviceCert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	enrollment := &models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		Component:       "endpoint",
		Status:          "approved",
		CertPEM:         string(deviceCertPEM),
		CertFingerprint: clientCertificateFingerprint(deviceCert),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	store.SaveDeviceEnrollment(enrollment)
	accessToken := newDeviceCatalogAccessToken(t, server, store, "device-1", "admin", clientCertificateFingerprint(deviceCert))

	gatewayCtx, cancelGateway := context.WithCancel(gatewayControlPeerContext(gatewayCert))
	defer cancelGateway()
	stream := newTestGatewayControlStream(gatewayCtx)
	stream.queueRecv(mustGatewayControlStruct(t, map[string]interface{}{
		"type":             gatewayControlMessageHello,
		"gateway_id":       "gw-1",
		"gateway_endpoint": "gateway.example.test:9443",
	}))
	streamDone := make(chan error, 1)
	go func() {
		streamDone <- (&gatewayControlGRPCService{server: server}).ControlStream(stream)
	}()
	waitGatewayControlConnected(t, server, "gw-1")

	request, err := structpb.NewStruct(map[string]interface{}{
		"access_token": accessToken,
		"resource_id":  "res-ssh",
		"protocol":     "ssh",
		"port":         float64(22),
		"process": map[string]interface{}{
			"pid":    float64(4242),
			"name":   "ssh.exe",
			"path":   `C:\\Windows\\System32\\OpenSSH\\ssh.exe`,
			"sha256": "abc123",
		},
	})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	serviceCtx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: *deviceTLSState(deviceCert)}})
	serviceCtx = context.WithValue(serviceCtx, deviceEnrollmentContextKey, enrollment)
	responseCh := make(chan *structpb.Struct, 1)
	errorCh := make(chan error, 1)
	go func() {
		response, err := (&agentAuthorizationGRPCService{server: server}).AuthorizeResource(serviceCtx, request)
		if err != nil {
			errorCh <- err
			return
		}
		responseCh <- response
	}()

	command := stream.nextSent(t)
	if got := structFieldString(command, "type"); got != gatewayControlCommandProvisionSession {
		t.Fatalf("command type = %q", got)
	}
	sessionPayload := command.GetFields()["session"].GetStructValue()
	if sessionPayload == nil || structFieldString(sessionPayload, "device_id") != "device-1" || structFieldString(sessionPayload, "resource_id") != "res-ssh" {
		t.Fatalf("session payload = %+v", command.AsMap())
	}
	stream.queueRecv(gatewayControlAckFor(t, command, gatewayControlAckStatusOK, "", "provisioned"))

	select {
	case err := <-errorCh:
		t.Fatalf("AuthorizeResource returned error: %v", err)
	case response := <-responseCh:
		if structFieldString(response, "decision") != "allow" || structFieldString(response, "session_token") == "" || structFieldString(response, "gateway_endpoint") != "gateway.example.test:9443" {
			t.Fatalf("authorization response = %+v", response.AsMap())
		}
	case <-time.After(time.Second):
		t.Fatal("AuthorizeResource did not finish")
	}

	cancelGateway()
	select {
	case <-streamDone:
	case <-time.After(time.Second):
		t.Fatal("gateway stream did not stop")
	}
}

func deviceTLSState(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}
