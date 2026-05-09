package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pdp/models"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestAgentAuthorizeProvisionsConnectedGateway(t *testing.T) {
	server, gatewayCert := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	store := server.pa.Store
	store.SaveResource(&models.Resource{
		ID:           "res-ssh",
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
	store.SaveDeviceEnrollment(&models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		Component:       "endpoint",
		Status:          "approved",
		CertPEM:         string(deviceCertPEM),
		CertFingerprint: clientCertificateFingerprint(deviceCert),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	})
	accessToken := newDeviceCatalogAccessToken(t, server, store, "device-1", "admin")

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

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/agent/authorize", strings.NewReader(`{"resource_id":"res-ssh","protocol":"ssh","port":22}`))
	request.RemoteAddr = ""
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.TLS = deviceTLSState(deviceCert)
	handlerDone := make(chan struct{})
	go func() {
		server.requireClientCert(server.deviceAuthMiddleware(http.HandlerFunc(server.handleAgentAuthorize))).ServeHTTP(recorder, request)
		close(handlerDone)
	}()

	command := stream.nextSent(t)
	if got := structFieldString(command, "type"); got != gatewayControlCommandProvisionSession {
		t.Fatalf("command type = %q", got)
	}
	sessionPayload := command.GetFields()["session"].GetStructValue()
	if sessionPayload == nil {
		t.Fatalf("missing session payload: %+v", command.AsMap())
	}
	if structFieldString(sessionPayload, "device_id") != "device-1" || structFieldString(sessionPayload, "resource_id") != "res-ssh" || structFieldString(sessionPayload, "internal_host") != "10.10.0.10" {
		t.Fatalf("session payload = %+v", sessionPayload.AsMap())
	}
	if token := structFieldString(sessionPayload, "session_token"); token == "" {
		t.Fatalf("session token was not sent to Gateway")
	}
	stream.queueRecv(gatewayControlAckFor(t, command, gatewayControlAckStatusOK, "", "provisioned"))

	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("agent authorization handler did not finish")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response agentAuthorizeResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "allow" || response.SessionID == "" || response.SessionToken == "" || response.GatewayID != "gw-1" || response.GatewayEndpoint != "gateway.example.test:9443" {
		t.Fatalf("authorization response = %+v", response)
	}
	if response.SessionToken != structFieldString(sessionPayload, "session_token") {
		t.Fatalf("response token and provisioned token differ")
	}
	if session, ok := store.GetSession(response.SessionID); !ok || session.DeviceID != "device-1" || session.Resource != "res-ssh" {
		t.Fatalf("stored session = %+v found=%t", session, ok)
	}

	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- server.pa.Sessions.RevokeSession(response.SessionID)
	}()
	revokeCommand := stream.nextSent(t)
	if got := structFieldString(revokeCommand, "type"); got != gatewayControlCommandRevokeSession {
		t.Fatalf("revoke command type = %q", got)
	}
	if got := structFieldString(revokeCommand, "session_id"); got != response.SessionID {
		t.Fatalf("revoke session_id = %q", got)
	}
	stream.queueRecv(gatewayControlAckFor(t, revokeCommand, gatewayControlAckStatusOK, "", "revoked"))
	if err := <-revokeDone; err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}

	cancelGateway()
	select {
	case <-streamDone:
	case <-time.After(time.Second):
		t.Fatal("gateway stream did not stop")
	}
}

func TestAgentAuthorizationGRPCProvisionsConnectedGateway(t *testing.T) {
	server, gatewayCert := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	store := server.pa.Store
	store.SaveResource(&models.Resource{
		ID:           "res-ssh",
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
	accessToken := newDeviceCatalogAccessToken(t, server, store, "device-1", "admin")

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
	serviceCtx := context.WithValue(context.Background(), deviceEnrollmentContextKey, enrollment)
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

func TestAgentAuthorizeRequiresConnectedGatewayForAllow(t *testing.T) {
	server, _ := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	store := server.pa.Store
	store.SaveResource(&models.Resource{ID: "res-ssh", Name: "SSH Server", Type: "ssh", Host: "10.10.0.10", Port: 22, Enabled: true, AllowedRoles: []string{"admin"}, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	deviceCertPEM, deviceCert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	store.SaveDeviceEnrollment(&models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		Component:       "endpoint",
		Status:          "approved",
		CertPEM:         string(deviceCertPEM),
		CertFingerprint: clientCertificateFingerprint(deviceCert),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	})
	accessToken := newDeviceCatalogAccessToken(t, server, store, "device-1", "admin")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/agent/authorize", strings.NewReader(`{"resource_id":"res-ssh","protocol":"ssh","port":22}`))
	request.RemoteAddr = ""
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.TLS = deviceTLSState(deviceCert)
	server.requireClientCert(server.deviceAuthMiddleware(http.HandlerFunc(server.handleAgentAuthorize))).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if sessions := store.ListSessions(); len(sessions) != 0 {
		t.Fatalf("sessions were created despite missing gateway: %+v", sessions)
	}
}

func TestAgentAuthorizeDoesNotProvisionWhenMFARequired(t *testing.T) {
	server, _ := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	store := server.pa.Store
	store.DeletePolicyRule("rule_default_deny_unhealthy")
	store.DeletePolicyRule("rule_block_high_risk")
	store.SaveResource(&models.Resource{ID: "res-ssh", Name: "SSH Server", Type: "ssh", Host: "10.10.0.10", Port: 22, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	deviceCertPEM, deviceCert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	store.SaveDeviceEnrollment(&models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		Component:       "endpoint",
		Status:          "approved",
		CertPEM:         string(deviceCertPEM),
		CertFingerprint: clientCertificateFingerprint(deviceCert),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	})
	accessToken := newDeviceCatalogAccessToken(t, server, store, "device-1", "user")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/agent/authorize", strings.NewReader(`{"resource_id":"res-ssh","protocol":"ssh","port":22}`))
	request.RemoteAddr = ""
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.TLS = deviceTLSState(deviceCert)
	server.requireClientCert(server.deviceAuthMiddleware(http.HandlerFunc(server.handleAgentAuthorize))).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response agentAuthorizeResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "mfa_required" || response.SessionID != "" || response.SessionToken != "" {
		t.Fatalf("authorization response = %+v", response)
	}
	if sessions := store.ListSessions(); len(sessions) != 0 {
		t.Fatalf("sessions were created for MFA decision: %+v", sessions)
	}
}

func deviceTLSState(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}
