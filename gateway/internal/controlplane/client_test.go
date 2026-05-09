package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gateway/internal/provisioning"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
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
	handler := &recordingHandler{revokeOK: true}
	client, err := NewClient(Config{
		PAURL:     "https://pa.example.test:9443",
		GatewayID: "gw-1",
		CertFile:  "client.crt",
		KeyFile:   "client.key",
		Now:       func() time.Time { return now },
	}, handler)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
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
			"internal_port":      float64(22),
			"protocol":           "ssh",
			"expires_at":         now.Add(time.Hour).Format(time.RFC3339Nano),
			"constraints":        []interface{}{"managed_device", "healthy_posture"},
			"policy_version":     "policy-7",
			"max_bandwidth_mbps": float64(25),
		},
	})

	ack := client.handleCommand(command)
	if got := structFieldString(ack, "status"); got != ackStatusOK {
		t.Fatalf("ack status = %q, want %q", got, ackStatusOK)
	}
	if len(handler.provisioned) != 1 {
		t.Fatalf("provisioned sessions = %d, want 1", len(handler.provisioned))
	}
	session := handler.provisioned[0]
	if session.ID != "sess-1" || session.DeviceID != "device-1" || session.ResourceID != "res-ssh" || session.InternalHost != "10.10.0.10" || session.InternalPort != 22 {
		t.Fatalf("provisioned session = %+v", session)
	}
	if session.ExpiresAt.IsZero() || session.MaxBandwidthMbps != 25 || len(session.Constraints) != 2 {
		t.Fatalf("provisioned session details = %+v", session)
	}
	if len(handler.tokens) != 1 || handler.tokens[0] != "session-secret" {
		t.Fatalf("token = %v", handler.tokens)
	}
}

func TestHandleRevokeSessionCommand(t *testing.T) {
	handler := &recordingHandler{revokeOK: true}
	client, err := NewClient(Config{
		PAURL:     "https://pa.example.test:9443",
		GatewayID: "gw-1",
		CertFile:  "client.crt",
		KeyFile:   "client.key",
	}, handler)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ack := client.handleCommand(mustStruct(t, map[string]interface{}{
		"type":       CommandRevokeSession,
		"command_id": "cmd-2",
		"session_id": "sess-1",
		"reason":     "policy.updated",
	}))
	if got := structFieldString(ack, "status"); got != ackStatusOK {
		t.Fatalf("ack status = %q, want %q", got, ackStatusOK)
	}
	if len(handler.revoked) != 1 || handler.revoked[0] != "sess-1" || handler.reasons[0] != "policy.updated" {
		t.Fatalf("revocations = %v reasons = %v", handler.revoked, handler.reasons)
	}
}

func TestHandleProvisionSessionRejectsMalformedCommand(t *testing.T) {
	client, err := NewClient(Config{PAURL: "https://pa.example.test:9443", GatewayID: "gw-1", CertFile: "client.crt", KeyFile: "client.key"}, &recordingHandler{})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	ack := client.handleCommand(mustStruct(t, map[string]interface{}{
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

func TestRunOnceUsesMTLSAndAppliesStreamCommands(t *testing.T) {
	certs := generateTestCertificates(t)
	handler := &recordingHandler{revokeOK: true}
	server := &testControlServer{t: t}

	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certs.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certs.caPool,
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	grpcServer.RegisterService(&testControlServiceDesc, server)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	go grpcServer.Serve(listener)
	t.Cleanup(func() {
		grpcServer.Stop()
		listener.Close()
	})

	client, err := NewClient(Config{
		PAURL:      "https://" + listener.Addr().String(),
		GatewayID:  "gw-1",
		ServerName: "localhost",
		CAFile:     certs.caFile,
		CertFile:   certs.clientCertFile,
		KeyFile:    certs.clientKeyFile,
	}, handler)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if !server.sawClientCertificate {
		t.Fatal("server did not observe a verified gateway client certificate")
	}
	if len(handler.provisioned) != 1 || handler.provisioned[0].ID != "sess-stream" {
		t.Fatalf("stream provisioned sessions = %+v", handler.provisioned)
	}
	if len(handler.revoked) != 1 || handler.revoked[0] != "sess-stream" {
		t.Fatalf("stream revocations = %v", handler.revoked)
	}
}

type testControlServer struct {
	t                    *testing.T
	sawClientCertificate bool
}

func (server *testControlServer) ControlStream(stream grpc.ServerStream) error {
	peerInfo, ok := peer.FromContext(stream.Context())
	if ok {
		if tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo); ok && len(tlsInfo.State.PeerCertificates) > 0 {
			server.sawClientCertificate = true
		}
	}
	hello := &structpb.Struct{}
	if err := stream.RecvMsg(hello); err != nil {
		return err
	}
	if got := structFieldString(hello, "type"); got != MessageGatewayHello {
		server.t.Fatalf("hello type = %q, want %q", got, MessageGatewayHello)
	}
	provision := mustStruct(server.t, map[string]interface{}{
		"type":       CommandProvisionSession,
		"command_id": "cmd-stream-1",
		"session": map[string]interface{}{
			"session_id":    "sess-stream",
			"session_token": "stream-token",
			"device_id":     "device-1",
			"resource_id":   "res-ssh",
			"internal_host": "10.10.0.10",
			"internal_port": float64(22),
			"protocol":      "ssh",
			"expires_at":    time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		},
	})
	if err := stream.SendMsg(provision); err != nil {
		return err
	}
	ack := &structpb.Struct{}
	if err := stream.RecvMsg(ack); err != nil {
		return err
	}
	if got := structFieldString(ack, "status"); got != ackStatusOK {
		server.t.Fatalf("provision ack status = %q", got)
	}
	revoke := mustStruct(server.t, map[string]interface{}{
		"type":       CommandRevokeSession,
		"command_id": "cmd-stream-2",
		"session_id": "sess-stream",
		"reason":     "session.revoked",
	})
	if err := stream.SendMsg(revoke); err != nil {
		return err
	}
	ack = &structpb.Struct{}
	if err := stream.RecvMsg(ack); err != nil {
		return err
	}
	if got := structFieldString(ack, "status"); got != ackStatusOK {
		server.t.Fatalf("revoke ack status = %q", got)
	}
	return nil
}

type testCertificates struct {
	caFile         string
	clientCertFile string
	clientKeyFile  string
	serverCert     tls.Certificate
	caPool         *x509.CertPool
}

func generateTestCertificates(t *testing.T) testCertificates {
	t.Helper()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(ca) error = %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ZTNA Test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(ca) error = %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(ca) error = %v", err)
	}
	serverCert := signedLeaf(t, caCert, caKey, "pa.local", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true)
	clientCertDER, clientKey := signedLeafDER(t, caCert, caKey, "gw-1", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	clientCertFile := filepath.Join(dir, "client.pem")
	clientKeyFile := filepath.Join(dir, "client-key.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)
	writePEM(t, clientCertFile, "CERTIFICATE", clientCertDER)
	writePEM(t, clientKeyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return testCertificates{caFile: caFile, clientCertFile: clientCertFile, clientKeyFile: clientKeyFile, serverCert: serverCert, caPool: pool}
}

func signedLeaf(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, commonName string, usages []x509.ExtKeyUsage, isServer bool) tls.Certificate {
	t.Helper()
	der, key := signedLeafDER(t, caCert, caKey, commonName, usages, isServer)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	return cert
}

func signedLeafDER(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, commonName string, usages []x509.ExtKeyUsage, isServer bool) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(%s) error = %v", commonName, err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usages,
	}
	if isServer {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s) error = %v", commonName, err)
	}
	return der, key
}

func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create(%s) error = %v", path, err)
	}
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		file.Close()
		t.Fatalf("Encode(%s) error = %v", path, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close(%s) error = %v", path, err)
	}
}

type testControlService interface {
	ControlStream(grpc.ServerStream) error
}

func testControlStreamHandler(server interface{}, stream grpc.ServerStream) error {
	return server.(testControlService).ControlStream(stream)
}

var testControlServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*testControlService)(nil),
	Streams: []grpc.StreamDesc{
		{StreamName: "ControlStream", Handler: testControlStreamHandler, ServerStreams: true, ClientStreams: true},
	},
	Metadata: "gateway_control.proto",
}

func mustStruct(t *testing.T, fields map[string]interface{}) *structpb.Struct {
	t.Helper()
	value, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("NewStruct() error = %v", err)
	}
	return value
}
