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

	"gateway/internal/config"
	"gateway/internal/provisioning"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/structpb"
)

type recordingControlHandler struct {
	provisioned []provisioning.Session
	tokens      []string
	revoked     []string
	reasons     []string
}

func (handler *recordingControlHandler) ProvisionSession(session provisioning.Session, sessionToken string) error {
	handler.provisioned = append(handler.provisioned, session)
	handler.tokens = append(handler.tokens, sessionToken)
	return nil
}

func (handler *recordingControlHandler) RevokeProvisionedSession(sessionID, reason string) bool {
	handler.revoked = append(handler.revoked, sessionID)
	handler.reasons = append(handler.reasons, reason)
	return true
}

func TestRunControlStreamOnceUsesMTLSAndAppliesCommands(t *testing.T) {
	workspace := t.TempDir()
	restoreWorkingDir := chdir(t, workspace)
	defer restoreWorkingDir()

	certs := generateTestCertificates(t)
	writePEM(t, config.PACAPath, "CERTIFICATE", certs.caDER)
	writePEM(t, config.GatewayCertPath, "CERTIFICATE", certs.gatewayCertDER)
	writePEM(t, config.GatewayKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(certs.gatewayKey))

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

	client, err := NewClient(&config.Config{PAURL: "https://" + listener.Addr().String()})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	protocol, err := NewHandler("gw-1", &recordingControlHandler{}, nil)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.runControlStreamOnce(ctx, protocol); err != nil {
		t.Fatalf("runControlStreamOnce() error = %v", err)
	}
	if !server.sawClientCertificate {
		t.Fatal("server did not observe a verified gateway client certificate")
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
	if got := structFieldString(ack, "status"); got != "ok" {
		server.t.Fatalf("provision ack status = %q", got)
	}
	return nil
}

type testCertificates struct {
	caDER          []byte
	gatewayCertDER []byte
	gatewayKey     *rsa.PrivateKey
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
		SerialNumber:          bigSerial(t),
		Subject:               pkix.Name{CommonName: "TrustCloud Test CA"},
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
	gatewayCertDER, gatewayKey := signedLeafDER(t, caCert, caKey, "gw-1", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, false)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return testCertificates{caDER: caDER, gatewayCertDER: gatewayCertDER, gatewayKey: gatewayKey, serverCert: serverCert, caPool: pool}
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
		SerialNumber: bigSerial(t),
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

func bigSerial(t *testing.T) *big.Int {
	t.Helper()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}
	return serial
}

func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(path), err)
	}
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

func chdir(t *testing.T, dir string) func() {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%s) error = %v", dir, err)
	}
	return func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore Chdir(%s) error = %v", previous, err)
		}
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
