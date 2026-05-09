package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"ztna.local/agent/internal/relay"
	"ztna.local/agent/internal/tunnel"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAuthorizeResourceUsesGRPCMTLSAndBearerMetadata(t *testing.T) {
	serverCertificate := testAuthorizationTLSCertificate(t, "127.0.0.1", nil, []net.IP{net.ParseIP("127.0.0.1")})
	clientCertificate := testAuthorizationTLSCertificate(t, "device-1", nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAnyClientCert})))
	service := &testAuthorizationService{t: t}
	server.RegisterService(&testAuthorizationServiceDesc, service)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	caFile := filepath.Join(t.TempDir(), "authorization-server-ca.pem")
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertificate.Certificate[0]})
	if err := os.WriteFile(caFile, serverCAPEM, 0600); err != nil {
		t.Fatalf("write server CA: %v", err)
	}
	client, err := NewClient(Config{
		CloudURL: "https://" + listener.Addr().String(),
		CAFile:   caFile,
		ClientCertificateProvider: func(context.Context) (tls.Certificate, error) {
			return clientCertificate, nil
		},
		AccessTokenProvider: func() (string, string) {
			return "access-token", "device-1"
		},
	})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	result, err := client.AuthorizeResource(context.Background(), relay.ResourceAuthorizationRequest{ResourceID: "res-ssh", Protocol: "ssh", Port: 22, Process: &tunnel.ProcessIdentity{PID: 4242, Name: "ssh.exe", Path: `C:\Windows\System32\OpenSSH\ssh.exe`, SHA256: "abc123"}})
	if err != nil {
		t.Fatalf("AuthorizeResource returned error: %v", err)
	}
	if !service.sawClientCertificate {
		t.Fatalf("server did not observe a client certificate")
	}
	if service.authorization != "Bearer access-token" || service.resourceID != "res-ssh" || service.protocol != "ssh" || service.port != 22 || service.processName != "ssh.exe" {
		t.Fatalf("service captured auth=%q resource=%q protocol=%q port=%d process=%q", service.authorization, service.resourceID, service.protocol, service.port, service.processName)
	}
	if result.SessionID != "sess-1" || result.SessionToken != "session-token" || result.GatewayEndpoint != "gateway.example.test:9443" || result.ResourceID != "res-ssh" || result.Protocol != "ssh" || result.Port != 22 {
		t.Fatalf("authorization result = %+v", result)
	}
}

func TestAuthorizeResourceReturnsDecisionErrorForMFA(t *testing.T) {
	_, err := authorizationResultFromStruct(mustAuthorizationStruct(t, map[string]interface{}{
		"decision":   "mfa_required",
		"reason":     "step-up required",
		"risk_score": float64(45),
	}))
	decisionErr, ok := err.(*DecisionError)
	if !ok || decisionErr.ErrorCode() != "mfa_required" {
		t.Fatalf("error = %#v", err)
	}
}

type testAuthorizationService struct {
	t                    *testing.T
	sawClientCertificate bool
	authorization        string
	resourceID           string
	protocol             string
	port                 int
	processName          string
}

func (service *testAuthorizationService) AuthorizeResource(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo.AuthInfo == nil {
		service.t.Fatalf("gRPC peer did not include auth info")
	}
	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		service.t.Fatalf("gRPC peer did not include a client certificate")
	}
	service.sawClientCertificate = true
	metadataValues, ok := metadata.FromIncomingContext(ctx)
	if ok {
		values := metadataValues.Get("authorization")
		if len(values) > 0 {
			service.authorization = values[0]
		}
	}
	service.resourceID = structFieldString(request, "resource_id")
	service.protocol = structFieldString(request, "protocol")
	service.port = int(structFieldNumberDefault(request, "port"))
	if process := request.GetFields()["process"].GetStructValue(); process != nil {
		service.processName = structFieldString(process, "name")
	}
	return structpb.NewStruct(map[string]interface{}{
		"decision":         "allow",
		"session_id":       "sess-1",
		"session_token":    "session-token",
		"gateway_id":       "gw-1",
		"gateway_endpoint": "gateway.example.test:9443",
		"resource_id":      "res-ssh",
		"protocol":         "ssh",
		"port":             float64(22),
		"expires_at":       time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	})
}

type testAuthorizationGRPCServer interface {
	AuthorizeResource(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

func testAuthorizationHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(testAuthorizationGRPCServer).AuthorizeResource(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentAuthorizationGRPCAuthorizePath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(testAuthorizationGRPCServer).AuthorizeResource(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var testAuthorizationServiceDesc = grpc.ServiceDesc{
	ServiceName: "ztna.agent.v1.AgentAuthorizationService",
	HandlerType: (*testAuthorizationGRPCServer)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "AuthorizeResource",
		Handler:    testAuthorizationHandler,
	}},
	Streams: []grpc.StreamDesc{},
}

func testAuthorizationTLSCertificate(t *testing.T, commonName string, dnsNames []string, ipAddresses ...[]net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if len(ipAddresses) > 0 {
		template.IPAddresses = ipAddresses[0]
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate returned error: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func mustAuthorizationStruct(t *testing.T, fields map[string]interface{}) *structpb.Struct {
	t.Helper()
	value, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	return value
}
