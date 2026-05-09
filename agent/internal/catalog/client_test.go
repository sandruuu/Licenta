package catalog

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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetCatalogUsesGRPCMTLSAndBearerMetadata(t *testing.T) {
	serverCertificate := testCatalogTLSCertificate(t, "127.0.0.1", nil, []net.IP{net.ParseIP("127.0.0.1")})
	clientCertificate := testCatalogTLSCertificate(t, "device-1", nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAnyClientCert,
	})))
	service := &testCatalogService{t: t}
	server.RegisterService(&testCatalogServiceDesc, service)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	caFile := filepath.Join(t.TempDir(), "catalog-server-ca.pem")
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
	})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	catalog, err := client.GetCatalog(context.Background(), "access-token", "v1")
	if err != nil {
		t.Fatalf("GetCatalog returned error: %v", err)
	}
	if !service.sawClientCertificate {
		t.Fatalf("server did not observe a client certificate")
	}
	if service.authorization != "Bearer access-token" || service.currentVersion != "v1" {
		t.Fatalf("service metadata authorization=%q currentVersion=%q", service.authorization, service.currentVersion)
	}
	if catalog.Version != "v2" || catalog.TTLSeconds != 300 || catalog.NotModified {
		t.Fatalf("catalog metadata = %+v", catalog)
	}
	want := []string{"apps.example.test", "example.test"}
	if len(catalog.DNSSuffixes) != len(want) {
		t.Fatalf("dns suffixes = %+v", catalog.DNSSuffixes)
	}
	for index := range want {
		if catalog.DNSSuffixes[index] != want[index] {
			t.Fatalf("dns suffixes = %+v, want %+v", catalog.DNSSuffixes, want)
		}
	}
	if len(catalog.Resources) != 1 || catalog.Resources[0].FQDN != "admin.example.test" || catalog.Resources[0].ResourceID != "res-1" || catalog.Resources[0].Protocol != "https" || catalog.Resources[0].Port != 443 {
		t.Fatalf("resources = %+v", catalog.Resources)
	}
}

func TestCatalogFromStructHandlesNotModified(t *testing.T) {
	response, err := structpb.NewStruct(map[string]interface{}{
		"not_modified": true,
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	catalog, err := catalogFromStruct(response, "v1")
	if err != nil {
		t.Fatalf("catalogFromStruct returned error: %v", err)
	}
	if !catalog.NotModified || catalog.Version != "v1" {
		t.Fatalf("catalog = %+v", catalog)
	}
}

type testCatalogService struct {
	t                    *testing.T
	sawClientCertificate bool
	authorization        string
	currentVersion       string
}

func (service *testCatalogService) GetCatalog(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
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
	service.currentVersion = structFieldString(request, "current_version")
	return structpb.NewStruct(map[string]interface{}{
		"version":      "v2",
		"dns_suffixes": []interface{}{"Example.Test", ".apps.example.test.", "example.test"},
		"resources": []interface{}{map[string]interface{}{
			"fqdn":        "Admin.Example.Test.",
			"resource_id": "res-1",
			"protocol":    "HTTPS",
			"port":        float64(443),
		}},
		"ttl_seconds":  float64(300),
		"not_modified": false,
		"policy_epoch": "v2",
	})
}

type testCatalogGRPCServer interface {
	GetCatalog(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

func testCatalogGetCatalogHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(testCatalogGRPCServer).GetCatalog(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: deviceCatalogGRPCGetCatalogPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(testCatalogGRPCServer).GetCatalog(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var testCatalogServiceDesc = grpc.ServiceDesc{
	ServiceName: "ztna.catalog.v1.DeviceCatalogService",
	HandlerType: (*testCatalogGRPCServer)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "GetCatalog",
		Handler:    testCatalogGetCatalogHandler,
	}},
	Streams: []grpc.StreamDesc{},
}

func testCatalogTLSCertificate(t *testing.T, commonName string, dnsNames []string, ipAddresses ...[]net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
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
