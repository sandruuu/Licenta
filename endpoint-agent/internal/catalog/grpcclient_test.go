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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestNewGRPCClientRequiresDeviceMTLSCredentials(t *testing.T) {
	_, err := NewGRPCClient(GRPCClientConfig{CloudURL: "https://cloud.example"})
	if err == nil {
		t.Fatalf("NewGRPCClient accepted missing mTLS credentials")
	}
}

func TestGRPCClientFetchCatalogWithMTLS(t *testing.T) {
	serverSawClientCertificate := false
	grpcServer := grpc.NewServer()
	grpcServer.RegisterService(&testCatalogServiceDesc, &testCatalogService{})

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Fatalf("catalog request did not present a client certificate")
		}
		serverSawClientCertificate = true
		grpcServer.ServeHTTP(w, r)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	defer grpcServer.Stop()

	caFile := writeCertificatePEM(t, server.Certificate())
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientCertPEM := testCertificatePEMForKey(t, "device-1", &clientKey.PublicKey, clientKey)

	client, err := NewGRPCClient(GRPCClientConfig{
		CloudURL: server.URL,
		CAFile:   caFile,
		CertPEM:  clientCertPEM,
		Signer:   clientKey,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewGRPCClient returned error: %v", err)
	}
	defer client.Close()

	catalog, err := client.FetchCatalog(context.Background(), "")
	if err != nil {
		t.Fatalf("FetchCatalog returned error: %v", err)
	}
	if !serverSawClientCertificate {
		t.Fatalf("server did not observe client certificate")
	}
	if catalog == nil || catalog.Version != "v1" || len(catalog.Entries) != 1 {
		t.Fatalf("catalog = %+v", catalog)
	}
	if catalog.Entries[0].FQDN != "app.internal" || catalog.Entries[0].ResourceID != "res-1" {
		t.Fatalf("entry = %+v", catalog.Entries[0])
	}

	notModified, err := client.FetchCatalog(context.Background(), "v1")
	if err != nil {
		t.Fatalf("FetchCatalog with current version returned error: %v", err)
	}
	if notModified != nil {
		t.Fatalf("expected nil catalog for not-modified response, got %+v", notModified)
	}
}

type testCatalogService struct{}

func (testCatalogService) GetCatalog(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	currentVersion := ""
	if request != nil && request.GetFields()["current_version"] != nil {
		currentVersion = request.GetFields()["current_version"].GetStringValue()
	}
	if currentVersion == "v1" {
		return structpb.NewStruct(map[string]any{
			"version":      "v1",
			"not_modified": true,
		})
	}
	return structpb.NewStruct(map[string]any{
		"version":    "v1",
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"entries": []any{map[string]any{
			"fqdn":        "app.internal",
			"port":        443,
			"protocol":    "https",
			"resource_id": "res-1",
		}},
		"not_modified": false,
	})
}

type testCatalogGRPCServer interface {
	GetCatalog(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

func testCatalogGetCatalogHandler(service interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return service.(testCatalogGRPCServer).GetCatalog(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: service, FullMethod: deviceCatalogGRPCGetCatalogPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.(testCatalogGRPCServer).GetCatalog(ctx, req.(*structpb.Struct))
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

func writeCertificatePEM(t *testing.T, certificate *x509.Certificate) string {
	t.Helper()
	path := t.TempDir() + string(os.PathSeparator) + "ca.pem"
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}

func testCertificatePEMForKey(t *testing.T, commonName string, publicKey any, signer any) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	return serial
}
