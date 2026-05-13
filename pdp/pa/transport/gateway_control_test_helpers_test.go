package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/url"
	"testing"
	"time"

	"pdp/models"
	pagateway "pdp/pa/gateway"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

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
	certPEM, cert := newGatewayControlCertificate(t, transportTestTenantID, gatewayID, fqdn, time.Now().Add(time.Hour))
	server.gatewayControl = NewGatewayControlRegistry()
	dataStore.SaveGateway(&models.Gateway{
		ID:              gatewayID,
		TenantID:        transportTestTenantID,
		TenantIDs:       []string{transportTestTenantID},
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

func newGatewayControlCertificate(t *testing.T, tenantID, gatewayID, fqdn string, notAfter time.Time) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway key: %v", err)
	}
	identityURI, err := url.Parse(pagateway.GatewayIdentityURI(tenantID, gatewayID))
	if err != nil {
		t.Fatalf("parse gateway identity URI: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: gatewayID},
		DNSNames:     []string{fqdn},
		URIs:         []*url.URL{identityURI},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create gateway certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse gateway certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, cert
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
