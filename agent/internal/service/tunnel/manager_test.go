package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestNewManagerDisabledWhenNoGatewayConfigured(t *testing.T) {
	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if status := manager.Status(); status.State != StatusDisabled {
		t.Fatalf("status = %+v", status)
	}
}

func TestGatewayErrorFormatsStructuredCode(t *testing.T) {
	err := (&GatewayError{Code: CodePolicyDenied, Message: "blocked"}).Error()
	if err != "policy_denied: blocked" {
		t.Fatalf("error = %q", err)
	}
}

func TestLoadRootCAsParsesPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ZTNA Test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	path := writeTempPEM(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	pool, err := loadRootCAs(path)
	if err != nil {
		t.Fatalf("loadRootCAs returned error: %v", err)
	}
	if len(pool.Subjects()) != 1 {
		t.Fatalf("subjects = %d", len(pool.Subjects()))
	}
}

func TestLoadRootCAsRejectsFileWithoutCertificates(t *testing.T) {
	path := writeTempPEM(t, []byte("not a certificate"))
	_, err := loadRootCAs(path)
	if err == nil || !strings.Contains(err.Error(), "does not contain certificates") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunRejectsNilManager(t *testing.T) {
	var manager *Manager
	if err := manager.Run(context.Background()); err == nil {
		t.Fatalf("expected nil manager error")
	}
}

func TestOpenResourceStreamIncludesStrictSessionFields(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientSession, err := yamux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	defer clientSession.Close()
	serverSession, err := yamux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	defer serverSession.Close()
	captured := make(chan ConnectRequest, 1)
	go func() {
		stream, err := serverSession.Accept()
		if err != nil {
			return
		}
		defer stream.Close()
		var request ConnectRequest
		if err := json.NewDecoder(stream).Decode(&request); err != nil {
			return
		}
		captured <- request
		_ = json.NewEncoder(stream).Encode(ConnectResponse{Type: "connect_response", Status: "connected", Code: CodeOK})
	}()
	manager := &Manager{
		options: Options{GatewayAddress: "gateway.example.test:9443", Timeout: time.Second, AccessTokenProvider: func() (string, string) {
			return "legacy-access-token", "device-1"
		}},
		logger:  loggerOrDefault(nil),
		status:  Status{State: StatusReady},
		session: clientSession,
	}
	stream, err := manager.OpenResourceStream(context.Background(), ResourceStreamRequest{TargetHost: "100.64.0.42", TargetPort: 22, SessionID: "sess-1", SessionToken: "session-token", ResourceID: "res-ssh", Protocol: "ssh", GatewayEndpoint: "gateway.example.test:9443", Process: &ProcessIdentity{PID: 42, Name: "ssh.exe"}})
	if err != nil {
		t.Fatalf("OpenResourceStream returned error: %v", err)
	}
	defer stream.Close()
	select {
	case request := <-captured:
		if request.RemoteAddr != "100.64.0.42" || request.RemotePort != 22 || request.SessionID != "sess-1" || request.SessionToken != "session-token" || request.ResourceID != "res-ssh" || request.Protocol != "ssh" || request.DeviceID != "device-1" {
			t.Fatalf("connect request = %+v", request)
		}
		if request.Token != "" {
			t.Fatalf("legacy bearer token was sent with strict session material")
		}
		if request.Process == nil || request.Process.Name != "ssh.exe" {
			t.Fatalf("process identity = %+v", request.Process)
		}
	case <-time.After(time.Second):
		t.Fatalf("connect request was not captured")
	}
}

func writeTempPEM(t *testing.T, data []byte) string {
	t.Helper()
	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write temp PEM: %v", err)
	}
	return path
}
