package tunnel

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

type Tunnel struct {
	pepAddr   string
	tlsConfig *tls.Config
	conn      net.Conn
	session   *yamux.Session
	mu        sync.Mutex
	closed    bool
	authMu    sync.RWMutex
	authFunc  func() (token string, deviceID string)
}

func New(pepAddr, certFile, keyFile, caFile, serverName string) (*Tunnel, error) {
	tlsConfig, err := buildTLSConfig(certFile, keyFile, caFile, serverName)
	if err != nil {
		return nil, fmt.Errorf("TLS config error: %w", err)
	}

	return &Tunnel{
		pepAddr:   pepAddr,
		tlsConfig: tlsConfig,
	}, nil
}

// NewWithSigner creates a tunnel using a crypto.Signer (TPM or software key)
// and a PEM-encoded certificate from enrollment.
func NewWithSigner(pepAddr string, certPEM, caPEM []byte, signer crypto.Signer, serverName string) (*Tunnel, error) {
	tlsConfig, err := buildTLSConfigFromSigner(certPEM, caPEM, signer, serverName)
	if err != nil {
		return nil, fmt.Errorf("TLS config error: %w", err)
	}

	return &Tunnel{
		pepAddr:   pepAddr,
		tlsConfig: tlsConfig,
	}, nil
}

func (t *Tunnel) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connectLocked()
}

func (t *Tunnel) connectLocked() error {
	slog.Info("Connecting to PEP", "address", t.pepAddr)

	if t.tlsConfig == nil {
		return fmt.Errorf("TLS configuration is missing or invalid")
	}

	conn, err := tls.Dial("tcp", t.pepAddr, t.tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	slog.Info("TLS handshake complete",
		"version", fmt.Sprintf("0x%04x", conn.ConnectionState().Version),
		"cipher", fmt.Sprintf("0x%04x", conn.ConnectionState().CipherSuite))

	t.conn = conn

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.KeepAliveInterval = 10 * time.Second
	yamuxConfig.ConnectionWriteTimeout = 10 * time.Second

	session, err := yamux.Client(conn, yamuxConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("Yamux session failed: %w", err)
	}
	t.session = session

	slog.Info("Yamux session established — multiplexing ready")

	// Run the protocol-version handshake before any auth/connect/dns frames
	// are sent. A version mismatch closes the session immediately so we fail
	// fast with a clear log line instead of getting cryptic decode errors
	// further down the request pipeline.
	if err := t.handshake(); err != nil {
		t.session.Close()
		t.conn.Close()
		t.session = nil
		t.conn = nil
		return fmt.Errorf("protocol handshake failed: %w", err)
	}
	return nil
}

// handshake exchanges hello / hello_ack with the gateway to negotiate the
// wire protocol version. The handshake runs on a dedicated yamux stream and
// is independent of any auth state.
func (t *Tunnel) handshake() error {
	stream, err := t.session.Open()
	if err != nil {
		return fmt.Errorf("open hello stream: %w", err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(5 * time.Second))

	hello := HelloRequest{
		Type:          "hello",
		ClientVersion: ProtocolVersion,
		ClientApp:     "connect-app",
		ClientBuild:   ClientBuild,
		Features:      []string{"structured-codes", "hello-handshake"},
	}
	if err := json.NewEncoder(stream).Encode(&hello); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	var resp HelloResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		return fmt.Errorf("decode hello_ack: %w", err)
	}

	if resp.Code != "" && resp.Code != CodeOK {
		return fmt.Errorf("gateway rejected hello [%s]: %s (server=%s, accepts %s..%s)",
			resp.Code, resp.Message, resp.ServerVersion, resp.MinClientVersion, resp.MaxClientVersion)
	}

	slog.Info("Protocol handshake complete",
		"client_version", ProtocolVersion,
		"server_version", resp.ServerVersion,
		"server_features", resp.Features,
	)
	return nil
}

func (t *Tunnel) OpenStream() (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.session == nil {
		return nil, fmt.Errorf("Tunnel not connected")
	}

	stream, err := t.session.Open()
	if err != nil {
		return nil, fmt.Errorf("Open stream: %w", err)
	}

	return stream, nil
}

func (t *Tunnel) SetAuthProvider(fn func() (token string, deviceID string)) {
	t.authMu.Lock()
	defer t.authMu.Unlock()
	t.authFunc = fn
}

func (t *Tunnel) AuthCredentials() (string, string) {
	t.authMu.RLock()
	fn := t.authFunc
	t.authMu.RUnlock()
	if fn == nil {
		return "", ""
	}
	return fn()
}

func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.session != nil {
		t.session.Close()
	}
	if t.conn != nil {
		t.conn.Close()
	}

	slog.Info("Connection to PEP closed")
	return nil
}

func (t *Tunnel) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.session != nil && !t.session.IsClosed()
}

func (t *Tunnel) Reconnect(maxRetries int) error {
	backoff := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		slog.Info("Reconnect attempt", "attempt", i+1, "max", maxRetries)

		t.mu.Lock()
		if t.session != nil {
			t.session.Close()
		}
		if t.conn != nil {
			t.conn.Close()
		}

		err := t.connectLocked()
		t.mu.Unlock()

		if err != nil {
			slog.Warn("Reconnect failed", "error", err)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}

		t.mu.Lock()
		t.closed = false
		t.mu.Unlock()
		slog.Info("Reconnected successfully")
		return nil
	}

	return fmt.Errorf("Reconnect failed after %d attempts", maxRetries)
}

func buildTLSConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("client certificate and key are required for mTLS")
	}
	if caFile == "" {
		return nil, fmt.Errorf("CA certificate is required for server verification")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("Load client cert: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("Read CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("Failed to parse CA cert")
	}

	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	if serverName != "" {
		config.ServerName = serverName
	}

	return config, nil
}

func buildTLSConfigFromSigner(certPEM, caPEM []byte, signer crypto.Signer, serverName string) (*tls.Config, error) {
	if len(certPEM) == 0 {
		return nil, fmt.Errorf("certificate PEM is required")
	}

	// Build tls.Certificate with the signer as PrivateKey
	var tlsCert tls.Certificate
	for rest := certPEM; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		tlsCert.Certificate = append(tlsCert.Certificate, block.Bytes)
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificates in PEM data")
	}
	tlsCert.PrivateKey = signer

	// Build CA pool (combine provided CA PEM + caFile if available)
	caPool := x509.NewCertPool()
	if len(caPEM) > 0 {
		caPool.AppendCertsFromPEM(caPEM)
	}

	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caPool,
	}
	if serverName != "" {
		config.ServerName = serverName
	}

	return config, nil
}
