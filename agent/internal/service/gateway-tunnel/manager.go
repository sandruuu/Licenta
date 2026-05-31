package gatewaytunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	StatusDisabled = "disabled"
	StatusReady    = "ready"
	StatusError    = "error"
	StatusStopped  = "stopped"
)

type ClientCertificateProvider func(context.Context) (tls.Certificate, error)

type DeviceIDProvider func() string

type Options struct {
	Enabled                   bool
	GatewayAddress            string
	ServerName                string
	CAFile                    string
	ClientCertificateProvider ClientCertificateProvider
	DeviceIDProvider          DeviceIDProvider
	Logger                    *slog.Logger
	Timeout                   time.Duration
	KeepAliveInterval         time.Duration
	ReconnectInitialBackoff   time.Duration
	ReconnectMaxBackoff       time.Duration
	ClientBuild               string
}

type Status struct {
	State          string
	GatewayAddress string
	ServerName     string
	ConnectedAt    time.Time
	UpdatedAt      time.Time
	LastError      string
	StreamCount    int64
}

type GatewayError struct {
	Status    string
	Code      string
	Message   string
	ACRValues string
}

func (err *GatewayError) Error() string {
	if err == nil {
		return "gateway error"
	}
	code := strings.TrimSpace(err.Code)
	if code == "" {
		code = strings.TrimSpace(err.Status)
	}
	message := strings.TrimSpace(err.Message)
	if message == "" {
		message = "Gateway rejected resource stream"
	}
	if code == "" {
		return message
	}
	return fmt.Sprintf("%s: %s", code, message)
}

type Manager struct {
	mu                sync.Mutex
	options           Options
	defaultServerName string
	logger            *slog.Logger
	status            Status
	conn              net.Conn
	session           *yamux.Session
	statusMu          sync.RWMutex
}

func NewManager(options Options) (*Manager, error) {
	options.GatewayAddress = strings.TrimSpace(options.GatewayAddress)
	options.ServerName = strings.TrimSpace(options.ServerName)
	options.CAFile = strings.TrimSpace(options.CAFile)
	if !options.Enabled && options.GatewayAddress == "" {
		return &Manager{options: options, logger: loggerOrDefault(options.Logger), status: Status{State: StatusDisabled}}, nil
	}
	options.Enabled = true
	if options.ClientCertificateProvider == nil {
		return nil, errors.New("client certificate provider is required")
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	if options.KeepAliveInterval <= 0 {
		options.KeepAliveInterval = 10 * time.Second
	}
	if options.ReconnectInitialBackoff <= 0 {
		options.ReconnectInitialBackoff = time.Second
	}
	if options.ReconnectMaxBackoff <= 0 {
		options.ReconnectMaxBackoff = 30 * time.Second
	}
	return &Manager{
		options:           options,
		defaultServerName: options.ServerName,
		logger:            loggerOrDefault(options.Logger),
		status:            Status{State: StatusStopped, GatewayAddress: options.GatewayAddress, ServerName: options.ServerName, UpdatedAt: time.Now().UTC()},
	}, nil
}

func (manager *Manager) Run(ctx context.Context) error {
	if manager == nil {
		return errors.New("gateway tunnel manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !manager.options.Enabled {
		<-ctx.Done()
		return nil
	}
	backoff := manager.options.ReconnectInitialBackoff
	for {
		if ctx.Err() != nil {
			manager.closeSession()
			manager.setStatus(Status{State: StatusStopped})
			return nil
		}
		if err := manager.Connect(ctx); err != nil {
			manager.setStatus(Status{State: StatusError, LastError: err.Error()})
			manager.logger.Warn("TrustAgent Gateway tunnel connection failed", "error", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				manager.closeSession()
				manager.setStatus(Status{State: StatusStopped})
				return nil
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > manager.options.ReconnectMaxBackoff {
				backoff = manager.options.ReconnectMaxBackoff
			}
			continue
		}
		backoff = manager.options.ReconnectInitialBackoff
		manager.waitForDisconnect(ctx)
	}
}

func (manager *Manager) Connect(ctx context.Context) error {
	if manager == nil {
		return errors.New("gateway tunnel manager is nil")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.session != nil && !manager.session.IsClosed() {
		return nil
	}
	return manager.connectLocked(ctx)
}

func (manager *Manager) ConnectTo(ctx context.Context, gatewayAddress string) error {
	return manager.ConnectToServerName(ctx, gatewayAddress, "")
}

func (manager *Manager) ConnectToServerName(ctx context.Context, gatewayAddress, serverName string) error {
	if manager == nil {
		return errors.New("gateway tunnel manager is nil")
	}
	gatewayAddress = strings.TrimSpace(gatewayAddress)
	if gatewayAddress == "" {
		return errors.New("gateway endpoint is required")
	}
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		serverName = manager.defaultServerName
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.session != nil && !manager.session.IsClosed() && strings.EqualFold(manager.options.GatewayAddress, gatewayAddress) && strings.EqualFold(strings.TrimSpace(manager.options.ServerName), serverName) {
		return nil
	}
	manager.closeSessionLocked()
	manager.options.GatewayAddress = gatewayAddress
	manager.options.ServerName = serverName
	return manager.connectLocked(ctx)
}

func (manager *Manager) OpenResourceStream(ctx context.Context, request ResourceStreamRequest) (net.Conn, error) {
	if manager == nil {
		return nil, errors.New("gateway tunnel manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	targetHost := strings.TrimSpace(request.TargetHost)
	if targetHost == "" {
		return nil, errors.New("target host is required")
	}
	if request.TargetPort <= 0 {
		return nil, errors.New("target port is required")
	}
	if strings.TrimSpace(request.SessionID) == "" || strings.TrimSpace(request.SessionToken) == "" {
		return nil, errors.New("Gateway stream requires PDP-provisioned session material")
	}
	if err := manager.ConnectToServerName(ctx, firstNonEmpty(request.GatewayEndpoint, manager.options.GatewayAddress), request.GatewayServerName); err != nil {
		return nil, err
	}
	manager.mu.Lock()
	session := manager.session
	manager.mu.Unlock()
	if session == nil || session.IsClosed() {
		return nil, errors.New("Gateway tunnel is not connected")
	}
	stream, err := session.Open()
	if err != nil {
		manager.closeSession()
		return nil, fmt.Errorf("open Gateway stream: %w", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(manager.options.Timeout)
	}
	_ = stream.SetDeadline(deadline)
	connectRequest := ConnectRequest{
		Type:         "connect",
		RemoteAddr:   targetHost,
		RemotePort:   request.TargetPort,
		SessionID:    strings.TrimSpace(request.SessionID),
		SessionToken: strings.TrimSpace(request.SessionToken),
		ResourceID:   strings.TrimSpace(request.ResourceID),
		Protocol:     strings.TrimSpace(request.Protocol),
		Process:      request.Process,
	}
	if manager.options.DeviceIDProvider != nil {
		connectRequest.DeviceID = strings.TrimSpace(manager.options.DeviceIDProvider())
	}
	if err := json.NewEncoder(stream).Encode(connectRequest); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send Gateway connect request: %w", err)
	}
	var response ConnectResponse
	if err := json.NewDecoder(stream).Decode(&response); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("read Gateway connect response: %w", err)
	}
	if response.Status != "connected" || (response.Code != "" && response.Code != CodeOK) {
		_ = stream.Close()
		return nil, &GatewayError{Status: response.Status, Code: response.Code, Message: response.Message, ACRValues: response.ACRValues}
	}
	_ = stream.SetDeadline(time.Time{})
	manager.recordStream()
	return stream, nil
}

func (manager *Manager) Status() Status {
	if manager == nil {
		return Status{State: StatusDisabled}
	}
	manager.statusMu.RLock()
	defer manager.statusMu.RUnlock()
	return manager.status
}

func (manager *Manager) connectLocked(ctx context.Context) error {
	tlsConfig, err := manager.tlsConfig(ctx)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: manager.options.Timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", manager.options.GatewayAddress)
	if err != nil {
		return fmt.Errorf("dial Gateway: %w", err)
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("Gateway TLS handshake: %w", err)
	}
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.KeepAliveInterval = manager.options.KeepAliveInterval
	yamuxConfig.ConnectionWriteTimeout = manager.options.Timeout
	session, err := yamux.Client(tlsConn, yamuxConfig)
	if err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("create yamux session: %w", err)
	}
	manager.conn = tlsConn
	manager.session = session
	if err := manager.helloLocked(); err != nil {
		manager.closeSessionLocked()
		return err
	}
	manager.setStatus(Status{State: StatusReady, ConnectedAt: time.Now().UTC(), LastError: ""})
	manager.logger.Info("TrustAgent Gateway tunnel connected", "gateway", manager.options.GatewayAddress)
	return nil
}

func (manager *Manager) helloLocked() error {
	stream, err := manager.session.Open()
	if err != nil {
		return fmt.Errorf("open Gateway hello stream: %w", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(manager.options.Timeout))
	clientBuild := strings.TrimSpace(manager.options.ClientBuild)
	if clientBuild == "" {
		clientBuild = "dev"
	}
	request := HelloRequest{Type: "hello", ClientVersion: ProtocolVersion, ClientApp: "trustagent", ClientBuild: clientBuild, Features: []string{"pa-provisioned-connect", "yamux", "mtls"}}
	if err := json.NewEncoder(stream).Encode(request); err != nil {
		return fmt.Errorf("send Gateway hello: %w", err)
	}
	var response HelloResponse
	if err := json.NewDecoder(stream).Decode(&response); err != nil {
		return fmt.Errorf("read Gateway hello: %w", err)
	}
	if response.Code != "" && response.Code != CodeOK {
		return fmt.Errorf("Gateway rejected hello [%s]: %s", response.Code, response.Message)
	}
	return nil
}

func (manager *Manager) tlsConfig(ctx context.Context) (*tls.Config, error) {
	certificate, err := manager.options.ClientCertificateProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("load Gateway client certificate: %w", err)
	}
	rootCAs, err := loadRootCAs(manager.options.CAFile)
	if err != nil {
		return nil, err
	}
	serverName := manager.options.ServerName
	if serverName == "" {
		host, _, splitErr := net.SplitHostPort(manager.options.GatewayAddress)
		if splitErr == nil {
			serverName = host
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: rootCAs, Certificates: []tls.Certificate{certificate}}, nil
}

func loadRootCAs(caFile string) (*x509.CertPool, error) {
	if strings.TrimSpace(caFile) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Gateway CA file: %w", err)
	}
	pool := x509.NewCertPool()
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse Gateway CA certificate: %w", err)
			}
			pool.AddCert(cert)
		}
		remaining = rest
	}
	if len(pool.Subjects()) == 0 {
		return nil, errors.New("Gateway CA file does not contain certificates")
	}
	return pool, nil
}

func (manager *Manager) waitForDisconnect(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			manager.closeSession()
			return
		case <-ticker.C:
			manager.mu.Lock()
			closed := manager.session == nil || manager.session.IsClosed()
			manager.mu.Unlock()
			if closed {
				manager.setStatus(Status{State: StatusError, LastError: "Gateway yamux session closed"})
				return
			}
		}
	}
}

func (manager *Manager) closeSession() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.closeSessionLocked()
}

func (manager *Manager) closeSessionLocked() {
	if manager.session != nil {
		_ = manager.session.Close()
	}
	if manager.conn != nil {
		_ = manager.conn.Close()
	}
	manager.session = nil
	manager.conn = nil
}

func (manager *Manager) setStatus(update Status) {
	manager.statusMu.Lock()
	defer manager.statusMu.Unlock()
	current := manager.status
	if strings.TrimSpace(update.State) != "" {
		current.State = update.State
	}
	if !update.ConnectedAt.IsZero() {
		current.ConnectedAt = update.ConnectedAt
	}
	current.UpdatedAt = time.Now().UTC()
	current.LastError = update.LastError
	current.GatewayAddress = manager.options.GatewayAddress
	current.ServerName = manager.options.ServerName
	manager.status = current
}

func (manager *Manager) recordStream() {
	manager.statusMu.Lock()
	defer manager.statusMu.Unlock()
	manager.status.StreamCount++
	manager.status.UpdatedAt = time.Now().UTC()
}

func loggerOrDefault(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.Default()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
