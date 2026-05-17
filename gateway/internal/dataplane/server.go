package dataplane

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gatewaycert "gateway/internal/cert"
	"gateway/internal/config"
	"gateway/internal/controlplane"
	"gateway/internal/provisioning"

	"github.com/hashicorp/yamux"
)

const (
	agentListenAddr          = ":9443"
	relayDialTimeout         = 10 * time.Second
	maxConnections           = 1000
	maxConnectionsPerIP      = 100
	relayBufferSizeBytes     = 64 * 1024
	yamuxMaxStreamWindowSize = 256 * 1024
	yamuxStreamOpenTimeout   = 30 * time.Second
	yamuxStreamCloseTimeout  = 5 * time.Minute
	revocationSyncInterval   = time.Minute
	certExpiryCheckInterval  = 12 * time.Hour
	certExpiryCriticalWindow = 7 * 24 * time.Hour
	certExpiryWarningWindow  = 30 * 24 * time.Hour
	certRenewalCheckInterval = 6 * time.Hour
	certRenewalWindow        = 48 * time.Hour
	maxRelayBandwidthMbps    = 400
)

type Gateway struct {
	cfg          *config.Config
	controlPlane *controlplane.Client
	relay        *Relay

	provisioned *provisioning.Store

	ctx    context.Context
	cancel context.CancelFunc

	activeConns atomic.Int64
	perIPConns  sync.Map

	revokedSerials sync.Map
	activeRelays   sync.Map
}

type connectionState struct {
	remoteAddr   string
	certDeviceID string
}

type activeRelay struct {
	id         string
	sessionID  string
	deviceID   string
	resourceID string
	cancel     func(reason string)
}

func New(cfg *config.Config, controlPlaneClient *controlplane.Client, relayManager *Relay) *Gateway {
	if relayManager == nil {
		relayManager = NewRelay(relayDialTimeout)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Gateway{
		cfg:          cfg,
		controlPlane: controlPlaneClient,
		relay:        relayManager,
		provisioned:  provisioning.NewStore(),
		ctx:          ctx,
		cancel:       cancel,
	}
}

func (gateway *Gateway) ProvisionSession(session provisioning.Session, sessionToken string) error {
	if gateway.provisioned == nil {
		gateway.provisioned = provisioning.NewStore()
	}
	if err := gateway.provisioned.Provision(session, sessionToken); err != nil {
		return err
	}
	log.Printf("[GATEWAY] PA provisioned session %s for device=%s resource=%s target=%s:%d expires=%s",
		session.ID, session.DeviceID, session.ResourceID, session.InternalHost, session.InternalPort, session.ExpiresAt.Format(time.RFC3339))
	return nil
}

func (gateway *Gateway) RevokeProvisionedSession(sessionID, reason string) bool {
	if gateway.provisioned == nil {
		return false
	}
	session, ok := gateway.provisioned.Revoke(sessionID, reason)
	if !ok {
		return false
	}
	gateway.terminateRelays(func(relay *activeRelay) bool {
		return relay.sessionID == session.ID
	}, "session.revoked")
	log.Printf("[GATEWAY] PA revoked session %s reason=%s", sessionID, strings.TrimSpace(reason))
	return true
}

func (gateway *Gateway) ProvisionedSessionCount() int {
	if gateway == nil || gateway.provisioned == nil {
		return 0
	}
	return gateway.provisioned.Count()
}

func (gateway *Gateway) ListenAndServe() error {
	if gateway.cfg == nil {
		return fmt.Errorf("gateway config is required")
	}
	listener, err := gateway.listen()
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-gateway.ctx.Done()
		_ = listener.Close()
	}()

	gateway.syncRevokedSerials()
	go gateway.revocationSyncLoop()
	go gateway.certExpiryLoop()

	log.Printf("[GATEWAY] strict PEP listening on %s", agentListenAddr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if gateway.ctx.Err() != nil {
				return nil
			}
			log.Printf("[GATEWAY] accept failed: %v", err)
			continue
		}
		go gateway.handleConnection(conn)
	}
}

func (gateway *Gateway) listen() (net.Listener, error) {
	tlsConfig, useTLS, err := gateway.buildServerTLSConfig()
	if err != nil {
		return nil, err
	}
	baseListener, err := net.Listen("tcp", agentListenAddr)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		baseListener.Close()
		return nil, fmt.Errorf("gateway certificate and key are required")
	}
	return tls.NewListener(baseListener, tlsConfig), nil
}

func (gateway *Gateway) buildServerTLSConfig() (*tls.Config, bool, error) {
	clientCAPool, err := gateway.clientCAPool()
	if err != nil {
		return nil, false, err
	}
	if clientCAPool == nil {
		return nil, false, fmt.Errorf("Agent mTLS requires PA CA or a reachable PA CA endpoint")
	}
	if _, err := loadGatewayServerCertificate(); err != nil {
		return nil, false, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientCAs:  clientCAPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := loadGatewayServerCertificate()
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("client certificate is required")
			}
			cert := state.PeerCertificates[0]
			for _, key := range serialLookupKeys(cert.SerialNumber) {
				if _, revoked := gateway.revokedSerials.Load(key); revoked {
					return fmt.Errorf("client certificate serial %s is revoked", cert.SerialNumber.String())
				}
			}
			return nil
		},
	}

	return tlsConfig, true, nil
}

func loadGatewayServerCertificate() (tls.Certificate, error) {
	cert, err := gatewaycert.LoadGatewayKeyPairAndValidateCert(config.GatewayCertPath, config.GatewayKeyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load gateway TLS key pair: %w", err)
	}
	return cert, nil
}

func (gateway *Gateway) clientCAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	added := false
	for _, path := range []string{config.PACAPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read client CA %s: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse client CA %s", path)
		}
		added = true
	}
	if gateway.controlPlane != nil {
		if caPEM, err := gateway.controlPlane.GetCACert(); err == nil && len(caPEM) > 0 {
			if pool.AppendCertsFromPEM(caPEM) {
				added = true
			}
		} else {
			log.Printf("[GATEWAY] PA CA fetch failed: %v", err)
		}
	}
	if !added {
		return nil, nil
	}
	return pool, nil
}

func (gateway *Gateway) handleConnection(conn net.Conn) {
	remoteIP := remoteIPOnly(conn.RemoteAddr())
	if gateway.activeConns.Load() >= maxConnections {
		log.Printf("[GATEWAY] rejected connection from %s: global connection limit reached", remoteIP)
		_ = conn.Close()
		return
	}
	if count := gateway.incIP(remoteIP); count > maxConnectionsPerIP {
		gateway.decIP(remoteIP)
		log.Printf("[GATEWAY] rejected connection from %s: per-IP connection limit reached", remoteIP)
		_ = conn.Close()
		return
	}
	gateway.activeConns.Add(1)
	defer func() {
		gateway.activeConns.Add(-1)
		gateway.decIP(remoteIP)
		_ = conn.Close()
	}()

	state := &connectionState{remoteAddr: conn.RemoteAddr().String()}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[GATEWAY] TLS handshake failed from %s: %v", state.remoteAddr, err)
			return
		}
		tlsState := tlsConn.ConnectionState()
		if len(tlsState.PeerCertificates) > 0 {
			state.certDeviceID = strings.TrimSpace(tlsState.PeerCertificates[0].Subject.CommonName)
		}
	}

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.MaxStreamWindowSize = yamuxMaxStreamWindowSize
	yamuxConfig.StreamOpenTimeout = yamuxStreamOpenTimeout
	yamuxConfig.StreamCloseTimeout = yamuxStreamCloseTimeout
	session, err := yamux.Server(conn, yamuxConfig)
	if err != nil {
		log.Printf("[GATEWAY] yamux session failed from %s: %v", state.remoteAddr, err)
		return
	}
	defer session.Close()

	for {
		stream, err := session.Accept()
		if err != nil {
			if gateway.ctx.Err() != nil {
				return
			}
			return
		}
		go gateway.handleStream(stream, state)
	}
}

func (gateway *Gateway) handleStream(stream net.Conn, state *connectionState) {
	defer stream.Close()

	decoder := json.NewDecoder(stream)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		log.Printf("[GATEWAY] invalid stream frame from %s: %v", state.remoteAddr, err)
		return
	}

	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		_ = json.NewEncoder(stream).Encode(ConnectResponse{Type: "connect_response", Status: "denied", Code: CodeBadRequest, Message: "invalid JSON frame"})
		return
	}

	switch envelope.Type {
	case "hello":
		var request HelloRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			_ = json.NewEncoder(stream).Encode(HelloResponse{Type: "hello_ack", Code: CodeBadRequest, Message: "invalid hello frame"})
			return
		}
		gateway.handleHello(stream, &request)
	case "connect":
		var request ConnectRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			_ = json.NewEncoder(stream).Encode(ConnectResponse{Type: "connect_response", Status: "denied", Code: CodeBadRequest, Message: "invalid connect frame"})
			return
		}
		gateway.handleConnectRequest(stream, &request, state)
	default:
		_ = json.NewEncoder(stream).Encode(ConnectResponse{Type: "connect_response", Status: "denied", Code: CodeBadRequest, Message: "unsupported gateway request type"})
	}
}

func (gateway *Gateway) handleHello(stream net.Conn, request *HelloRequest) {
	response := HelloResponse{
		Type:             "hello_ack",
		Code:             CodeOK,
		ServerVersion:    ProtocolVersion,
		MinClientVersion: ProtocolMinClientVersion,
		MaxClientVersion: ProtocolMaxClientVersion,
		Features:         []string{"pa-provisioned-connect", "yamux", "mtls"},
	}
	if request == nil || strings.TrimSpace(request.ClientVersion) == "" {
		response.Code = CodeBadRequest
		response.Message = "client_version is required"
	}
	_ = json.NewEncoder(stream).Encode(response)
}

func (gateway *Gateway) handleConnectRequest(stream net.Conn, request *ConnectRequest, state *connectionState) {
	encoder := json.NewEncoder(stream)
	session, code, message := gateway.validateProvisionedConnect(request, state)
	if code != "" {
		log.Printf("[GATEWAY] denied connect from %s device=%s resource=%s code=%s process=%s",
			state.remoteAddr, request.DeviceID, request.ResourceID, code, processLogName(request.Process))
		_ = encoder.Encode(ConnectResponse{Type: "connect_response", Status: "denied", Code: code, Message: message})
		return
	}

	targetConn, err := gateway.relay.Connect(session.InternalHost, session.InternalPort)
	if err != nil {
		log.Printf("[GATEWAY] relay connect failed session=%s target=%s:%d err=%v", session.ID, session.InternalHost, session.InternalPort, err)
		_ = encoder.Encode(ConnectResponse{Type: "connect_response", Status: "denied", Code: CodeResourceUnavailable, Message: "internal resource is unavailable"})
		return
	}

	if err := encoder.Encode(ConnectResponse{Type: "connect_response", Status: "connected", Code: CodeOK, Message: "connected"}); err != nil {
		_ = targetConn.Close()
		return
	}

	relayID := newRelayID()
	relayCtx, cancelRelay := context.WithCancel(gateway.ctx)
	var closeOnce sync.Once
	closeRelay := func(reason string) {
		closeOnce.Do(func() {
			log.Printf("[GATEWAY] closing relay id=%s session=%s reason=%s", relayID, session.ID, reason)
			cancelRelay()
			_ = targetConn.Close()
			_ = stream.Close()
		})
	}
	gateway.activeRelays.Store(relayID, &activeRelay{
		id:         relayID,
		sessionID:  session.ID,
		deviceID:   session.DeviceID,
		resourceID: session.ResourceID,
		cancel:     closeRelay,
	})
	defer func() {
		gateway.activeRelays.Delete(relayID)
		closeRelay("complete")
	}()

	if deadline := time.Until(session.ExpiresAt); deadline > 0 {
		timer := time.NewTimer(deadline)
		defer timer.Stop()
		go func() {
			select {
			case <-timer.C:
				closeRelay("session.expired")
			case <-relayCtx.Done():
			}
		}()
	}

	bytesPerSecond := relayLimitBytesPerSecond(session.MaxBandwidthMbps, maxRelayBandwidthMbps)
	log.Printf("[GATEWAY] relay opened id=%s session=%s device=%s resource=%s target=%s:%d process=%s",
		relayID, session.ID, session.DeviceID, session.ResourceID, session.InternalHost, session.InternalPort, processLogName(request.Process))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := rateLimitedCopy(targetConn, stream, bytesPerSecond, relayBufferSizeBytes)
		if err != nil && relayCtx.Err() == nil {
			log.Printf("[GATEWAY] client->target copy ended id=%s bytes=%d err=%v", relayID, n, err)
		}
		closeRelay("client.closed")
	}()
	go func() {
		defer wg.Done()
		n, err := rateLimitedCopy(stream, targetConn, bytesPerSecond, relayBufferSizeBytes)
		if err != nil && relayCtx.Err() == nil {
			log.Printf("[GATEWAY] target->client copy ended id=%s bytes=%d err=%v", relayID, n, err)
		}
		closeRelay("target.closed")
	}()
	wg.Wait()
}

func (gateway *Gateway) validateProvisionedConnect(request *ConnectRequest, state *connectionState) (*provisioning.Session, string, string) {
	if request == nil {
		return nil, CodeBadRequest, "connect request is required"
	}
	if strings.TrimSpace(request.SessionID) == "" || strings.TrimSpace(request.SessionToken) == "" {
		return nil, CodeSessionInvalid, "connect requires a PA-provisioned session_id and session_token"
	}
	if state != nil && state.certDeviceID != "" && strings.TrimSpace(request.DeviceID) != state.certDeviceID {
		return nil, CodeAuthInvalid, "device certificate does not match connect request"
	}
	if gateway.provisioned == nil {
		return nil, CodeSessionInvalid, "no PA-provisioned sessions are available"
	}
	session, err := gateway.provisioned.Validate(provisioning.ConnectCheck{
		SessionID:    request.SessionID,
		SessionToken: request.SessionToken,
		DeviceID:     request.DeviceID,
		ResourceID:   request.ResourceID,
		Protocol:     request.Protocol,
		Port:         request.RemotePort,
	})
	if err == nil {
		return session, "", ""
	}
	validationErr, _ := provisioning.AsValidationError(err)
	switch validationErr.Code {
	case provisioning.CodeBadRequest:
		return nil, CodeBadRequest, validationErr.Message
	default:
		return nil, CodeSessionInvalid, validationErr.Message
	}
}

func (gateway *Gateway) syncRevokedSerials() {
	if gateway.controlPlane == nil {
		return
	}
	serials, err := gateway.controlPlane.GetRevokedSerials()
	if err != nil {
		log.Printf("[GATEWAY] revocation sync failed: %v", err)
		return
	}
	if len(serials) == 0 {
		return
	}
	gateway.revokedSerials.Range(func(key, _ any) bool {
		gateway.revokedSerials.Delete(key)
		return true
	})
	for _, serial := range serials {
		for _, key := range normalizedSerialKeys(serial) {
			gateway.revokedSerials.Store(key, true)
		}
	}
	log.Printf("[GATEWAY] synced %d revoked certificate serial(s) from PA", len(serials))
}

func (gateway *Gateway) revocationSyncLoop() {
	ticker := time.NewTicker(revocationSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.syncRevokedSerials()
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) certExpiryLoop() {
	gateway.checkCertExpiry()
	ticker := time.NewTicker(certExpiryCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.checkCertExpiry()
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) checkCertExpiry() {
	certFiles := map[string]string{
		"gateway_cert": config.GatewayCertPath,
		"pa_ca":        config.PACAPath,
	}
	for label, path := range certFiles {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[GATEWAY] cannot read certificate %s (%s): %v", label, path, err)
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		remaining := time.Until(cert.NotAfter)
		if remaining < 0 {
			log.Printf("[GATEWAY] certificate %s expired on %s", label, cert.NotAfter.Format(time.RFC3339))
		} else if remaining < certExpiryCriticalWindow {
			log.Printf("[GATEWAY] certificate %s expires soon in %s", label, remaining.Round(time.Hour))
		} else if remaining < certExpiryWarningWindow {
			log.Printf("[GATEWAY] certificate %s expires in %d days", label, int(remaining.Hours()/24))
		}
	}
}

func (gateway *Gateway) StartCertRenewalLoop(ctx context.Context) {
	gateway.renewCertIfNeeded(certRenewalWindow)
	ticker := time.NewTicker(certRenewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.renewCertIfNeeded(certRenewalWindow)
		case <-ctx.Done():
			return
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) renewCertIfNeeded(threshold time.Duration) {
	if gateway.controlPlane == nil {
		return
	}
	certPath := config.GatewayCertPath
	keyPath := config.GatewayKeyPath
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Printf("[GATEWAY] cannot read mTLS certificate for renewal: %v", err)
		return
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		log.Printf("[GATEWAY] cannot decode mTLS certificate for renewal")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("[GATEWAY] cannot parse mTLS certificate for renewal: %v", err)
		return
	}
	remaining := time.Until(cert.NotAfter)
	if remaining > threshold {
		return
	}

	newKey, err := gatewaycert.GenerateGatewayPrivateKey()
	if err != nil {
		log.Printf("[GATEWAY] generate renewal key failed: %v", err)
		return
	}
	gatewayID := gateway.identityForCertificateRenewal()
	if gatewayID == "" {
		log.Printf("[GATEWAY] cannot renew mTLS certificate: gateway identity is required")
		return
	}
	ekuExtension, err := gatewaycert.GatewayExtendedKeyUsageExtension()
	if err != nil {
		log.Printf("[GATEWAY] build renewal EKU extension failed: %v", err)
		return
	}
	renewalCSR := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: gatewayID},
		DNSNames:    append([]string(nil), cert.DNSNames...),
		IPAddresses: append([]net.IP(nil), cert.IPAddresses...),
		ExtraExtensions: []pkix.Extension{
			ekuExtension,
		},
	}
	renewalCSR.URIs = append(renewalCSR.URIs, cert.URIs...)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, renewalCSR, newKey)
	if err != nil {
		log.Printf("[GATEWAY] create renewal CSR failed: %v", err)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	result, err := gateway.controlPlane.RenewCert(string(csrPEM))
	if err != nil {
		log.Printf("[GATEWAY] certificate renewal request failed: %v", err)
		return
	}
	renewedCert, err := gatewaycert.ParseGatewayCertificatePEM([]byte(result.CertPEM))
	if err != nil {
		log.Printf("[GATEWAY] renewed certificate parse failed: %v", err)
		return
	}
	if err := gatewaycert.ValidateGatewayCertificate(renewedCert); err != nil {
		log.Printf("[GATEWAY] renewed certificate rejected: %v", err)
		return
	}
	keyPEM, err := gatewaycert.EncodePrivateKeyPEM(newKey)
	if err != nil {
		log.Printf("[GATEWAY] encode renewal key failed: %v", err)
		return
	}
	if err := config.AtomicWriteFile(keyPath, keyPEM, 0o600); err != nil {
		log.Printf("[GATEWAY] write renewal key failed: %v", err)
		return
	}
	if err := config.AtomicWriteFile(certPath, []byte(result.CertPEM), 0o644); err != nil {
		log.Printf("[GATEWAY] write renewed certificate failed: %v", err)
		return
	}
	if result.CAPEM != "" {
		if err := config.AtomicWriteFile(config.PACAPath, []byte(result.CAPEM), 0o644); err != nil {
			log.Printf("[GATEWAY] write renewed CA failed: %v", err)
		}
	}
	if err := gateway.controlPlane.ReloadTLSCert(certPath, keyPath); err != nil {
		log.Printf("[GATEWAY] reload renewed mTLS certificate failed: %v", err)
		return
	}
	log.Printf("[GATEWAY] renewed mTLS certificate for gateway_id=%s", gatewayID)
}

func (gateway *Gateway) identityForCertificateRenewal() string {
	if gateway == nil || gateway.cfg == nil {
		return ""
	}
	if gateway.cfg.ControlPlane != nil {
		if gatewayID := strings.TrimSpace(gateway.cfg.ControlPlane.GatewayID); gatewayID != "" {
			return gatewayID
		}
	}
	return ""
}

func (gateway *Gateway) Shutdown() {
	if gateway.cancel != nil {
		gateway.cancel()
	}
	gateway.terminateRelays(func(*activeRelay) bool { return true }, "gateway.shutdown")
}

func (gateway *Gateway) terminateRelays(match func(*activeRelay) bool, reason string) {
	count := 0
	gateway.activeRelays.Range(func(_, value any) bool {
		active, ok := value.(*activeRelay)
		if !ok || active == nil {
			return true
		}
		if match(active) {
			active.cancel(reason)
			count++
		}
		return true
	})
	if count > 0 {
		log.Printf("[GATEWAY] terminated %d active relay(s) due to %s", count, reason)
	}
}

func (gateway *Gateway) incIP(ip string) int64 {
	value, _ := gateway.perIPConns.LoadOrStore(ip, &atomic.Int64{})
	return value.(*atomic.Int64).Add(1)
}

func (gateway *Gateway) decIP(ip string) {
	value, ok := gateway.perIPConns.Load(ip)
	if !ok {
		return
	}
	counter := value.(*atomic.Int64)
	if counter.Add(-1) <= 0 {
		gateway.perIPConns.Delete(ip)
	}
}

func relayLimitBytesPerSecond(sessionMbps, globalMbps int) int {
	if sessionMbps > 0 {
		return sessionMbps * 1024 * 1024 / 8
	}
	if globalMbps > 0 {
		return globalMbps * 1024 * 1024 / 8
	}
	return 0
}

func processLogName(process *ProcessIdentity) string {
	if process == nil {
		return "unknown"
	}
	if strings.TrimSpace(process.Name) != "" {
		return strings.TrimSpace(process.Name)
	}
	if strings.TrimSpace(process.Path) != "" {
		return strings.TrimSpace(process.Path)
	}
	if process.PID > 0 {
		return fmt.Sprintf("pid:%d", process.PID)
	}
	return "unknown"
}

func remoteIPOnly(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && host != "" {
		return host
	}
	return addr.String()
}

func newRelayID() string {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("relay-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes[:])
}

func serialLookupKeys(serial *big.Int) []string {
	if serial == nil {
		return nil
	}
	return normalizedSerialKeys(serial.String())
}

func normalizedSerialKeys(serial string) []string {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return nil
	}
	keys := map[string]struct{}{
		strings.ToLower(serial): {},
	}
	if decimal, ok := new(big.Int).SetString(serial, 10); ok {
		keys[decimal.String()] = struct{}{}
		keys[strings.ToLower(decimal.Text(16))] = struct{}{}
	}
	if hexValue, ok := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(serial), "0x"), 16); ok {
		keys[hexValue.String()] = struct{}{}
		keys[strings.ToLower(hexValue.Text(16))] = struct{}{}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	return result
}

func rateLimitedCopy(dst io.Writer, src io.Reader, bytesPerSecond, bufferSize int) (int64, error) {
	if bufferSize <= 0 {
		return 0, fmt.Errorf("relay_buffer_size_bytes must be configured")
	}
	buffer := make([]byte, bufferSize)
	var total int64
	windowStart := time.Now()
	var windowBytes int64
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			total += int64(written)
			windowBytes += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if bytesPerSecond > 0 && windowBytes >= int64(bytesPerSecond) {
				elapsed := time.Since(windowStart)
				if elapsed < time.Second {
					time.Sleep(time.Second - elapsed)
				}
				windowStart = time.Now()
				windowBytes = 0
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return total, nil
			}
			return total, readErr
		}
	}
}

func atoi(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}
