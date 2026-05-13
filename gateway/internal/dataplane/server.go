package dataplane

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/auth"
	"gateway/internal/config"
	"gateway/internal/provisioning"
	"gateway/internal/relay"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/acme/autocert"
)

const (
	maxConnections      int64 = 1000
	maxConnectionsPerIP int64 = 100
	relayBufferSize           = 64 * 1024
)

type Gateway struct {
	cfg   *config.Config
	cloud *auth.CloudClient
	relay *relay.Relay

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

func New(cfg *config.Config, cloud *auth.CloudClient, relayManager *relay.Relay) *Gateway {
	if relayManager == nil {
		relayManager = relay.New()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Gateway{
		cfg:         cfg,
		cloud:       cloud,
		relay:       relayManager,
		provisioned: provisioning.NewStore(),
		ctx:         ctx,
		cancel:      cancel,
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

	log.Printf("[GATEWAY] strict PEP listening on %s", gateway.cfg.ListenAddr)
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
	addr := strings.TrimSpace(gateway.cfg.ListenAddr)
	if addr == "" {
		addr = ":9443"
	}

	tlsConfig, useTLS, err := gateway.buildServerTLSConfig()
	if err != nil {
		return nil, err
	}
	baseListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		baseListener.Close()
		return nil, fmt.Errorf("tls_cert and tls_key are required")
	}
	return tls.NewListener(baseListener, tlsConfig), nil
}

func (gateway *Gateway) buildServerTLSConfig() (*tls.Config, bool, error) {
	useAutocert := gateway.cfg.LetsEncrypt && strings.TrimSpace(gateway.cfg.FQDN) != ""
	certPath := strings.TrimSpace(gateway.cfg.TLSCert)
	keyPath := strings.TrimSpace(gateway.cfg.TLSKey)

	if !useAutocert && (certPath == "" || keyPath == "") {
		return nil, false, nil
	}

	clientCAPool, err := gateway.clientCAPool()
	if err != nil {
		return nil, false, err
	}
	if gateway.cfg.RequireClientCert && clientCAPool == nil {
		return nil, false, fmt.Errorf("require_client_cert=true requires client_ca, tls_ca, cloud_ca, or a reachable cloud CA endpoint")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientCAs:  clientCAPool,
		VerifyConnection: func(state tls.ConnectionState) error {
			if gateway.cfg.RequireClientCert && len(state.PeerCertificates) == 0 {
				return fmt.Errorf("client certificate is required")
			}
			if len(state.PeerCertificates) == 0 {
				return nil
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
	if clientCAPool != nil {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		if gateway.cfg.RequireClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	if useAutocert {
		cacheDir := firstNonEmpty(gateway.cfg.AutocertCacheDir, "certs/autocert")
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cacheDir),
			HostPolicy: autocert.HostWhitelist(gateway.cfg.FQDN),
		}
		tlsConfig.GetCertificate = manager.GetCertificate
		challengeAddr := firstNonEmpty(gateway.cfg.AutocertHTTPAddr, ":80")
		go func() {
			server := &http.Server{Addr: challengeAddr, Handler: manager.HTTPHandler(nil), ReadHeaderTimeout: 5 * time.Second}
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[GATEWAY] ACME HTTP-01 server failed: %v", err)
			}
		}()
		return tlsConfig, true, nil
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false, fmt.Errorf("load TLS key pair: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}
	return tlsConfig, true, nil
}

func (gateway *Gateway) clientCAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	added := false
	for _, path := range []string{gateway.cfg.ClientCA, gateway.cfg.TLSCA, gateway.cfg.CloudCA} {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read client CA %s: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse client CA %s", path)
		}
		added = true
	}
	if gateway.cloud != nil {
		if caPEM, err := gateway.cloud.GetCACert(); err == nil && len(caPEM) > 0 {
			if pool.AppendCertsFromPEM(caPEM) {
				added = true
			}
		} else if gateway.cfg.RequireClientCert {
			log.Printf("[GATEWAY] cloud CA fetch failed: %v", err)
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
	yamuxConfig.MaxStreamWindowSize = 256 * 1024
	yamuxConfig.StreamOpenTimeout = 30 * time.Second
	yamuxConfig.StreamCloseTimeout = 5 * time.Minute
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
		_ = json.NewEncoder(stream).Encode(auth.ConnectResponse{Type: "connect_response", Status: "denied", Code: auth.CodeBadRequest, Message: "invalid JSON frame"})
		return
	}

	switch envelope.Type {
	case "hello":
		var request auth.HelloRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			_ = json.NewEncoder(stream).Encode(auth.HelloResponse{Type: "hello_ack", Code: auth.CodeBadRequest, Message: "invalid hello frame"})
			return
		}
		gateway.handleHello(stream, &request)
	case "connect":
		var request auth.ConnectRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			_ = json.NewEncoder(stream).Encode(auth.ConnectResponse{Type: "connect_response", Status: "denied", Code: auth.CodeBadRequest, Message: "invalid connect frame"})
			return
		}
		gateway.handleConnectRequest(stream, &request, state)
	default:
		_ = json.NewEncoder(stream).Encode(auth.ConnectResponse{Type: "connect_response", Status: "denied", Code: auth.CodeBadRequest, Message: "unsupported gateway request type"})
	}
}

func (gateway *Gateway) handleHello(stream net.Conn, request *auth.HelloRequest) {
	response := auth.HelloResponse{
		Type:             "hello_ack",
		Code:             auth.CodeOK,
		ServerVersion:    auth.ProtocolVersion,
		MinClientVersion: auth.ProtocolMinClientVersion,
		MaxClientVersion: auth.ProtocolMaxClientVersion,
		Features:         []string{"pa-provisioned-connect", "yamux", "mtls"},
	}
	if request == nil || strings.TrimSpace(request.ClientVersion) == "" {
		response.Code = auth.CodeBadRequest
		response.Message = "client_version is required"
	}
	_ = json.NewEncoder(stream).Encode(response)
}

func (gateway *Gateway) handleConnectRequest(stream net.Conn, request *auth.ConnectRequest, state *connectionState) {
	encoder := json.NewEncoder(stream)
	session, code, message := gateway.validateProvisionedConnect(request, state)
	if code != "" {
		log.Printf("[GATEWAY] denied connect from %s device=%s resource=%s code=%s process=%s",
			state.remoteAddr, request.DeviceID, request.ResourceID, code, processLogName(request.Process))
		_ = encoder.Encode(auth.ConnectResponse{Type: "connect_response", Status: "denied", Code: code, Message: message})
		return
	}

	targetConn, err := gateway.relay.Connect(session.InternalHost, session.InternalPort)
	if err != nil {
		log.Printf("[GATEWAY] relay connect failed session=%s target=%s:%d err=%v", session.ID, session.InternalHost, session.InternalPort, err)
		_ = encoder.Encode(auth.ConnectResponse{Type: "connect_response", Status: "denied", Code: auth.CodeCloudUnreachable, Message: "internal resource is unavailable"})
		return
	}

	if err := encoder.Encode(auth.ConnectResponse{Type: "connect_response", Status: "connected", Code: auth.CodeOK, Message: "connected"}); err != nil {
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

	bytesPerSecond := relayLimitBytesPerSecond(session.MaxBandwidthMbps, gateway.cfg.MaxRelayBandwidthMbps)
	log.Printf("[GATEWAY] relay opened id=%s session=%s device=%s resource=%s target=%s:%d process=%s",
		relayID, session.ID, session.DeviceID, session.ResourceID, session.InternalHost, session.InternalPort, processLogName(request.Process))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := rateLimitedCopy(targetConn, stream, bytesPerSecond, relayBufferSize)
		if err != nil && relayCtx.Err() == nil {
			log.Printf("[GATEWAY] client->target copy ended id=%s bytes=%d err=%v", relayID, n, err)
		}
		closeRelay("client.closed")
	}()
	go func() {
		defer wg.Done()
		n, err := rateLimitedCopy(stream, targetConn, bytesPerSecond, relayBufferSize)
		if err != nil && relayCtx.Err() == nil {
			log.Printf("[GATEWAY] target->client copy ended id=%s bytes=%d err=%v", relayID, n, err)
		}
		closeRelay("target.closed")
	}()
	wg.Wait()
}

func (gateway *Gateway) validateProvisionedConnect(request *auth.ConnectRequest, state *connectionState) (*provisioning.Session, string, string) {
	if request == nil {
		return nil, auth.CodeBadRequest, "connect request is required"
	}
	if strings.TrimSpace(request.SessionID) == "" || strings.TrimSpace(request.SessionToken) == "" {
		return nil, auth.CodeSessionInvalid, "connect requires a PA-provisioned session_id and session_token"
	}
	if state != nil && state.certDeviceID != "" && strings.TrimSpace(request.DeviceID) != state.certDeviceID {
		return nil, auth.CodeAuthInvalid, "device certificate does not match connect request"
	}
	if gateway.provisioned == nil {
		return nil, auth.CodeSessionInvalid, "no PA-provisioned sessions are available"
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
		return nil, auth.CodeBadRequest, validationErr.Message
	default:
		return nil, auth.CodeSessionInvalid, validationErr.Message
	}
}

func (gateway *Gateway) syncRevokedSerials() {
	if gateway.cloud == nil {
		return
	}
	serials, source, err := gateway.cloud.GetRevokedSerialsByProvider()
	if err != nil {
		log.Printf("[GATEWAY] revocation sync warning: %v", err)
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
	log.Printf("[GATEWAY] synced %d revoked certificate serial(s) from %s", len(serials), source)
}

func (gateway *Gateway) revocationSyncLoop() {
	ticker := time.NewTicker(time.Minute)
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
	ticker := time.NewTicker(12 * time.Hour)
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
		"tls_cert":  gateway.cfg.TLSCert,
		"mtls_cert": gateway.cfg.MTLSCert,
		"client_ca": gateway.cfg.ClientCA,
		"cloud_ca":  gateway.cfg.CloudCA,
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
		} else if remaining < 7*24*time.Hour {
			log.Printf("[GATEWAY] certificate %s expires soon in %s", label, remaining.Round(time.Hour))
		} else if remaining < 30*24*time.Hour {
			log.Printf("[GATEWAY] certificate %s expires in %d days", label, int(remaining.Hours()/24))
		}
	}
}

func (gateway *Gateway) StartCertRenewalLoop(stop <-chan struct{}) {
	const checkInterval = 6 * time.Hour
	const renewThreshold = 48 * time.Hour

	gateway.renewCertIfNeeded(renewThreshold)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.renewCertIfNeeded(renewThreshold)
		case <-stop:
			return
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) renewCertIfNeeded(threshold time.Duration) {
	if gateway.cloud == nil {
		return
	}
	certPath := strings.TrimSpace(gateway.cfg.MTLSCert)
	keyPath := strings.TrimSpace(gateway.cfg.MTLSKey)
	if certPath == "" || keyPath == "" {
		return
	}
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

	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("[GATEWAY] generate renewal key failed: %v", err)
		return
	}
	gatewayID, tenantID := gateway.identityForCertificateRenewal()
	if gatewayID == "" || tenantID == "" {
		log.Printf("[GATEWAY] cannot renew mTLS certificate: tenant_id and gateway_id are required")
		return
	}
	fqdn := firstNonEmpty(gateway.cfg.FQDN, firstDNSName(cert))
	identityURL, err := url.Parse(fmt.Sprintf(
		"spiffe://ztna.local/tenant/%s/gateway/%s",
		url.PathEscape(tenantID),
		url.PathEscape(gatewayID),
	))
	if err != nil {
		log.Printf("[GATEWAY] build renewal identity URI failed: %v", err)
		return
	}
	renewalCSR := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: gatewayID},
		URIs:    []*url.URL{identityURL},
	}
	if fqdn != "" {
		renewalCSR.DNSNames = []string{fqdn}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, renewalCSR, newKey)
	if err != nil {
		log.Printf("[GATEWAY] create renewal CSR failed: %v", err)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	result, err := gateway.cloud.RenewCert(string(csrPEM))
	if err != nil {
		log.Printf("[GATEWAY] certificate renewal request failed: %v", err)
		return
	}
	keyDER := x509.MarshalPKCS1PrivateKey(newKey)
	if err := config.AtomicWriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		log.Printf("[GATEWAY] write renewal key failed: %v", err)
		return
	}
	if err := config.AtomicWriteFile(certPath, []byte(result.CertPEM), 0o644); err != nil {
		log.Printf("[GATEWAY] write renewed certificate failed: %v", err)
		return
	}
	if result.CAPEM != "" && strings.TrimSpace(gateway.cfg.CloudCA) != "" {
		if err := config.AtomicWriteFile(gateway.cfg.CloudCA, []byte(result.CAPEM), 0o644); err != nil {
			log.Printf("[GATEWAY] write renewed CA failed: %v", err)
		}
	}
	if err := gateway.cloud.ReloadTLSCert(certPath, keyPath); err != nil {
		log.Printf("[GATEWAY] reload renewed mTLS certificate failed: %v", err)
		return
	}
	log.Printf("[GATEWAY] renewed mTLS certificate for gateway_id=%s tenant_id=%s", gatewayID, tenantID)
}

func (gateway *Gateway) identityForCertificateRenewal() (gatewayID, tenantID string) {
	if gateway == nil || gateway.cfg == nil {
		return "", ""
	}
	tenantID = strings.TrimSpace(gateway.cfg.TenantID)
	if gateway.cfg.ControlPlane != nil {
		gatewayID = strings.TrimSpace(gateway.cfg.ControlPlane.GatewayID)
	}
	return gatewayID, tenantID
}

func firstDNSName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, name := range cert.DNSNames {
		if strings.TrimSpace(name) != "" {
			return strings.TrimSpace(name)
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
	return 50 * 1024 * 1024
}

func processLogName(process *auth.ProcessIdentity) string {
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
		bufferSize = 32 * 1024
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func atoi(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}
