package dataplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"gateway/internal/provisioning"

	"github.com/hashicorp/yamux"
)

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
		log.Printf("[GATEWAY] denied connect from %s device=%s resource=%s code=%s message=%q session=%s remote_port=%d protocol=%s process=%s",
			state.remoteAddr, request.DeviceID, request.ResourceID, code, message, request.SessionID, request.RemotePort, request.Protocol, processLogName(request.Process))
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
	renewRelay := make(chan time.Time, 1)
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
		renew:      renewRelay,
		cancel:     closeRelay,
	})
	defer func() {
		gateway.activeRelays.Delete(relayID)
		closeRelay("complete")
	}()

	go watchRelayExpiry(relayCtx, session.ExpiresAt, renewRelay, closeRelay)

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
	case provisioning.CodeSessionExpired:
		return nil, CodeSessionExpired, validationErr.Message
	default:
		return nil, CodeSessionInvalid, validationErr.Message
	}
}
