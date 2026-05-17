package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"agent/internal/service/appid"
	"agent/internal/service/dnsresolver"
	"agent/internal/service/network"
	"agent/internal/service/tcpproxy"
	"agent/internal/service/tunnel"
	"agent/internal/shared/ipc"
)

const (
	defaultOpenTimeout = 10 * time.Second
	maxRelayBufferSize = 4096
)

type StreamOpener interface {
	OpenResourceStream(context.Context, tunnel.ResourceStreamRequest) (net.Conn, error)
}

type ResourceAuthorizer interface {
	AuthorizeResource(context.Context, ResourceAuthorizationRequest) (ResourceAuthorizationResult, error)
}

type ResourceAuthorizationRequest struct {
	ResourceID string
	Protocol   string
	Port       int
	Process    *tunnel.ProcessIdentity
}

type ResourceAuthorizationResult struct {
	SessionID       string
	SessionToken    string
	ResourceID      string
	Protocol        string
	Port            int
	GatewayID       string
	GatewayEndpoint string
	ExpiresAt       time.Time
}

type Options struct {
	StreamOpener        StreamOpener
	Authorizer          ResourceAuthorizer
	ProcessIdentity     bool
	AccessEventRecorder func(ipc.AccessEvent)
	UserSIDProvider     func() string
	Clock               func() time.Time
	Logger              *slog.Logger
	OpenTimeout         time.Duration
}

type Forwarder struct {
	mu                  sync.RWMutex
	streamOpener        StreamOpener
	authorizer          ResourceAuthorizer
	processIdentity     bool
	accessEventRecorder func(ipc.AccessEvent)
	userSIDProvider     func() string
	clock               func() time.Time
	logger              *slog.Logger
	openTimeout         time.Duration
	flows               map[flowKey]*activeFlow
}

type flowKey struct {
	sourceIP        string
	sourcePort      uint16
	destinationIP   string
	destinationPort uint16
}

type activeFlow struct {
	mu        sync.Mutex
	key       flowKey
	flow      *tcpproxy.Flow
	mapping   dnsresolver.Mapping
	stream    net.Conn
	writer    network.PacketWriter
	process   *tunnel.ProcessIdentity
	state     string
	userSID   string
	startedAt time.Time
	expiresAt time.Time
	bytesIn   int64
	bytesOut  int64
	lastError string
	closed    bool
}

func NewForwarder(options Options) (*Forwarder, error) {
	if options.StreamOpener == nil {
		return nil, errors.New("stream opener is required")
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	openTimeout := options.OpenTimeout
	if openTimeout <= 0 {
		openTimeout = defaultOpenTimeout
	}
	return &Forwarder{streamOpener: options.StreamOpener, authorizer: options.Authorizer, processIdentity: options.ProcessIdentity, accessEventRecorder: options.AccessEventRecorder, userSIDProvider: options.UserSIDProvider, clock: clock, logger: logger, openTimeout: openTimeout, flows: make(map[flowKey]*activeFlow)}, nil
}

func (forwarder *Forwarder) HandlePacket(ctx context.Context, packet network.Packet, mapping dnsresolver.Mapping, writer network.PacketWriter) error {
	if forwarder == nil {
		return errors.New("relay forwarder is nil")
	}
	key := packetFlowKey(packet)
	if packet.Flags&network.TCPFlagRST != 0 {
		forwarder.remove(key, "reset")
		return nil
	}
	if packet.Flags&network.TCPFlagSYN != 0 && packet.Flags&network.TCPFlagACK == 0 {
		return forwarder.handleSYN(ctx, key, packet, mapping, writer)
	}
	if packet.Flags&network.TCPFlagFIN != 0 {
		return forwarder.handleFIN(key, packet, writer)
	}
	if len(packet.Payload) > 0 {
		return forwarder.handleData(key, packet, writer)
	}
	forwarder.handleACK(key)
	return nil
}

func (forwarder *Forwarder) Sessions() []ipc.ActiveSession {
	if forwarder == nil {
		return nil
	}
	forwarder.mu.RLock()
	flows := make([]*activeFlow, 0, len(forwarder.flows))
	for _, flow := range forwarder.flows {
		flows = append(flows, flow)
	}
	forwarder.mu.RUnlock()
	sessions := make([]ipc.ActiveSession, 0, len(flows))
	for _, flow := range flows {
		flow.mu.Lock()
		session := ipc.ActiveSession{
			ID:         flow.id(),
			ResourceID: flow.mapping.ResourceID,
			FQDN:       flow.mapping.FQDN,
			Protocol:   firstNonEmpty(flow.mapping.Protocol, "tcp"),
			Port:       flow.mapping.Port,
			State:      flow.state,
			UserSID:    flow.userSID,
			StartedAt:  flow.startedAt,
			ExpiresAt:  flow.expiresAt,
			BytesIn:    flow.bytesIn,
			BytesOut:   flow.bytesOut,
			LastError:  flow.lastError,
		}
		flow.mu.Unlock()
		sessions = append(sessions, session)
	}
	return sessions
}

func (forwarder *Forwarder) Close() {
	forwarder.mu.Lock()
	keys := make([]flowKey, 0, len(forwarder.flows))
	for key := range forwarder.flows {
		keys = append(keys, key)
	}
	forwarder.mu.Unlock()
	for _, key := range keys {
		forwarder.remove(key, "closed")
	}
}

func (forwarder *Forwarder) handleSYN(ctx context.Context, key flowKey, packet network.Packet, mapping dnsresolver.Mapping, writer network.PacketWriter) error {
	forwarder.mu.Lock()
	if _, exists := forwarder.flows[key]; exists {
		forwarder.mu.Unlock()
		return nil
	}
	flow := &activeFlow{key: key, mapping: mapping, writer: writer, state: "connecting", userSID: forwarder.userSID(), startedAt: forwarder.clock().UTC()}
	flow.flow = tcpproxy.NewFlow(net.ParseIP(packet.SourceIP), net.ParseIP(packet.DestinationIP), packet.SourcePort, packet.DestinationPort)
	forwarder.flows[key] = flow
	forwarder.mu.Unlock()

	process := forwarder.processForPacket(packet)
	flow.process = process
	openCtx, cancel := context.WithTimeout(ctx, forwarder.openTimeout)
	defer cancel()
	streamRequest := tunnel.ResourceStreamRequest{TargetHost: packet.DestinationIP, TargetPort: int(packet.DestinationPort), ResourceID: strings.TrimSpace(mapping.ResourceID), Protocol: firstNonEmpty(mapping.Protocol, "tcp"), Process: process}
	if forwarder.authorizer != nil {
		authorization, err := forwarder.authorizer.AuthorizeResource(openCtx, ResourceAuthorizationRequest{ResourceID: strings.TrimSpace(mapping.ResourceID), Protocol: firstNonEmpty(mapping.Protocol, "tcp"), Port: authorizationPort(mapping, packet), Process: process})
		if err != nil {
			flow.markError(err.Error())
			forwarder.recordDenyFromSource("policy_administrator", mapping, packet, err)
			if writeErr := writer.WritePacket(tcpproxy.BuildRST(net.ParseIP(packet.SourceIP), net.ParseIP(packet.DestinationIP), packet.SourcePort, packet.DestinationPort, packet.Sequence+1)); writeErr != nil {
				forwarder.remove(key, "authorization_failed")
				return writeErr
			}
			forwarder.remove(key, "authorization_failed")
			return nil
		}
		if strings.TrimSpace(authorization.SessionID) == "" || strings.TrimSpace(authorization.SessionToken) == "" {
			err := errors.New("policy administrator returned incomplete session material")
			flow.markError(err.Error())
			forwarder.recordDenyFromSource("policy_administrator", mapping, packet, err)
			if writeErr := writer.WritePacket(tcpproxy.BuildRST(net.ParseIP(packet.SourceIP), net.ParseIP(packet.DestinationIP), packet.SourcePort, packet.DestinationPort, packet.Sequence+1)); writeErr != nil {
				forwarder.remove(key, "authorization_failed")
				return writeErr
			}
			forwarder.remove(key, "authorization_failed")
			return nil
		}
		streamRequest = applyAuthorization(streamRequest, authorization)
	}
	stream, err := forwarder.streamOpener.OpenResourceStream(openCtx, streamRequest)
	if err != nil {
		flow.markError(err.Error())
		forwarder.recordDeny(mapping, packet, err)
		if writeErr := writer.WritePacket(tcpproxy.BuildRST(net.ParseIP(packet.SourceIP), net.ParseIP(packet.DestinationIP), packet.SourcePort, packet.DestinationPort, packet.Sequence+1)); writeErr != nil {
			forwarder.remove(key, "open_failed")
			return writeErr
		}
		forwarder.remove(key, "open_failed")
		return nil
	}
	flow.mu.Lock()
	flow.stream = stream
	flow.state = "active"
	flow.mu.Unlock()
	if err := writer.WritePacket(flow.flow.HandleSYN(packet.Sequence)); err != nil {
		forwarder.remove(key, "syn_ack_failed")
		return err
	}
	go forwarder.streamToTUN(flow)
	return nil
}

func (forwarder *Forwarder) handleData(key flowKey, packet network.Packet, writer network.PacketWriter) error {
	flow := forwarder.get(key)
	if flow == nil {
		return nil
	}
	ackPacket, data := flow.flow.HandleData(packet.Sequence, packet.Payload)
	if ackPacket != nil {
		if err := writer.WritePacket(ackPacket); err != nil {
			return err
		}
	}
	if len(data) == 0 {
		return nil
	}
	flow.mu.Lock()
	stream := flow.stream
	closed := flow.closed
	flow.mu.Unlock()
	if closed || stream == nil {
		return nil
	}
	written, err := stream.Write(data)
	flow.addBytesIn(int64(written))
	if err != nil {
		flow.markError(err.Error())
		forwarder.remove(key, "stream_write_failed")
		return nil
	}
	return nil
}

func (forwarder *Forwarder) handleACK(key flowKey) {
	flow := forwarder.get(key)
	if flow == nil || flow.flow == nil {
		return
	}
	flow.flow.HandleACK()
}

func (forwarder *Forwarder) handleFIN(key flowKey, packet network.Packet, writer network.PacketWriter) error {
	flow := forwarder.get(key)
	if flow == nil || flow.flow == nil {
		return nil
	}
	if err := writer.WritePacket(flow.flow.HandleFIN(packet.Sequence)); err != nil {
		return err
	}
	forwarder.remove(key, "fin")
	return nil
}

func (forwarder *Forwarder) streamToTUN(flow *activeFlow) {
	defer forwarder.remove(flow.key, "stream_closed")
	buffer := make([]byte, maxRelayBufferSize)
	for {
		flow.mu.Lock()
		stream := flow.stream
		writer := flow.writer
		closed := flow.closed
		flow.mu.Unlock()
		if closed || stream == nil || writer == nil {
			return
		}
		bytesRead, err := stream.Read(buffer)
		if bytesRead > 0 {
			packets := flow.flow.BuildDataPackets(buffer[:bytesRead])
			for _, packet := range packets {
				if writeErr := writer.WritePacket(packet); writeErr != nil {
					flow.markError(writeErr.Error())
					return
				}
			}
			flow.addBytesOut(int64(bytesRead))
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				flow.markError(err.Error())
			}
			finPacket := flow.flow.BuildFIN()
			_ = writer.WritePacket(finPacket)
			return
		}
	}
}

func (forwarder *Forwarder) get(key flowKey) *activeFlow {
	forwarder.mu.RLock()
	defer forwarder.mu.RUnlock()
	return forwarder.flows[key]
}

func (forwarder *Forwarder) remove(key flowKey, state string) {
	forwarder.mu.Lock()
	flow := forwarder.flows[key]
	delete(forwarder.flows, key)
	forwarder.mu.Unlock()
	if flow == nil {
		return
	}
	flow.mu.Lock()
	if !flow.closed && flow.stream != nil {
		_ = flow.stream.Close()
	}
	flow.closed = true
	if state != "" {
		flow.state = state
	}
	flow.mu.Unlock()
}

func (forwarder *Forwarder) processForPacket(packet network.Packet) *tunnel.ProcessIdentity {
	if !forwarder.processIdentity {
		return nil
	}
	identity, err := appid.LookupTCPProcess(appid.FlowKey{LocalIP: net.ParseIP(packet.SourceIP), LocalPort: packet.SourcePort, RemoteIP: net.ParseIP(packet.DestinationIP), RemotePort: packet.DestinationPort})
	if err != nil || identity == nil {
		if err != nil {
			forwarder.logger.Debug("ZTNA Agent process identity lookup failed", "error", err)
		}
		return nil
	}
	return &tunnel.ProcessIdentity{PID: int(identity.PID), Name: identity.Name, Path: identity.Path, SHA256: identity.SHA256, Signer: identity.Signer}
}

func (forwarder *Forwarder) recordDeny(mapping dnsresolver.Mapping, packet network.Packet, err error) {
	forwarder.recordDenyFromSource("gateway_tunnel", mapping, packet, err)
}

func (forwarder *Forwarder) recordDenyFromSource(source string, mapping dnsresolver.Mapping, packet network.Packet, err error) {
	if forwarder.accessEventRecorder == nil || err == nil {
		return
	}
	code := "authorization_failed"
	if source == "gateway_tunnel" {
		code = "gateway_error"
	}
	reason := err.Error()
	var gatewayErr *tunnel.GatewayError
	if errors.As(err, &gatewayErr) {
		code = firstNonEmpty(gatewayErr.Code, gatewayErr.Status, code)
		reason = firstNonEmpty(gatewayErr.Message, gatewayErr.Error())
	}
	var codedErr interface{ ErrorCode() string }
	if errors.As(err, &codedErr) {
		code = firstNonEmpty(codedErr.ErrorCode(), code)
	}
	forwarder.accessEventRecorder(ipc.AccessEvent{
		ID:         fmt.Sprintf("%s-%d-%s-%d", source, forwarder.clock().UnixNano(), packet.DestinationIP, packet.DestinationPort),
		Decision:   "deny",
		Reason:     reason,
		Source:     source,
		ResourceID: mapping.ResourceID,
		FQDN:       mapping.FQDN,
		Protocol:   firstNonEmpty(mapping.Protocol, "tcp"),
		Port:       mapping.Port,
		Details:    map[string]string{"code": code, "synthetic_ip": packet.DestinationIP},
		OccurredAt: forwarder.clock().UTC(),
	})
}

func authorizationPort(mapping dnsresolver.Mapping, packet network.Packet) int {
	if mapping.Port > 0 {
		return mapping.Port
	}
	return int(packet.DestinationPort)
}

func applyAuthorization(request tunnel.ResourceStreamRequest, authorization ResourceAuthorizationResult) tunnel.ResourceStreamRequest {
	request.SessionID = strings.TrimSpace(authorization.SessionID)
	request.SessionToken = strings.TrimSpace(authorization.SessionToken)
	if resourceID := strings.TrimSpace(authorization.ResourceID); resourceID != "" {
		request.ResourceID = resourceID
	}
	if protocol := strings.TrimSpace(authorization.Protocol); protocol != "" {
		request.Protocol = protocol
	}
	if authorization.Port > 0 {
		request.TargetPort = authorization.Port
	}
	request.GatewayID = strings.TrimSpace(authorization.GatewayID)
	request.GatewayEndpoint = strings.TrimSpace(authorization.GatewayEndpoint)
	return request
}

func (forwarder *Forwarder) userSID() string {
	if forwarder.userSIDProvider == nil {
		return ""
	}
	return strings.TrimSpace(forwarder.userSIDProvider())
}

func packetFlowKey(packet network.Packet) flowKey {
	return flowKey{sourceIP: packet.SourceIP, sourcePort: packet.SourcePort, destinationIP: packet.DestinationIP, destinationPort: packet.DestinationPort}
}

func (flow *activeFlow) id() string {
	return fmt.Sprintf("%s:%d-%s:%d", flow.key.sourceIP, flow.key.sourcePort, flow.key.destinationIP, flow.key.destinationPort)
}

func (flow *activeFlow) addBytesIn(value int64) {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.bytesIn += value
}

func (flow *activeFlow) addBytesOut(value int64) {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.bytesOut += value
}

func (flow *activeFlow) markError(message string) {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.state = "error"
	flow.lastError = message
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
