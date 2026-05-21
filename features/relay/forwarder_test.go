package relay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"licenta/features/contracts"
	"licenta/features/dnsresolver"
	"licenta/features/network"
	"licenta/features/tunnel"
)

func TestForwarderBridgesTUNDataToGatewayStream(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	opener := &fakeStreamOpener{stream: client}
	writer := &captureWriter{packets: make(chan []byte, 4)}
	forwarder, err := NewForwarder(Options{StreamOpener: opener, Clock: func() time.Time { return time.Unix(1000, 0).UTC() }})
	if err != nil {
		t.Fatalf("NewForwarder returned error: %v", err)
	}
	defer forwarder.Close()
	mapping := dnsresolver.Mapping{FQDN: "admin.example.test", ResourceID: "res-1", Protocol: "tcp", Port: 443, SyntheticIP: "100.64.0.42"}
	syn := network.Packet{SourceIP: "10.0.0.25", DestinationIP: "100.64.0.42", SourcePort: 52000, DestinationPort: 443, Sequence: 100, Flags: network.TCPFlagSYN}
	if err := forwarder.HandlePacket(context.Background(), syn, mapping, writer); err != nil {
		t.Fatalf("HandlePacket SYN returned error: %v", err)
	}
	if opener.request.TargetHost != "100.64.0.42" || opener.request.TargetPort != 443 {
		t.Fatalf("target = %s:%d", opener.request.TargetHost, opener.request.TargetPort)
	}
	<-writer.packets

	ack := network.Packet{SourceIP: "10.0.0.25", DestinationIP: "100.64.0.42", SourcePort: 52000, DestinationPort: 443, Sequence: 101, Acknowledgment: 1, Flags: network.TCPFlagACK}
	if err := forwarder.HandlePacket(context.Background(), ack, mapping, writer); err != nil {
		t.Fatalf("HandlePacket ACK returned error: %v", err)
	}
	readResult := make(chan []byte, 1)
	readError := make(chan error, 1)
	go func() {
		buf := make([]byte, 5)
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		_, err := server.Read(buf)
		if err != nil {
			readError <- err
			return
		}
		readResult <- buf
	}()
	data := network.Packet{SourceIP: "10.0.0.25", DestinationIP: "100.64.0.42", SourcePort: 52000, DestinationPort: 443, Sequence: 101, Acknowledgment: 1, Flags: network.TCPFlagPSH | network.TCPFlagACK, Payload: []byte("hello")}
	if err := forwarder.HandlePacket(context.Background(), data, mapping, writer); err != nil {
		t.Fatalf("HandlePacket data returned error: %v", err)
	}
	<-writer.packets
	select {
	case err := <-readError:
		t.Fatalf("read stream payload: %v", err)
	case buf := <-readResult:
		if string(buf) != "hello" {
			t.Fatalf("stream payload = %q", buf)
		}
	case <-time.After(time.Second):
		t.Fatalf("stream payload was not written")
	}
	sessions := forwarder.Sessions()
	if len(sessions) != 1 || sessions[0].ResourceID != "res-1" || sessions[0].BytesIn != 5 || sessions[0].State != "active" {
		t.Fatalf("sessions = %+v", sessions)
	}
}

func TestForwarderAuthorizesSYNBeforeOpeningGatewayStream(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	authorizer := &fakeAuthorizer{result: ResourceAuthorizationResult{SessionID: "sess-1", SessionToken: "session-token", ResourceID: "res-1", Protocol: "ssh", Port: 22, GatewayEndpoint: "gateway.example.test:9443"}}
	opener := &fakeStreamOpener{stream: client}
	writer := &captureWriter{packets: make(chan []byte, 2)}
	forwarder, err := NewForwarder(Options{StreamOpener: opener, Authorizer: authorizer})
	if err != nil {
		t.Fatalf("NewForwarder returned error: %v", err)
	}
	mapping := dnsresolver.Mapping{FQDN: "ssh.example.test", ResourceID: "res-1", Protocol: "ssh", Port: 22, SyntheticIP: "100.64.0.42"}
	syn := network.Packet{SourceIP: "10.0.0.25", DestinationIP: "100.64.0.42", SourcePort: 52000, DestinationPort: 22, Sequence: 100, Flags: network.TCPFlagSYN}
	if err := forwarder.HandlePacket(context.Background(), syn, mapping, writer); err != nil {
		t.Fatalf("HandlePacket SYN returned error: %v", err)
	}
	if !authorizer.called {
		t.Fatalf("authorizer was not called")
	}
	if authorizer.request.ResourceID != "res-1" || authorizer.request.Protocol != "ssh" || authorizer.request.Port != 22 {
		t.Fatalf("authorization request = %+v", authorizer.request)
	}
	if opener.request.SessionID != "sess-1" || opener.request.SessionToken != "session-token" || opener.request.ResourceID != "res-1" || opener.request.Protocol != "ssh" || opener.request.TargetPort != 22 {
		t.Fatalf("stream request = %+v", opener.request)
	}
	<-writer.packets
}

func TestForwarderRecordsAuthorizationDeny(t *testing.T) {
	authorizer := &fakeAuthorizer{err: errors.New("mfa_required: step-up required")}
	opener := &fakeStreamOpener{}
	writer := &captureWriter{packets: make(chan []byte, 2)}
	events := make(chan contracts.AccessEvent, 1)
	forwarder, err := NewForwarder(Options{StreamOpener: opener, Authorizer: authorizer, AccessEventRecorder: func(event contracts.AccessEvent) { events <- event }})
	if err != nil {
		t.Fatalf("NewForwarder returned error: %v", err)
	}
	mapping := dnsresolver.Mapping{FQDN: "ssh.example.test", ResourceID: "res-1", Protocol: "ssh", Port: 22, SyntheticIP: "100.64.0.42"}
	syn := network.Packet{SourceIP: "10.0.0.25", DestinationIP: "100.64.0.42", SourcePort: 52000, DestinationPort: 22, Sequence: 100, Flags: network.TCPFlagSYN}
	if err := forwarder.HandlePacket(context.Background(), syn, mapping, writer); err != nil {
		t.Fatalf("HandlePacket SYN returned error: %v", err)
	}
	<-writer.packets
	if opener.request.TargetHost != "" {
		t.Fatalf("gateway stream was opened despite authorization failure: %+v", opener.request)
	}
	select {
	case event := <-events:
		if event.Source != "policy_administrator" || event.ResourceID != "res-1" || event.Details["code"] != "authorization_failed" {
			t.Fatalf("event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatalf("authorization deny event was not recorded")
	}
}

func TestForwarderRecordsGatewayDeny(t *testing.T) {
	opener := &fakeStreamOpener{err: &tunnel.GatewayError{Code: tunnel.CodePolicyDenied, Message: "blocked"}}
	writer := &captureWriter{packets: make(chan []byte, 2)}
	events := make(chan string, 1)
	forwarder, err := NewForwarder(Options{
		StreamOpener: opener,
		AccessEventRecorder: func(event contracts.AccessEvent) {
			events <- event.Reason
		},
	})
	if err != nil {
		t.Fatalf("NewForwarder returned error: %v", err)
	}
	mapping := dnsresolver.Mapping{FQDN: "admin.example.test", ResourceID: "res-1", Protocol: "tcp", Port: 443, SyntheticIP: "100.64.0.42"}
	syn := network.Packet{SourceIP: "10.0.0.25", DestinationIP: "100.64.0.42", SourcePort: 52000, DestinationPort: 443, Sequence: 100, Flags: network.TCPFlagSYN}
	if err := forwarder.HandlePacket(context.Background(), syn, mapping, writer); err != nil {
		t.Fatalf("HandlePacket SYN returned error: %v", err)
	}
	<-writer.packets
	select {
	case reason := <-events:
		if reason != "blocked" {
			t.Fatalf("reason = %q", reason)
		}
	case <-time.After(time.Second):
		t.Fatalf("access event was not recorded")
	}
}

type fakeStreamOpener struct {
	stream  net.Conn
	err     error
	request tunnel.ResourceStreamRequest
}

func (opener *fakeStreamOpener) OpenResourceStream(_ context.Context, request tunnel.ResourceStreamRequest) (net.Conn, error) {
	opener.request = request
	if opener.err != nil {
		return nil, opener.err
	}
	return opener.stream, nil
}

type fakeAuthorizer struct {
	called  bool
	request ResourceAuthorizationRequest
	result  ResourceAuthorizationResult
	err     error
}

func (authorizer *fakeAuthorizer) AuthorizeResource(_ context.Context, request ResourceAuthorizationRequest) (ResourceAuthorizationResult, error) {
	authorizer.called = true
	authorizer.request = request
	if authorizer.err != nil {
		return ResourceAuthorizationResult{}, authorizer.err
	}
	return authorizer.result, nil
}

type captureWriter struct {
	packets chan []byte
}

func (writer *captureWriter) WritePacket(packet []byte) error {
	writer.packets <- append([]byte(nil), packet...)
	return nil
}
