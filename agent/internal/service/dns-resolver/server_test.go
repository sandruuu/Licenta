package dnsresolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestServerReturnsSyntheticARecordForCatalogResource(t *testing.T) {
	resolver, err := New(Options{})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := resolver.ApplyPolicy(Policy{TTLSeconds: 90, Resources: []Resource{{FQDN: "admin.example.test", ResourceID: "res-1", Protocol: "https", Port: 443}}}); err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	server, done, cancel := startTestServer(t, resolver)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("DNS server returned error: %v", err)
		}
	}()

	udpResponse := exchangeDNS(t, server.LocalAddr(), "udp", "admin.example.test.", dns.TypeA)
	assertSyntheticAnswer(t, udpResponse)

	tcpResponse := exchangeDNS(t, server.LocalAddr(), "tcp", "admin.example.test.", dns.TypeA)
	assertSyntheticAnswer(t, tcpResponse)
}

func TestServerReturnsNXDOMAINForUnknownCatalogResource(t *testing.T) {
	resolver, err := New(Options{})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := resolver.ApplyPolicy(Policy{}); err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	server, done, cancel := startTestServer(t, resolver)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("DNS server returned error: %v", err)
		}
	}()

	response := exchangeDNS(t, server.LocalAddr(), "udp", "unknown.example.test.", dns.TypeA)
	if response.Rcode != dns.RcodeNameError || len(response.Answer) != 0 {
		t.Fatalf("response rcode=%s answers=%+v", dns.RcodeToString[response.Rcode], response.Answer)
	}
}

func startTestServer(t *testing.T, resolver *Resolver) (*Server, <-chan error, context.CancelFunc) {
	t.Helper()
	server, err := NewServer(ServerOptions{ListenAddress: "127.0.0.1:0", Resolver: resolver})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	select {
	case <-server.Ready():
	case err := <-done:
		cancel()
		t.Fatalf("DNS server exited before ready: %v", err)
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatalf("DNS server did not become ready")
	}
	if server.LocalAddr() == "" {
		cancel()
		t.Fatalf("DNS server local address was empty")
	}
	return server, done, cancel
}

func exchangeDNS(t *testing.T, addr, network, name string, queryType uint16) *dns.Msg {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion(name, queryType)
	client := &dns.Client{Net: network, Timeout: 2 * time.Second}
	response, _, err := client.Exchange(request, addr)
	if err != nil {
		t.Fatalf("DNS %s exchange returned error: %v", network, err)
	}
	return response
}

func assertSyntheticAnswer(t *testing.T, response *dns.Msg) {
	t.Helper()
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("response rcode=%s answers=%+v", dns.RcodeToString[response.Rcode], response.Answer)
	}
	record, ok := response.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", response.Answer[0])
	}
	if record.Hdr.Ttl == 0 || record.Hdr.Ttl > 90 {
		t.Fatalf("answer TTL = %d, want 1..90", record.Hdr.Ttl)
	}
	if !mustCIDR(t, DefaultCGNATCIDR).Contains(net.ParseIP(record.A.String())) {
		t.Fatalf("synthetic IP %q is outside CGNAT range", record.A.String())
	}
}
