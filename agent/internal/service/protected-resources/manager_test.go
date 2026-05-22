package protectedresources

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	dnscontrol "agent/internal/service/dns-control"
	dnsresolver "agent/internal/service/dns-resolver"
	"agent/internal/shared/ipc"

	"github.com/miekg/dns"
)

func TestManagerAppliesCatalogToResolverAndNRPT(t *testing.T) {
	nrpt := &fakeDNSControl{}
	manager, err := NewManager(Config{
		DNSListenAddress: "127.0.0.1:0",
		SyntheticIPCIDR:  dnsresolver.DefaultCGNATCIDR,
		ReadyTimeout:     2 * time.Second,
	}, Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DNSControl: nrpt,
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	waitForManagerDNS(t, manager)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	}()

	catalog := ipc.CatalogInfo{
		Version:     "cat-1",
		DNSSuffixes: []string{"Internal.Example"},
		Resources: []ipc.CatalogResource{{
			ResourceID: "res-1",
			FQDN:       "app.internal.example",
			Protocol:   "https",
			Port:       443,
		}},
		TTLSeconds:  60,
		PolicyEpoch: "epoch-1",
	}
	if err := manager.ApplyCatalog(context.Background(), catalog); err != nil {
		t.Fatalf("ApplyCatalog returned error: %v", err)
	}

	applied := nrpt.last()
	if applied.DNSServer != "127.0.0.1" || len(applied.DNSNames) != 1 || applied.DNSNames[0] != "app.internal.example" {
		t.Fatalf("NRPT config = %+v", applied)
	}

	response := exchangeDNS(t, manager.LocalDNSAddress(), "app.internal.example.")
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("DNS response rcode=%s answers=%+v", dns.RcodeToString[response.Rcode], response.Answer)
	}
	record, ok := response.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("DNS answer type = %T", response.Answer[0])
	}
	if !mustCIDR(t, dnsresolver.DefaultCGNATCIDR).Contains(record.A) {
		t.Fatalf("synthetic IP %q is outside %s", record.A.String(), dnsresolver.DefaultCGNATCIDR)
	}
}

func TestManagerClearsCatalogAndNRPT(t *testing.T) {
	nrpt := &fakeDNSControl{}
	manager, err := NewManager(Config{DNSListenAddress: "127.0.0.1:0"}, Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DNSControl: nrpt,
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if err := manager.Clear(context.Background()); err != nil {
		t.Fatalf("Clear returned error: %v", err)
	}
	applied := nrpt.last()
	if len(applied.DNSNames) != 0 || applied.DNSServer != "" {
		t.Fatalf("clear NRPT config = %+v", applied)
	}
}

func TestManagerDoesNotCreateNRPTFromSuffixesOnly(t *testing.T) {
	nrpt := &fakeDNSControl{}
	manager, err := NewManager(Config{DNSListenAddress: "127.0.0.1:0"}, Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DNSControl: nrpt,
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if err := manager.ApplyCatalog(context.Background(), ipc.CatalogInfo{
		Version:     "cat-empty",
		DNSSuffixes: []string{"internal.example"},
	}); err != nil {
		t.Fatalf("ApplyCatalog returned error: %v", err)
	}
	applied := nrpt.last()
	if len(applied.DNSNames) != 0 {
		t.Fatalf("NRPT config = %+v, want no rules from suffix-only catalog", applied)
	}
}

type fakeDNSControl struct {
	mu      sync.Mutex
	applied []dnscontrol.Config
}

func (control *fakeDNSControl) Apply(_ context.Context, config dnscontrol.Config) error {
	control.mu.Lock()
	defer control.mu.Unlock()
	control.applied = append(control.applied, config)
	return nil
}

func (control *fakeDNSControl) last() dnscontrol.Config {
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.applied) == 0 {
		return dnscontrol.Config{}
	}
	return control.applied[len(control.applied)-1]
}

func waitForManagerDNS(t *testing.T, manager *Manager) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatalf("local DNS resolver did not publish an address")
		case <-ticker.C:
			if manager.LocalDNSAddress() != "" {
				return
			}
		}
	}
}

func exchangeDNS(t *testing.T, addr, name string) *dns.Msg {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion(name, dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	response, _, err := client.Exchange(request, addr)
	if err != nil {
		t.Fatalf("DNS exchange returned error: %v", err)
	}
	return response
}

func mustCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatalf("ParseCIDR returned error: %v", err)
	}
	return network
}
