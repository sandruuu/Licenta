package protectedresources

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	dnscontrol "agent/internal/service/dns-control"
	dnsresolver "agent/internal/service/dns-resolver"
	trafficinterception "agent/internal/service/traffic-interception"
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
		Version: "cat-1",
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

func TestManagerAppliesCatalogAfterUnknownDNSLookup(t *testing.T) {
	nrpt := &fakeDNSControl{}
	manager, err := NewManager(Config{
		DNSListenAddress: "127.0.0.1:0",
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

	response := exchangeDNS(t, manager.LocalDNSAddress(), "missing.internal.example.")
	if response.Rcode != dns.RcodeNameError {
		t.Fatalf("DNS response rcode=%s, want NXDOMAIN", dns.RcodeToString[response.Rcode])
	}
	if status := manager.Status(); status.LastError == "" {
		t.Fatalf("manager status did not retain resolver error after unknown lookup: %+v", status)
	}

	if err := manager.ApplyCatalog(context.Background(), ipc.CatalogInfo{
		Version: "cat-after-miss",
		Resources: []ipc.CatalogResource{{
			ResourceID: "res-1",
			FQDN:       "app.internal.example",
			Protocol:   "https",
			Port:       443,
		}},
		TTLSeconds: 60,
	}); err != nil {
		t.Fatalf("ApplyCatalog returned error after stale resolver error: %v", err)
	}
	if applied := nrpt.last(); len(applied.DNSNames) != 1 || applied.DNSNames[0] != "app.internal.example" {
		t.Fatalf("NRPT config = %+v", applied)
	}
}

func TestManagerClearsStaleRulesOnRun(t *testing.T) {
	nrpt := &fakeDNSControl{}
	traffic := &fakeTrafficInterceptor{}
	manager, err := NewManager(Config{
		DNSListenAddress:           "127.0.0.1:0",
		TrafficInterceptionEnabled: true,
		TrafficProxyListenAddress:  "127.0.0.1:0",
	}, Dependencies{
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		DNSControl:         nrpt,
		TrafficInterceptor: traffic,
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	waitForManagerDNS(t, manager)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	applied := nrpt.first()
	if len(applied.DNSNames) != 0 || applied.DNSServer != "" {
		t.Fatalf("startup clear NRPT config = %+v", applied)
	}
	if traffic.clearCount() == 0 {
		t.Fatalf("traffic interceptor was not cleared on startup")
	}
}

func TestManagerClearAttemptsNRPTEvenWhenTrafficClearFails(t *testing.T) {
	nrpt := &fakeDNSControl{}
	traffic := &fakeTrafficInterceptor{clearErr: errors.New("driver unavailable")}
	manager, err := NewManager(Config{
		DNSListenAddress:           "127.0.0.1:0",
		TrafficInterceptionEnabled: true,
	}, Dependencies{
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		DNSControl:         nrpt,
		TrafficInterceptor: traffic,
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	if err := manager.Clear(context.Background()); err == nil {
		t.Fatalf("Clear returned nil, want traffic clear error")
	}
	applied := nrpt.last()
	if len(applied.DNSNames) != 0 || applied.DNSServer != "" {
		t.Fatalf("NRPT clear was not attempted after traffic error: %+v", applied)
	}
}

func TestManagerAppliesTrafficInterceptionMappingsWhenEnabled(t *testing.T) {
	nrpt := &fakeDNSControl{}
	traffic := &fakeTrafficInterceptor{}
	manager, err := NewManager(Config{
		DNSListenAddress:           "127.0.0.1:0",
		TrafficInterceptionEnabled: true,
		TrafficProxyListenAddress:  "127.0.0.1:18787",
		SyntheticIPCIDR:            dnsresolver.DefaultCGNATCIDR,
		ReadyTimeout:               2 * time.Second,
	}, Dependencies{
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		DNSControl:         nrpt,
		TrafficInterceptor: traffic,
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

	if err := manager.ApplyCatalog(context.Background(), ipc.CatalogInfo{
		Version: "cat-traffic",
		Resources: []ipc.CatalogResource{{
			ResourceID: "res-1",
			FQDN:       "app.internal.example",
			Protocol:   "tcp",
			Port:       443,
		}},
		TTLSeconds: 60,
	}); err != nil {
		t.Fatalf("ApplyCatalog returned error: %v", err)
	}
	mappings := traffic.last()
	if len(mappings) != 1 {
		t.Fatalf("traffic mappings = %+v, want one mapping", mappings)
	}
	if mappings[0].ResourceID != "res-1" || mappings[0].FQDN != "app.internal.example" || mappings[0].Port != 443 {
		t.Fatalf("traffic mapping = %+v", mappings[0])
	}
	if net.ParseIP(mappings[0].SyntheticIP) == nil {
		t.Fatalf("traffic mapping synthetic IP is invalid: %+v", mappings[0])
	}
}

type fakeDNSControl struct {
	mu      sync.Mutex
	applied []dnscontrol.Config
}

type fakeTrafficInterceptor struct {
	mu       sync.Mutex
	applied  [][]trafficinterception.ResourceMapping
	cleared  int
	runCount int
	clearErr error
}

func (interceptor *fakeTrafficInterceptor) Run(ctx context.Context) error {
	interceptor.mu.Lock()
	interceptor.runCount++
	interceptor.mu.Unlock()
	<-ctx.Done()
	return nil
}

func (interceptor *fakeTrafficInterceptor) ApplyMappings(_ context.Context, mappings []trafficinterception.ResourceMapping) error {
	interceptor.mu.Lock()
	defer interceptor.mu.Unlock()
	copyValue := append([]trafficinterception.ResourceMapping(nil), mappings...)
	interceptor.applied = append(interceptor.applied, copyValue)
	return nil
}

func (interceptor *fakeTrafficInterceptor) Clear(context.Context) error {
	interceptor.mu.Lock()
	defer interceptor.mu.Unlock()
	interceptor.cleared++
	return interceptor.clearErr
}

func (interceptor *fakeTrafficInterceptor) Status() trafficinterception.Status {
	return trafficinterception.Status{State: trafficinterception.StatusReady}
}

func (interceptor *fakeTrafficInterceptor) last() []trafficinterception.ResourceMapping {
	interceptor.mu.Lock()
	defer interceptor.mu.Unlock()
	if len(interceptor.applied) == 0 {
		return nil
	}
	return append([]trafficinterception.ResourceMapping(nil), interceptor.applied[len(interceptor.applied)-1]...)
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

func (control *fakeDNSControl) first() dnscontrol.Config {
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.applied) == 0 {
		return dnscontrol.Config{}
	}
	return control.applied[0]
}

func (interceptor *fakeTrafficInterceptor) clearCount() int {
	interceptor.mu.Lock()
	defer interceptor.mu.Unlock()
	return interceptor.cleared
}

func waitForManagerDNS(t *testing.T, manager *Manager) {
	t.Helper()
	select {
	case <-time.After(2 * time.Second):
		t.Fatalf("local DNS resolver did not become ready")
	case <-manager.server.Ready():
	}
	if manager.LocalDNSAddress() == "" {
		t.Fatalf("local DNS resolver did not publish an address; status=%+v", manager.Status())
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
