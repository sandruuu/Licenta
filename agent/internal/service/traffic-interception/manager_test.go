package trafficinterception

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	wfpcontrol "agent/internal/service/wfp-control"
)

func TestManagerAppliesMappingsToWFP(t *testing.T) {
	wfp := &fakeWFPController{}
	manager, err := NewManager(Config{
		Enabled:            true,
		ProxyListenAddress: "127.0.0.1:0",
		ReadyTimeout:       2 * time.Second,
	}, Dependencies{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		WFP:    wfp,
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	}()

	err = manager.ApplyMappings(context.Background(), []ResourceMapping{{
		ResourceID:  "res-1",
		FQDN:        "app.internal.example",
		Protocol:    "https",
		Port:        443,
		SyntheticIP: "100.64.0.2",
	}})
	if err != nil {
		t.Fatalf("ApplyMappings returned error: %v", err)
	}
	request := wfp.last()
	if request.ProxyAddress != "127.0.0.1" || request.ProxyPort <= 0 || request.ProxyPID == 0 || len(request.Rules) != 1 {
		t.Fatalf("WFP request = %+v", request)
	}
	if request.Rules[0].SyntheticIP != "100.64.0.2" || request.Rules[0].Port != 443 || request.Rules[0].Protocol != "tcp" {
		t.Fatalf("WFP rule = %+v", request.Rules[0])
	}
	status := manager.Status()
	if status.State != StatusReady || status.RuleCount != 1 {
		t.Fatalf("status = %+v", status)
	}
}

func TestRouteTableMapsApplicationProtocolsToTCP(t *testing.T) {
	table, rules, err := newRouteTable([]ResourceMapping{
		{ResourceID: "res-ssh", FQDN: "ssh.internal.example", Protocol: "ssh", Port: 22, SyntheticIP: "100.64.0.2"},
		{ResourceID: "res-rdp", FQDN: "rdp.internal.example", Protocol: "rdp", Port: 3389, SyntheticIP: "100.64.0.3"},
	})
	if err != nil {
		t.Fatalf("newRouteTable returned error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %+v, want 2", rules)
	}
	for _, rule := range rules {
		if rule.Protocol != "tcp" {
			t.Fatalf("rule protocol = %q, want tcp; rule=%+v", rule.Protocol, rule)
		}
	}
	rdpRoute, ok := table.Lookup("100.64.0.3", 3389, "tcp")
	if !ok {
		t.Fatalf("RDP route not found by TCP destination")
	}
	if rdpRoute.Protocol != "rdp" {
		t.Fatalf("RDP route protocol = %q, want rdp", rdpRoute.Protocol)
	}
	sshRoute, ok := table.Lookup("100.64.0.2", 22, "tcp")
	if !ok {
		t.Fatalf("SSH route not found by TCP destination")
	}
	if sshRoute.Protocol != "ssh" {
		t.Fatalf("SSH route protocol = %q, want ssh", sshRoute.Protocol)
	}
}

func TestRouteTableRejectsInvalidSyntheticIP(t *testing.T) {
	_, _, err := newRouteTable([]ResourceMapping{{SyntheticIP: "not-an-ip", Protocol: "tcp", Port: 443}})
	if err == nil {
		t.Fatalf("newRouteTable returned nil error for invalid synthetic IP")
	}
}

func TestProxyPassesWFPProcessIdentityToConnector(t *testing.T) {
	wfp := &fakeWFPController{destination: wfpcontrol.Destination{
		IP:        "100.64.0.2",
		Port:      443,
		Protocol:  "tcp",
		ProcessID: 1234,
	}}
	connector := &fakeProxyStreamConnector{}
	server := newProxyServer(Config{ProxyListenAddress: "127.0.0.1:0"}, slog.New(slog.NewTextHandler(io.Discard, nil)), wfp, connector)
	server.processResolver = func(_ context.Context, pid uint32) (*ProcessIdentity, error) {
		if pid != 1234 {
			t.Fatalf("process resolver pid = %d, want 1234", pid)
		}
		return &ProcessIdentity{PID: int(pid), Name: "browser.exe", SHA256: "hash"}, nil
	}
	table, _, err := newRouteTable([]ResourceMapping{{
		ResourceID:  "res-web",
		FQDN:        "web.internal.example",
		Protocol:    "https",
		Port:        443,
		SyntheticIP: "100.64.0.2",
	}})
	if err != nil {
		t.Fatalf("newRouteTable returned error: %v", err)
	}
	server.SetRoutes(table)

	left, right := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.handle(context.Background(), right)
		close(done)
	}()
	_ = left.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy handle did not finish")
	}
	if connector.request.ResourceID != "res-web" || connector.request.Protocol != "https" {
		t.Fatalf("stream request = %+v", connector.request)
	}
	if connector.request.Process == nil || connector.request.Process.PID != 1234 || connector.request.Process.Name != "browser.exe" || connector.request.Process.SHA256 != "hash" {
		t.Fatalf("stream process = %+v", connector.request.Process)
	}
}

type fakeWFPController struct {
	mu             sync.Mutex
	requests       []wfpcontrol.ApplyRequest
	cleared        int
	destination    wfpcontrol.Destination
	destinationErr error
}

func (controller *fakeWFPController) ApplyRules(_ context.Context, request wfpcontrol.ApplyRequest) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.requests = append(controller.requests, request)
	return nil
}

func (controller *fakeWFPController) Clear(context.Context) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.cleared++
	return nil
}

func (controller *fakeWFPController) ResolveOriginalDestination(context.Context, net.Conn) (wfpcontrol.Destination, error) {
	if controller.destinationErr != nil {
		return wfpcontrol.Destination{}, controller.destinationErr
	}
	return controller.destination, nil
}

func (controller *fakeWFPController) Status() wfpcontrol.Status {
	return wfpcontrol.Status{State: wfpcontrol.StatusReady}
}

func (controller *fakeWFPController) last() wfpcontrol.ApplyRequest {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.requests) == 0 {
		return wfpcontrol.ApplyRequest{}
	}
	return controller.requests[len(controller.requests)-1]
}

type fakeProxyStreamConnector struct {
	request StreamRequest
	err     error
}

func (connector *fakeProxyStreamConnector) OpenResourceStream(_ context.Context, request StreamRequest) (net.Conn, error) {
	connector.request = request
	if connector.err != nil {
		return nil, connector.err
	}
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}
