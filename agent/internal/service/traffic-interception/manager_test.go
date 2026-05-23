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

func TestRouteTableRejectsInvalidSyntheticIP(t *testing.T) {
	_, _, err := newRouteTable([]ResourceMapping{{SyntheticIP: "not-an-ip", Protocol: "tcp", Port: 443}})
	if err == nil {
		t.Fatalf("newRouteTable returned nil error for invalid synthetic IP")
	}
}

type fakeWFPController struct {
	mu       sync.Mutex
	requests []wfpcontrol.ApplyRequest
	cleared  int
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
	return wfpcontrol.Destination{}, nil
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
