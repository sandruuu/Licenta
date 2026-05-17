package network

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent/internal/service/dnsresolver"
	"agent/internal/service/routing"
	"agent/internal/service/tun"
)

func TestManagerStartsRoutesAndCleansUp(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	device := &fakeDevice{closed: make(chan struct{})}
	routes := &fakeRoutes{closed: make(chan struct{})}
	deviceConfig := make(chan tun.Config, 1)
	routeConfig := make(chan routing.Config, 1)
	manager, err := NewManager(Options{
		Enabled:      true,
		TUNName:      "ZTNA-Test",
		TUNIP:        "100.64.0.9",
		TUNNetmask:   "255.192.0.0",
		TUNDNSServer: "127.0.0.1",
		CGNATCIDR:    "100.64.0.0/10",
		Clock:        func() time.Time { return now },
		DeviceFactory: func(config tun.Config) (tun.Device, error) {
			deviceConfig <- config
			return device, nil
		},
		RouteFactory: func(ctx context.Context, config routing.Config) (routing.RouteSet, error) {
			routeConfig <- config
			return routes, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	select {
	case config := <-deviceConfig:
		if config.Name != "ZTNA-Test" || config.Address != "100.64.0.9" {
			t.Fatalf("device config = %+v", config)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatalf("device was not opened")
	}
	select {
	case config := <-routeConfig:
		if config.InterfaceIP != "100.64.0.9" || config.DestinationCIDR != "100.64.0.0/10" {
			t.Fatalf("route config = %+v", config)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatalf("route was not applied")
	}
	if status := manager.Status(); status.State != StatusReady || status.TUNName != "ZTNA-Test" || status.CGNATRange != "100.64.0.0/10" {
		t.Fatalf("status = %+v", status)
	}
	cancel()
	select {
	case <-routes.closed:
	case <-time.After(time.Second):
		t.Fatalf("routes were not closed")
	}
	select {
	case <-device.closed:
	case <-time.After(time.Second):
		t.Fatalf("device was not closed")
	}
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestNormalizeOptionsRejectsInvalidTUN(t *testing.T) {
	if _, err := NormalizeOptions(Options{Enabled: true, TUNIP: "not-ip"}); err == nil {
		t.Fatalf("NormalizeOptions accepted invalid TUN IP")
	}
}

func TestManagerClassifiesTUNPacketsWithResolver(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	device := &fakeDevice{packets: make(chan []byte, 1), closed: make(chan struct{})}
	handler := &fakePacketHandler{seen: make(chan handledPacket, 1)}
	manager, err := NewManager(Options{
		Enabled:      true,
		TUNIP:        "100.64.0.9",
		TUNNetmask:   "255.192.0.0",
		TUNDNSServer: "127.0.0.1",
		CGNATCIDR:    "100.64.0.0/10",
		Clock:        func() time.Time { return now },
		Resolver: fakeResolver{mapping: dnsresolver.Mapping{
			FQDN:        "admin.example.test",
			ResourceID:  "res-1",
			Protocol:    "tcp",
			Port:        443,
			SyntheticIP: "100.64.0.42",
		}},
		PacketHandler: handler,
		DeviceFactory: func(config tun.Config) (tun.Device, error) {
			return device, nil
		},
		RouteFactory: func(ctx context.Context, config routing.Config) (routing.RouteSet, error) {
			return &fakeRoutes{closed: make(chan struct{})}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	device.packets <- testTCPPacket("10.0.0.25", "100.64.0.42", 52000, 443, TCPFlagSYN, nil)
	select {
	case got := <-handler.seen:
		if got.packet.DestinationIP != "100.64.0.42" || got.packet.DestinationPort != 443 || got.mapping.ResourceID != "res-1" {
			t.Fatalf("handled packet = %+v mapping=%+v", got.packet, got.mapping)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatalf("packet was not classified")
	}
	status := manager.Status()
	if status.PacketsRead != 1 || status.TCPPackets != 1 || status.MatchedPackets != 1 || status.DroppedPackets != 0 || !status.ForwarderConfigured {
		t.Fatalf("status = %+v", status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

type fakeDevice struct {
	packets chan []byte
	writes  chan []byte
	closed  chan struct{}
	once    sync.Once
}

func (device *fakeDevice) ReadPacket() ([]byte, error) {
	if device.packets == nil {
		<-device.closed
		return nil, errors.New("TUN device is closed")
	}
	select {
	case packet := <-device.packets:
		return packet, nil
	case <-device.closed:
		return nil, errors.New("TUN device is closed")
	}
}

func (device *fakeDevice) WritePacket(packet []byte) error {
	if device.writes != nil {
		device.writes <- append([]byte(nil), packet...)
	}
	return nil
}
func (device *fakeDevice) Close() error {
	device.once.Do(func() { close(device.closed) })
	return nil
}

type fakeRoutes struct {
	closed chan struct{}
}

func (routes *fakeRoutes) Close() error {
	close(routes.closed)
	return nil
}

type fakeResolver struct {
	mapping dnsresolver.Mapping
}

func (resolver fakeResolver) Lookup(ip string) (dnsresolver.Mapping, bool) {
	return resolver.mapping, ip == resolver.mapping.SyntheticIP
}

type handledPacket struct {
	packet  Packet
	mapping dnsresolver.Mapping
}

type fakePacketHandler struct {
	seen chan handledPacket
}

func (handler *fakePacketHandler) HandlePacket(_ context.Context, packet Packet, mapping dnsresolver.Mapping, _ PacketWriter) error {
	handler.seen <- handledPacket{packet: packet, mapping: mapping}
	return nil
}
