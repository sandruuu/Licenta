package network

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"ztna.local/agent/internal/dnsresolver"
	"ztna.local/agent/internal/routing"
	"ztna.local/agent/internal/tun"
)

const (
	StatusDisabled = "disabled"
	StatusStarting = "starting"
	StatusReady    = "ready"
	StatusError    = "error"
	StatusStopped  = "stopped"
)

type Options struct {
	Enabled       bool
	TUNName       string
	TUNIP         string
	TUNNetmask    string
	TUNDNSServer  string
	CGNATCIDR     string
	Clock         func() time.Time
	Resolver      ResourceResolver
	PacketHandler PacketHandler
	DeviceFactory func(tun.Config) (tun.Device, error)
	RouteFactory  func(context.Context, routing.Config) (routing.RouteSet, error)
}

type ResourceResolver interface {
	Lookup(string) (dnsresolver.Mapping, bool)
}

type PacketHandler interface {
	HandlePacket(context.Context, Packet, dnsresolver.Mapping, PacketWriter) error
}

type PacketWriter interface {
	WritePacket([]byte) error
}

type Status struct {
	State               string
	TUNName             string
	TUNIP               string
	TUNNetmask          string
	CGNATRange          string
	StartedAt           time.Time
	UpdatedAt           time.Time
	PacketsRead         int64
	TCPPackets          int64
	MatchedPackets      int64
	UnmatchedPackets    int64
	DroppedPackets      int64
	ForwarderConfigured bool
	LastPacketAt        time.Time
	LastPacketError     string
	LastError           string
}

type Manager struct {
	mu            sync.RWMutex
	options       Options
	status        Status
	clock         func() time.Time
	device        tun.Device
	routes        routing.RouteSet
	resolver      ResourceResolver
	packetHandler PacketHandler
	deviceFactory func(tun.Config) (tun.Device, error)
	routeFactory  func(context.Context, routing.Config) (routing.RouteSet, error)
}

func NewManager(options Options) (*Manager, error) {
	normalized, err := NormalizeOptions(options)
	if err != nil {
		return nil, err
	}
	clock := normalized.Clock
	if clock == nil {
		clock = time.Now
	}
	deviceFactory := normalized.DeviceFactory
	if deviceFactory == nil {
		deviceFactory = tun.Open
	}
	routeFactory := normalized.RouteFactory
	if routeFactory == nil {
		routeFactory = routing.Apply
	}
	manager := &Manager{
		options:       normalized,
		clock:         clock,
		resolver:      normalized.Resolver,
		packetHandler: normalized.PacketHandler,
		deviceFactory: deviceFactory,
		routeFactory:  routeFactory,
		status: Status{
			State:               StatusDisabled,
			TUNName:             normalized.TUNName,
			TUNIP:               normalized.TUNIP,
			TUNNetmask:          normalized.TUNNetmask,
			CGNATRange:          normalized.CGNATCIDR,
			ForwarderConfigured: normalized.PacketHandler != nil,
			UpdatedAt:           clock().UTC(),
		},
	}
	return manager, nil
}

func NormalizeOptions(options Options) (Options, error) {
	if !options.Enabled {
		return options, nil
	}
	tunConfig, err := tun.NormalizeConfig(tun.Config{Name: options.TUNName, Address: options.TUNIP, Netmask: options.TUNNetmask, DNSServer: options.TUNDNSServer})
	if err != nil {
		return Options{}, err
	}
	options.TUNName = tunConfig.Name
	options.TUNIP = tunConfig.Address
	options.TUNNetmask = tunConfig.Netmask
	options.TUNDNSServer = tunConfig.DNSServer
	routingConfig, err := routing.NormalizeConfig(routing.Config{DestinationCIDR: options.CGNATCIDR, InterfaceIP: options.TUNIP})
	if err != nil {
		return Options{}, err
	}
	options.CGNATCIDR = routingConfig.DestinationCIDR
	return options, nil
}

func (manager *Manager) Run(ctx context.Context) error {
	if manager == nil {
		return errors.New("network manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !manager.options.Enabled {
		manager.setStatus(Status{State: StatusDisabled})
		<-ctx.Done()
		return nil
	}
	manager.setStatus(Status{State: StatusStarting})
	device, err := manager.deviceFactory(tun.Config{Name: manager.options.TUNName, Address: manager.options.TUNIP, Netmask: manager.options.TUNNetmask, DNSServer: manager.options.TUNDNSServer})
	if err != nil {
		manager.setStatus(Status{State: StatusError, LastError: err.Error()})
		return err
	}
	manager.mu.Lock()
	manager.device = device
	manager.mu.Unlock()
	routes, err := manager.routeFactory(ctx, routing.Config{DestinationCIDR: manager.options.CGNATCIDR, InterfaceIP: manager.options.TUNIP})
	if err != nil {
		_ = device.Close()
		manager.setStatus(Status{State: StatusError, LastError: err.Error()})
		return err
	}
	manager.mu.Lock()
	manager.routes = routes
	manager.mu.Unlock()
	manager.setStatus(Status{State: StatusReady, StartedAt: manager.clock().UTC()})
	loopDone := make(chan error, 1)
	go func() { loopDone <- manager.packetLoop(ctx, device) }()

	select {
	case <-ctx.Done():
	case err := <-loopDone:
		cleanupErr := manager.closeResources()
		if err != nil && ctx.Err() == nil {
			manager.setStatus(Status{State: StatusError, LastError: err.Error()})
			return errors.Join(err, cleanupErr)
		}
		if cleanupErr != nil {
			manager.setStatus(Status{State: StatusError, LastError: cleanupErr.Error()})
			return cleanupErr
		}
		manager.setStatus(Status{State: StatusStopped})
		return nil
	}
	cleanupErr := manager.closeResources()
	select {
	case err := <-loopDone:
		if cleanupErr == nil && err != nil && ctx.Err() == nil {
			cleanupErr = err
		}
	case <-time.After(2 * time.Second):
		if cleanupErr == nil {
			cleanupErr = errors.New("TUN packet loop did not stop after device close")
		}
	}
	if cleanupErr != nil {
		manager.setStatus(Status{State: StatusError, LastError: cleanupErr.Error()})
		return cleanupErr
	}
	manager.setStatus(Status{State: StatusStopped})
	return nil
}

func (manager *Manager) Status() Status {
	if manager == nil {
		return Status{State: StatusDisabled}
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.status
}

func (manager *Manager) setStatus(update Status) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	current := manager.status
	if strings.TrimSpace(update.State) != "" {
		current.State = update.State
	}
	if !update.StartedAt.IsZero() {
		current.StartedAt = update.StartedAt
	}
	current.UpdatedAt = manager.clock().UTC()
	current.LastError = update.LastError
	manager.status = current
}

func (manager *Manager) closeResources() error {
	manager.mu.Lock()
	routes := manager.routes
	device := manager.device
	manager.routes = nil
	manager.device = nil
	manager.mu.Unlock()
	var errs []error
	if routes != nil {
		if err := routes.Close(); err != nil {
			errs = append(errs, fmt.Errorf("remove TUN routes: %w", err))
		}
	}
	if device != nil {
		if err := device.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close TUN device: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (manager *Manager) packetLoop(ctx context.Context, device tun.Device) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		packetBytes, err := device.ReadPacket()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			manager.recordPacketError(err.Error())
			return err
		}
		if len(packetBytes) == 0 {
			continue
		}
		manager.recordPacketRead()
		packet, err := ParseIPv4TCPPacket(packetBytes)
		if err != nil {
			manager.recordPacketDrop(err.Error())
			continue
		}
		manager.recordTCPPacket()
		mapping, ok := manager.lookup(packet.DestinationIP)
		if !ok || !portMatches(packet, mapping) {
			manager.recordUnmatchedPacket()
			continue
		}
		manager.recordMatchedPacket()
		if manager.packetHandler == nil {
			manager.recordForwardingPending()
			continue
		}
		if err := manager.packetHandler.HandlePacket(ctx, packet, mapping, device); err != nil {
			manager.recordPacketDrop(err.Error())
			continue
		}
	}
}

func (manager *Manager) lookup(destinationIP string) (dnsresolver.Mapping, bool) {
	if manager.resolver == nil {
		return dnsresolver.Mapping{}, false
	}
	return manager.resolver.Lookup(destinationIP)
}

func portMatches(packet Packet, mapping dnsresolver.Mapping) bool {
	return mapping.Port <= 0 || int(packet.DestinationPort) == mapping.Port
}

func (manager *Manager) recordPacketRead() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.PacketsRead++
	manager.status.LastPacketAt = manager.clock().UTC()
	manager.status.UpdatedAt = manager.status.LastPacketAt
}

func (manager *Manager) recordTCPPacket() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.TCPPackets++
}

func (manager *Manager) recordMatchedPacket() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.MatchedPackets++
	manager.status.LastPacketError = ""
}

func (manager *Manager) recordUnmatchedPacket() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.UnmatchedPackets++
	manager.status.DroppedPackets++
}

func (manager *Manager) recordForwardingPending() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.DroppedPackets++
}

func (manager *Manager) recordPacketDrop(reason string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.DroppedPackets++
	manager.status.LastPacketError = strings.TrimSpace(reason)
}

func (manager *Manager) recordPacketError(reason string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.LastPacketError = strings.TrimSpace(reason)
}
