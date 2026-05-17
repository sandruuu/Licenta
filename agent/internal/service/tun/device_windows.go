//go:build windows

package tun

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

type NetworkDevice struct {
	adapter *wintun.Adapter
	session wintun.Session
	config  Config
	mu      sync.Mutex
	closed  bool
}

func Open(config Config) (Device, error) {
	normalized, err := NormalizeConfig(config)
	if err != nil {
		return nil, err
	}
	adapter, err := wintun.CreateAdapter(normalized.Name, "Wintun", nil)
	if err != nil {
		existing, openErr := wintun.OpenAdapter(normalized.Name)
		if openErr != nil {
			return nil, fmt.Errorf("create TUN adapter %q: %w", normalized.Name, err)
		}
		adapter = existing
	}
	session, err := adapter.StartSession(DefaultRingCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start TUN session: %w", err)
	}
	device := &NetworkDevice{adapter: adapter, session: session, config: normalized}
	if err := device.configureInterface(); err != nil {
		_ = device.Close()
		return nil, err
	}
	return device, nil
}

func (device *NetworkDevice) configureInterface() error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", device.config.Name),
		"source=static",
		fmt.Sprintf("addr=%s", device.config.Address),
		fmt.Sprintf("mask=%s", device.config.Netmask),
		"gateway=none",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("configure TUN address: %s: %w", string(output), err)
	}
	dnsCmd := exec.Command("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf("name=%s", device.config.Name),
		"source=static",
		fmt.Sprintf("addr=%s", device.config.DNSServer),
		"validate=no",
	)
	if output, err := dnsCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("configure TUN DNS: %s: %w", string(output), err)
	}
	return nil
}

func (device *NetworkDevice) ReadPacket() ([]byte, error) {
	for {
		device.mu.Lock()
		closed := device.closed
		device.mu.Unlock()
		if closed {
			return nil, errors.New("TUN device is closed")
		}
		packet, err := device.session.ReceivePacket()
		if err == nil {
			buf := make([]byte, len(packet))
			copy(buf, packet)
			device.session.ReleaseReceivePacket(packet)
			return buf, nil
		}
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			waitEvent := device.session.ReadWaitEvent()
			if waitEvent == 0 {
				continue
			}
			status, waitErr := windows.WaitForSingleObject(waitEvent, windows.INFINITE)
			if waitErr != nil {
				return nil, fmt.Errorf("wait for TUN packet: %w", waitErr)
			}
			if status == windows.WAIT_OBJECT_0 {
				continue
			}
			if status == windows.WAIT_FAILED {
				return nil, errors.New("wait for TUN packet failed")
			}
			continue
		}
		if errors.Is(err, windows.ERROR_HANDLE_EOF) || errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			return nil, errors.New("TUN device is closed")
		}
		return nil, fmt.Errorf("read TUN packet: %w", err)
	}
}

func (device *NetworkDevice) WritePacket(packet []byte) error {
	device.mu.Lock()
	closed := device.closed
	device.mu.Unlock()
	if closed {
		return errors.New("TUN device is closed")
	}
	buf, err := device.session.AllocateSendPacket(len(packet))
	if err != nil {
		return fmt.Errorf("allocate TUN send packet: %w", err)
	}
	copy(buf, packet)
	device.session.SendPacket(buf)
	return nil
}

func (device *NetworkDevice) Close() error {
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.closed {
		return nil
	}
	device.closed = true
	device.session.End()
	device.adapter.Close()
	return nil
}
