package tun

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	RingCapacity = 0x800000 // 8 MB
)

type NetworkDevice struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
	tunIP   string
	netmask string
	mu      sync.Mutex
	closed  bool
}

func New(name, tunIP, netmask string) (*NetworkDevice, error) {
	adapter, err := wintun.CreateAdapter(name, "Wintun", nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create TUN adapter: %w", err)
	}

	session, err := adapter.StartSession(RingCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("Failed to start TUN session: %w", err)
	}

	dev := &NetworkDevice{
		adapter: adapter,
		session: session,
		name:    name,
		tunIP:   tunIP,
		netmask: netmask,
	}

	if err := dev.configureInterface(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("Failed to configure interface: %w", err)
	}

	log.Printf("TUN Interface '%s' created with IP %s/%s", name, tunIP, netmask)
	return dev, nil
}

func (d *NetworkDevice) configureInterface() error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", d.name),
		"source=static",
		fmt.Sprintf("addr=%s", d.tunIP),
		fmt.Sprintf("mask=%s", d.netmask),
		"gateway=none",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Netsh set address failed: %s — %w", string(output), err)
	}

	// Set DNS on the TUN interface to 127.0.0.1 so Windows sends
	// queries for internal domains through the Magic DNS resolver.
	dnsCmd := exec.Command("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf("name=%s", d.name),
		"source=static",
		"addr=127.0.0.1",
		"validate=no",
	)
	dnsOutput, dnsErr := dnsCmd.CombinedOutput()
	if dnsErr != nil {
		log.Printf("Warning: failed to set DNS on TUN: %s — %v", string(dnsOutput), dnsErr)
	} else {
		log.Printf("DNS set to 127.0.0.1 on interface '%s'", d.name)
	}

	return nil
}

func (d *NetworkDevice) ReadPacket() ([]byte, error) {
	for {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return nil, fmt.Errorf("Device closed")
		}
		d.mu.Unlock()

		packet, err := d.session.ReceivePacket()
		if err == nil {
			buf := make([]byte, len(packet))
			copy(buf, packet)
			d.session.ReleaseReceivePacket(packet)
			return buf, nil
		}

		// Wintun signals an empty RX queue with ERROR_NO_MORE_ITEMS.
		// Wait for the read event and continue instead of aborting the loop.
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			waitEvent := d.session.ReadWaitEvent()
			if waitEvent == 0 {
				continue
			}

			waitStatus, waitErr := windows.WaitForSingleObject(waitEvent, windows.INFINITE)
			if waitErr != nil {
				return nil, fmt.Errorf("Wait for packet failed: %w", waitErr)
			}
			if waitStatus == windows.WAIT_OBJECT_0 {
				continue
			}
			if waitStatus == windows.WAIT_FAILED {
				return nil, fmt.Errorf("Wait for packet failed: WAIT_FAILED")
			}
			continue
		}

		if errors.Is(err, windows.ERROR_HANDLE_EOF) || errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			return nil, fmt.Errorf("Device closed")
		}

		return nil, fmt.Errorf("Read packet: %w", err)
	}
}

func (d *NetworkDevice) WritePacket(packet []byte) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return fmt.Errorf("Device closed")
	}
	d.mu.Unlock()

	buf, err := d.session.AllocateSendPacket(len(packet))
	if err != nil {
		return fmt.Errorf("Allocate send packet: %w", err)
	}

	copy(buf, packet)
	d.session.SendPacket(buf)

	return nil
}

func (d *NetworkDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}
	d.closed = true

	d.session.End()
	d.adapter.Close()
	log.Printf("TUN interface '%s' closed", d.name)
	return nil
}
