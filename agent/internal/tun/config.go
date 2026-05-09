package tun

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	DefaultName         = "ZTNA-TUN"
	DefaultAddress      = "100.64.0.1"
	DefaultNetmask      = "255.192.0.0"
	DefaultDNSServer    = "127.0.0.1"
	DefaultRingCapacity = 0x800000
)

type Config struct {
	Name      string
	Address   string
	Netmask   string
	DNSServer string
}

type Device interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	Close() error
}

func NormalizeConfig(config Config) (Config, error) {
	config.Name = strings.TrimSpace(config.Name)
	if config.Name == "" {
		config.Name = DefaultName
	}
	address, err := normalizeIPv4(config.Address, "TUN address")
	if err != nil {
		return Config{}, err
	}
	config.Address = address
	netmask, err := normalizeIPv4(config.Netmask, "TUN netmask")
	if err != nil {
		return Config{}, err
	}
	mask := net.IPMask(net.ParseIP(netmask).To4())
	if ones, bits := mask.Size(); bits != 32 || ones <= 0 {
		return Config{}, fmt.Errorf("TUN netmask %q is not a contiguous IPv4 mask", netmask)
	}
	config.Netmask = netmask
	dnsServer, err := normalizeIPv4(config.DNSServer, "TUN DNS server")
	if err != nil {
		return Config{}, err
	}
	config.DNSServer = dnsServer
	return config, nil
}

func normalizeIPv4(value, name string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		switch name {
		case "TUN address":
			value = DefaultAddress
		case "TUN netmask":
			value = DefaultNetmask
		case "TUN DNS server":
			value = DefaultDNSServer
		default:
			return "", errors.New("IPv4 value is required")
		}
	}
	parsed := net.ParseIP(value).To4()
	if parsed == nil {
		return "", fmt.Errorf("%s must be an IPv4 address", name)
	}
	return net.IP(parsed).String(), nil
}
