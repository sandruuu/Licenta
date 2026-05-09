package routing

import (
	"fmt"
	"net"
	"strings"
)

const (
	DefaultCGNATCIDR = "100.64.0.0/10"
	DefaultMetric    = 5
)

type Config struct {
	DestinationCIDR string
	InterfaceIP     string
	Metric          int
}

type RouteSet interface {
	Close() error
}

type Route struct {
	Destination string
	Mask        string
	Gateway     string
	InterfaceIP string
	Metric      int
}

type Table struct {
	routes []Route
}

func NormalizeConfig(config Config) (Config, error) {
	config.DestinationCIDR = strings.TrimSpace(config.DestinationCIDR)
	if config.DestinationCIDR == "" {
		config.DestinationCIDR = DefaultCGNATCIDR
	}
	if _, _, err := RouteParts(config.DestinationCIDR); err != nil {
		return Config{}, err
	}
	interfaceIP := net.ParseIP(strings.TrimSpace(config.InterfaceIP)).To4()
	if interfaceIP == nil {
		return Config{}, fmt.Errorf("route interface IP must be an IPv4 address")
	}
	config.InterfaceIP = net.IP(interfaceIP).String()
	if config.Metric <= 0 {
		config.Metric = DefaultMetric
	}
	return config, nil
}

func RouteParts(cidr string) (string, string, error) {
	parsedIP, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || parsedIP.To4() == nil || network == nil || network.IP.To4() == nil {
		return "", "", fmt.Errorf("route destination must be an IPv4 CIDR")
	}
	mask := network.Mask
	if ones, bits := mask.Size(); bits != 32 || ones <= 0 {
		return "", "", fmt.Errorf("route destination mask must be a contiguous IPv4 mask")
	}
	return network.IP.To4().String(), ipv4MaskString(mask), nil
}

func ipv4MaskString(mask net.IPMask) string {
	if len(mask) == 16 {
		mask = mask[12:]
	}
	if len(mask) != 4 {
		return ""
	}
	return net.IPv4(mask[0], mask[1], mask[2], mask[3]).String()
}
