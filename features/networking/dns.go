package networking

import (
	"net"
	"strings"

	"licenta/features/dnsresolver"
)

func DNSListenAddress(dnsServer string) string {
	value := strings.TrimSpace(dnsServer)
	if value == "" {
		return dnsresolver.DefaultListenAddress
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && strings.TrimSpace(port) != "" {
			return net.JoinHostPort(ip.String(), port)
		}
		return dnsresolver.DefaultListenAddress
	}
	if ip := net.ParseIP(value); ip != nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	return dnsresolver.DefaultListenAddress
}

func TUNDNSServer(dnsServer string) string {
	value := strings.TrimSpace(dnsServer)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return ip.String()
		}
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return ""
}
