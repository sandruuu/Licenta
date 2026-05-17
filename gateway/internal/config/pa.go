package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func PATargetFromURL(rawURL string) (string, string, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", fmt.Errorf("parse pa_url: %w", err)
	}
	if !strings.EqualFold(parsedURL.Scheme, "https") {
		return "", "", fmt.Errorf("pa_url must use https for gateway gRPC")
	}
	host := strings.TrimSpace(parsedURL.Host)
	serverName := strings.TrimSpace(parsedURL.Hostname())
	if host == "" || serverName == "" {
		return "", "", fmt.Errorf("pa_url must include a host")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(serverName, "443")
	}
	return host, serverName, nil
}
