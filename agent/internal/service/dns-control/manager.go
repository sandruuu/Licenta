package dnscontrol

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
)

type Config struct {
	DNSNames  []string
	DNSServer string
	HardenDoH bool
}

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

func (manager *Manager) Apply(ctx context.Context, config Config) error {
	if manager == nil {
		return errors.New("dns control manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	config.DNSNames = NormalizeDNSNames(config.DNSNames)
	config.DNSServer = normalizeDNSServer(config.DNSServer)
	if len(config.DNSNames) > 0 && config.DNSServer == "" {
		return errors.New("dns server is required when NRPT names are configured")
	}
	return applyPlatform(ctx, config)
}

func NormalizeDNSNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := normalizeDNSName(value)
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func RuleKey(name string) string {
	name = normalizeDNSName(name)
	if name == "" {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("TRUSTAGENT-")
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '.' || r == '-':
			builder.WriteRune('-')
		default:
			builder.WriteRune('-')
		}
	}
	return builder.String()
}

func normalizeDNSName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if strings.HasPrefix(value, ".") || strings.HasPrefix(value, "*.") {
		return ""
	}
	if value == "" || !strings.Contains(value, ".") || strings.ContainsAny(value, " /\\:\x00") || net.ParseIP(value) != nil {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.Contains(label, "*") {
			return ""
		}
	}
	return value
}

func normalizeDNSServer(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return ""
}

func nrptNameValue(name string) string {
	name = normalizeDNSName(name)
	if name == "" {
		return ""
	}
	return name
}
