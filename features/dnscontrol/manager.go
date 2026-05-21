package dnscontrol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

type Config struct {
	DNSSuffixes []string
	DNSServer   string
	HardenDoH   bool
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
	config.DNSSuffixes = NormalizeSuffixes(config.DNSSuffixes)
	config.DNSServer = normalizeDNSServer(config.DNSServer)
	if len(config.DNSSuffixes) > 0 && config.DNSServer == "" {
		return errors.New("dns server is required when NRPT suffixes are configured")
	}
	return applyPlatform(ctx, config)
}

func NormalizeSuffixes(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		suffix := normalizeSuffix(value)
		if suffix != "" {
			seen[suffix] = struct{}{}
		}
	}
	suffixes := make([]string, 0, len(seen))
	for suffix := range seen {
		suffixes = append(suffixes, suffix)
	}
	sort.Strings(suffixes)
	return suffixes
}

func RuleKey(suffix string) string {
	suffix = normalizeSuffix(suffix)
	if suffix == "" {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("ZTNA-")
	for _, r := range suffix {
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

func normalizeSuffix(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	value = strings.TrimSuffix(value, ".")
	if value == "" || !strings.Contains(value, ".") || strings.ContainsAny(value, " /\\:\x00") {
		return ""
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

func nrptNameValue(suffix string) string {
	suffix = normalizeSuffix(suffix)
	if suffix == "" {
		return ""
	}
	return fmt.Sprintf(".%s", suffix)
}
