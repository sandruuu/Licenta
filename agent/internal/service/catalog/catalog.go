package catalog

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

type Catalog struct {
	Version     string
	DNSSuffixes []string
	Resources   []Resource
	TTLSeconds  int
	NotModified bool
	PolicyEpoch string
}

type Resource struct {
	FQDN       string `json:"fqdn"`
	ResourceID string `json:"resource_id,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Port       int    `json:"port,omitempty"`
}

func NormalizeResources(values []Resource) []Resource {
	seen := make(map[string]Resource, len(values))
	for _, value := range values {
		resource := Resource{
			FQDN:       normalizeHost(value.FQDN),
			ResourceID: strings.TrimSpace(value.ResourceID),
			Protocol:   strings.ToLower(strings.TrimSpace(value.Protocol)),
			Port:       value.Port,
		}
		if resource.FQDN == "" {
			continue
		}
		if resource.Protocol == "" {
			resource.Protocol = "tcp"
		}
		if resource.Port < 0 {
			resource.Port = 0
		}
		seen[resource.FQDN] = resource
	}
	resources := make([]Resource, 0, len(seen))
	for _, resource := range seen {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(left, right int) bool {
		return resources[left].FQDN < resources[right].FQDN
	})
	return resources
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

func normalizeSuffix(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	value = strings.TrimSuffix(value, ".")
	if value == "" || !strings.Contains(value, ".") || strings.ContainsAny(value, " /\\:\x00") || net.ParseIP(value) != nil {
		return ""
	}
	return value
}

func normalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return ""
		}
		value = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(strings.TrimSpace(value), "[]")
	value = strings.TrimSuffix(value, ".")
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
