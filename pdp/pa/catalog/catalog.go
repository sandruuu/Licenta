package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strings"

	"pdp/models"
	"pdp/store"
)

const TTLSeconds = 300

type Service struct {
	store *store.Store
}

type Snapshot struct {
	Version     string          `json:"version"`
	DNSSuffixes []string        `json:"dns_suffixes"`
	Resources   []ResourceEntry `json:"resources"`
	TTLSeconds  int             `json:"ttl_seconds"`
	NotModified bool            `json:"not_modified"`
	PolicyEpoch string          `json:"policy_epoch"`
}

type ResourceEntry struct {
	FQDN       string `json:"fqdn"`
	ResourceID string `json:"resource_id"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
}

func NewService(store *store.Store) *Service {
	return &Service{store: store}
}

func EmptySnapshot() Snapshot {
	return newSnapshot(nil, nil)
}

func (service *Service) BuildForRole(role string) Snapshot {
	if service == nil || service.store == nil {
		return EmptySnapshot()
	}
	resources := service.store.ListResources()
	suffixes := buildSuffixes(resources, role)
	entries := buildResources(resources, role)
	return newSnapshot(suffixes, entries)
}

func (service *Service) BuildForTenantRole(tenantID, role string) Snapshot {
	if service == nil || service.store == nil {
		return EmptySnapshot()
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return service.BuildForRole(role)
	}
	resources := service.store.ListResourcesByTenant(tenantID)
	suffixes := buildSuffixes(resources, role)
	entries := buildResources(resources, role)
	return newSnapshot(suffixes, entries)
}

func ResourceVisibleForRole(resource *models.Resource, role string) bool {
	if resource == nil {
		return false
	}
	if len(resource.AllowedRoles) == 0 {
		return true
	}
	role = strings.TrimSpace(role)
	for _, allowedRole := range resource.AllowedRoles {
		if strings.EqualFold(strings.TrimSpace(allowedRole), role) {
			return true
		}
	}
	return false
}

func ResourceProtocol(resource *models.Resource) string {
	if resource == nil {
		return "tcp"
	}
	protocol := strings.ToLower(strings.TrimSpace(resource.Type))
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol == "web" {
		if parsed, err := url.Parse(strings.TrimSpace(resource.ExternalURL)); err == nil && parsed.Scheme != "" {
			protocol = strings.ToLower(parsed.Scheme)
		} else {
			protocol = "https"
		}
	}
	return protocol
}

func ResourcePort(resource *models.Resource, protocol string) int {
	if resource == nil {
		return 0
	}
	if resource.Port > 0 {
		return resource.Port
	}
	switch protocol {
	case "https":
		return 443
	case "http":
		return 80
	case "ssh":
		return 22
	case "rdp":
		return 3389
	default:
		return 0
	}
}

func newSnapshot(suffixes []string, resources []ResourceEntry) Snapshot {
	version := version(suffixes, resources)
	return Snapshot{
		Version:     version,
		DNSSuffixes: suffixes,
		Resources:   resources,
		TTLSeconds:  TTLSeconds,
		NotModified: false,
		PolicyEpoch: version,
	}
}

func buildSuffixes(resources []*models.Resource, role string) []string {
	suffixSet := make(map[string]struct{})
	for _, resource := range resources {
		if resource == nil || !resource.Enabled {
			continue
		}
		if !ResourceVisibleForRole(resource, role) {
			continue
		}
		for _, suffix := range suffixesForResource(resource) {
			suffixSet[suffix] = struct{}{}
		}
	}
	suffixes := make([]string, 0, len(suffixSet))
	for suffix := range suffixSet {
		suffixes = append(suffixes, suffix)
	}
	sort.Strings(suffixes)
	return suffixes
}

func buildResources(resources []*models.Resource, role string) []ResourceEntry {
	entries := make([]ResourceEntry, 0, len(resources))
	for _, resource := range resources {
		if resource == nil || !resource.Enabled {
			continue
		}
		if !ResourceVisibleForRole(resource, role) {
			continue
		}
		fqdn := resourceFQDN(resource)
		if fqdn == "" {
			continue
		}
		protocol := ResourceProtocol(resource)
		entries = append(entries, ResourceEntry{
			FQDN:       fqdn,
			ResourceID: strings.TrimSpace(resource.ID),
			Protocol:   protocol,
			Port:       ResourcePort(resource, protocol),
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].FQDN == entries[right].FQDN {
			return entries[left].ResourceID < entries[right].ResourceID
		}
		return entries[left].FQDN < entries[right].FQDN
	})
	return entries
}

func version(suffixes []string, resources []ResourceEntry) string {
	payload, _ := json.Marshal(struct {
		DNSSuffixes []string        `json:"dns_suffixes"`
		Resources   []ResourceEntry `json:"resources"`
	}{DNSSuffixes: suffixes, Resources: resources})
	fingerprint := sha256.Sum256(payload)
	return hex.EncodeToString(fingerprint[:16])
}

func suffixesForResource(resource *models.Resource) []string {
	if resource == nil {
		return nil
	}
	suffixSet := make(map[string]struct{})
	if resource.Metadata != nil {
		for _, key := range []string{"dns_suffixes", "dns_suffix", "catalog_dns_suffixes", "catalog_dns_suffix", "nrpt_suffixes", "nrpt_suffix"} {
			for _, candidate := range splitSuffixes(resource.Metadata[key]) {
				if suffix := normalizeSuffix(candidate); suffix != "" {
					suffixSet[suffix] = struct{}{}
				}
			}
		}
	}
	if len(suffixSet) == 0 {
		if suffix := parentSuffix(resourceFQDN(resource)); suffix != "" {
			suffixSet[suffix] = struct{}{}
		}
	}
	suffixes := make([]string, 0, len(suffixSet))
	for suffix := range suffixSet {
		suffixes = append(suffixes, suffix)
	}
	sort.Strings(suffixes)
	return suffixes
}

func splitSuffixes(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
}

func parentSuffix(host string) string {
	host = normalizeHost(host)
	if host == "" {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return ""
	}
	return normalizeSuffix(strings.Join(parts[1:], "."))
}

func normalizeSuffix(raw string) string {
	suffix := normalizeHost(strings.TrimPrefix(strings.TrimSpace(raw), "*."))
	suffix = strings.TrimPrefix(strings.TrimSpace(suffix), ".")
	if suffix == "" || suffix == "localhost" || net.ParseIP(suffix) != nil {
		return ""
	}
	parts := strings.Split(suffix, ".")
	if len(parts) < 2 {
		return ""
	}
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, "*:_/") {
			return ""
		}
	}
	return suffix
}

func resourceFQDN(resource *models.Resource) string {
	if resource.Metadata != nil {
		for _, key := range []string{"catalog_fqdn", "fqdn", "dns_name"} {
			if value := normalizeHost(resource.Metadata[key]); value != "" {
				return value
			}
		}
	}
	if value := normalizeHost(resource.ExternalURL); value != "" {
		return value
	}
	return normalizeHost(resource.Host)
}

func normalizeHost(raw string) string {
	host := strings.TrimSpace(raw)
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil {
			return ""
		}
		host = parsed.Hostname()
	} else if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	return strings.ToLower(host)
}
