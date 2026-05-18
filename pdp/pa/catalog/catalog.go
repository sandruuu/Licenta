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

const defaultTTLSeconds = 300

type Service struct {
	store      *store.Store
	ttlSeconds int
}

type Snapshot struct {
	Version       string          `json:"version"`
	DNSSuffixes   []string        `json:"dns_suffixes"`
	Resources     []ResourceEntry `json:"resources"`
	TTLSeconds    int             `json:"ttl_seconds"`
	NotModified   bool            `json:"not_modified"`
	PolicyEpoch   string          `json:"policy_epoch"`
	PosturePolicy PosturePolicy   `json:"posture_policy,omitempty"`
}

type ResourceEntry struct {
	FQDN       string `json:"fqdn"`
	ResourceID string `json:"resource_id"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
}

type PosturePolicy struct {
	RequiredChecks      []string `json:"required_checks,omitempty"`
	RequiredCheckStatus string   `json:"required_check_status,omitempty"`
}

func NewService(store *store.Store, ttlSeconds ...int) *Service {
	ttl := defaultTTLSeconds
	if len(ttlSeconds) > 0 && ttlSeconds[0] > 0 {
		ttl = ttlSeconds[0]
	}
	return &Service{store: store, ttlSeconds: ttl}
}

func EmptySnapshot() Snapshot {
	return newSnapshot(nil, nil, PosturePolicy{}, defaultTTLSeconds)
}

func (service *Service) BuildForRole(role string) Snapshot {
	if service == nil || service.store == nil {
		return EmptySnapshot()
	}
	resources := service.store.ListResources()
	suffixes := buildSuffixes(resources, role)
	entries := buildResources(resources, role)
	posturePolicy := buildPosturePolicy(service.store, "", role, resources)
	return newSnapshot(suffixes, entries, posturePolicy, service.ttlSeconds)
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
	posturePolicy := buildPosturePolicy(service.store, tenantID, role, resources)
	return newSnapshot(suffixes, entries, posturePolicy, service.ttlSeconds)
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

func newSnapshot(suffixes []string, resources []ResourceEntry, posturePolicy PosturePolicy, ttlSeconds int) Snapshot {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultTTLSeconds
	}
	posturePolicy = normalizePosturePolicy(posturePolicy)
	version := version(suffixes, resources, posturePolicy)
	return Snapshot{
		Version:       version,
		DNSSuffixes:   suffixes,
		Resources:     resources,
		TTLSeconds:    ttlSeconds,
		NotModified:   false,
		PolicyEpoch:   version,
		PosturePolicy: posturePolicy,
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

func version(suffixes []string, resources []ResourceEntry, posturePolicy PosturePolicy) string {
	payload, _ := json.Marshal(struct {
		DNSSuffixes   []string        `json:"dns_suffixes"`
		Resources     []ResourceEntry `json:"resources"`
		PosturePolicy PosturePolicy   `json:"posture_policy"`
	}{DNSSuffixes: suffixes, Resources: resources, PosturePolicy: normalizePosturePolicy(posturePolicy)})
	fingerprint := sha256.Sum256(payload)
	return hex.EncodeToString(fingerprint[:16])
}

func buildPosturePolicy(dataStore *store.Store, tenantID, role string, resources []*models.Resource) PosturePolicy {
	if dataStore == nil {
		return PosturePolicy{}
	}
	tenantID = strings.TrimSpace(tenantID)
	role = strings.TrimSpace(role)
	visibleResources := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if resource == nil || !resource.Enabled || strings.TrimSpace(resource.ID) == "" {
			continue
		}
		if !ResourceVisibleForRole(resource, role) {
			continue
		}
		visibleResources[strings.TrimSpace(resource.ID)] = struct{}{}
	}

	required := map[string]struct{}{}
	requiredStatus := ""
	for _, assignment := range dataStore.ListPolicyAssignments() {
		if assignment == nil || !assignment.Enabled {
			continue
		}
		assignmentTenantID := strings.TrimSpace(assignment.TenantID)
		if tenantID == "" {
			if assignmentTenantID != "" {
				continue
			}
		} else if !strings.EqualFold(assignmentTenantID, tenantID) {
			continue
		}
		if !posturePolicyAssignmentApplies(assignment, visibleResources) {
			continue
		}
		rule, ok := dataStore.GetPolicyRule(assignment.PolicyID)
		if !ok || rule == nil || !rule.Enabled || !posturePolicyRuleAction(rule.Action) {
			continue
		}
		if !posturePolicyRoleApplies(rule.Conditions, role) {
			continue
		}
		checks := normalizeCheckNames(rule.Conditions.RequiredChecks)
		if len(checks) == 0 {
			continue
		}
		for _, check := range checks {
			required[check] = struct{}{}
		}
		status := normalizePostureStatus(rule.Conditions.RequiredCheckStatus)
		if status == "" {
			status = "good"
		}
		if requiredStatus == "" || status == "good" {
			requiredStatus = status
		}
	}
	if len(required) == 0 {
		return PosturePolicy{}
	}
	checks := make([]string, 0, len(required))
	for check := range required {
		checks = append(checks, check)
	}
	sort.Strings(checks)
	if requiredStatus == "" {
		requiredStatus = "good"
	}
	return PosturePolicy{RequiredChecks: checks, RequiredCheckStatus: requiredStatus}
}

func posturePolicyAssignmentApplies(assignment *models.PolicyAssignment, visibleResources map[string]struct{}) bool {
	if assignment == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(assignment.Level)) {
	case "", "organization", "group":
		return true
	case "resource", "resource_group":
		_, ok := visibleResources[strings.TrimSpace(assignment.ResourceID)]
		return ok
	default:
		return false
	}
}

func posturePolicyRuleAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	return action == "allow" || action == "mfa_required"
}

func posturePolicyRoleApplies(conditions models.RuleConditions, role string) bool {
	if len(conditions.AllowedRoles) == 0 {
		return true
	}
	return containsFold(conditions.AllowedRoles, role)
}

func normalizePosturePolicy(policy PosturePolicy) PosturePolicy {
	checks := normalizeCheckNames(policy.RequiredChecks)
	if len(checks) == 0 {
		return PosturePolicy{}
	}
	status := normalizePostureStatus(policy.RequiredCheckStatus)
	if status == "" {
		status = "good"
	}
	return PosturePolicy{RequiredChecks: checks, RequiredCheckStatus: status}
}

func normalizeCheckNames(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		check := strings.TrimSpace(value)
		if check == "" {
			continue
		}
		seen[strings.ToLower(check)] = check
	}
	checks := make([]string, 0, len(seen))
	for _, check := range seen {
		checks = append(checks, check)
	}
	sort.Strings(checks)
	return checks
}

func normalizePostureStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "good", "warning", "critical", "unavailable":
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return ""
	}
}

func containsFold(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
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
