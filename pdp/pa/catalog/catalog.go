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
	Version          string           `json:"version"`
	Resources        []ResourceEntry  `json:"resources"`
	TTLSeconds       int              `json:"ttl_seconds"`
	NotModified      bool             `json:"not_modified"`
	PolicyEpoch      string           `json:"policy_epoch"`
	DeviceDataPolicy DeviceDataPolicy `json:"device_data_policy,omitempty"`
}

type ResourceEntry struct {
	FQDN       string `json:"fqdn"`
	ResourceID string `json:"resource_id"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
}

type DeviceDataPolicy struct {
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
	return newSnapshot(nil, DeviceDataPolicy{}, defaultTTLSeconds)
}

func (service *Service) BuildForTenantUser(tenantID string, user *models.User, groupIDs, groupNames []string) Snapshot {
	if service == nil || service.store == nil || user == nil {
		return EmptySnapshot()
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(user.TenantID)
	}
	if tenantID == "" {
		return EmptySnapshot()
	}

	resources := service.store.ListResourcesByTenant(tenantID)
	accessible := service.accessibleResources(tenantID, user, groupIDs, groupNames, resources)
	entries := buildResources(accessible)
	deviceDataPolicy := buildDeviceDataPolicyForUser(service.store, tenantID, user, groupIDs, groupNames, accessible)
	return newSnapshot(entries, deviceDataPolicy, service.ttlSeconds)
}

func (service *Service) accessibleResources(tenantID string, user *models.User, groupIDs, groupNames []string, resources []*models.Resource) []*models.Resource {
	accessible := make([]*models.Resource, 0, len(resources))
	for _, resource := range resources {
		if resource == nil || !resource.Enabled || strings.TrimSpace(resource.ID) == "" {
			continue
		}
		if service.resourceAllowedByPolicy(tenantID, user, groupIDs, groupNames, resource) {
			accessible = append(accessible, resource)
		}
	}
	return accessible
}

func (service *Service) resourceAllowedByPolicy(tenantID string, user *models.User, groupIDs, groupNames []string, resource *models.Resource) bool {
	if service == nil || service.store == nil || user == nil || resource == nil {
		return false
	}
	rules := service.store.ListPolicyRulesForAccessGroups(tenantID, resource.ID, groupIDs, groupNames)
	for _, rule := range rules {
		if rule == nil || !rule.Enabled {
			continue
		}
		if !catalogRuleMatchesIdentity(rule, user, groupIDs, groupNames, resource) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(rule.Action)) {
		case "allow", "mfa_required":
			return true
		case "deny":
			return false
		}
	}
	return false
}

func catalogRuleMatchesIdentity(rule *models.PolicyRule, user *models.User, groupIDs, groupNames []string, resource *models.Resource) bool {
	if rule == nil || user == nil {
		return false
	}
	conditions := rule.Conditions
	if len(conditions.AllowedRoles) > 0 && !containsFold(conditions.AllowedRoles, user.Role) {
		return false
	}
	if len(conditions.AllowedUsers) > 0 {
		if !containsAnyFold(conditions.AllowedUsers, user.ID, user.Username, user.Email) {
			return false
		}
	}
	if len(conditions.AllowedGroups) > 0 {
		if !intersectsFold(conditions.AllowedGroups, append(append([]string{}, groupIDs...), groupNames...)) {
			return false
		}
	}
	if len(conditions.TargetResources) > 0 {
		if resource == nil || !containsAnyFold(conditions.TargetResources, resource.ID, resource.Name) {
			return false
		}
	}
	if len(conditions.TargetPorts) > 0 {
		if resource == nil {
			return false
		}
		port := ResourcePort(resource, ResourceProtocol(resource))
		if !containsInt(conditions.TargetPorts, port) {
			return false
		}
	}
	return true
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

func newSnapshot(resources []ResourceEntry, deviceDataPolicy DeviceDataPolicy, ttlSeconds int) Snapshot {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultTTLSeconds
	}
	deviceDataPolicy = normalizeDeviceDataPolicy(deviceDataPolicy)
	version := version(resources, deviceDataPolicy)
	return Snapshot{
		Version:          version,
		Resources:        resources,
		TTLSeconds:       ttlSeconds,
		NotModified:      false,
		PolicyEpoch:      version,
		DeviceDataPolicy: deviceDataPolicy,
	}
}

func buildResources(resources []*models.Resource) []ResourceEntry {
	entries := make([]ResourceEntry, 0, len(resources))
	for _, resource := range resources {
		if resource == nil || !resource.Enabled {
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

func version(resources []ResourceEntry, deviceDataPolicy DeviceDataPolicy) string {
	payload, _ := json.Marshal(struct {
		Resources        []ResourceEntry  `json:"resources"`
		DeviceDataPolicy DeviceDataPolicy `json:"device_data_policy"`
	}{Resources: resources, DeviceDataPolicy: normalizeDeviceDataPolicy(deviceDataPolicy)})
	fingerprint := sha256.Sum256(payload)
	return hex.EncodeToString(fingerprint[:16])
}

func buildDeviceDataPolicyForUser(dataStore *store.Store, tenantID string, user *models.User, groupIDs, groupNames []string, resources []*models.Resource) DeviceDataPolicy {
	if dataStore == nil || user == nil {
		return DeviceDataPolicy{}
	}
	required := map[string]struct{}{}
	requiredStatus := ""
	for _, resource := range resources {
		if resource == nil || strings.TrimSpace(resource.ID) == "" {
			continue
		}
		for _, rule := range dataStore.ListPolicyRulesForAccessGroups(tenantID, resource.ID, groupIDs, groupNames) {
			if rule == nil || !rule.Enabled || !deviceDataPolicyRuleAction(rule.Action) {
				continue
			}
			if !catalogRuleMatchesIdentity(rule, user, groupIDs, groupNames, resource) {
				continue
			}
			checks := normalizeCheckNames(rule.Conditions.RequiredChecks)
			if len(checks) == 0 {
				continue
			}
			for _, check := range checks {
				required[check] = struct{}{}
			}
			status := normalizeDeviceDataStatus(rule.Conditions.RequiredCheckStatus)
			if status == "" {
				status = "good"
			}
			if requiredStatus == "" || status == "good" {
				requiredStatus = status
			}
		}
	}
	if len(required) == 0 {
		return DeviceDataPolicy{}
	}
	checks := make([]string, 0, len(required))
	for check := range required {
		checks = append(checks, check)
	}
	sort.Strings(checks)
	if requiredStatus == "" {
		requiredStatus = "good"
	}
	return DeviceDataPolicy{RequiredChecks: checks, RequiredCheckStatus: requiredStatus}
}

func deviceDataPolicyRuleAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	return action == "allow" || action == "mfa_required"
}

func normalizeDeviceDataPolicy(policy DeviceDataPolicy) DeviceDataPolicy {
	checks := normalizeCheckNames(policy.RequiredChecks)
	if len(checks) == 0 {
		return DeviceDataPolicy{}
	}
	status := normalizeDeviceDataStatus(policy.RequiredCheckStatus)
	if status == "" {
		status = "good"
	}
	return DeviceDataPolicy{RequiredChecks: checks, RequiredCheckStatus: status}
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

func normalizeDeviceDataStatus(status string) string {
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

func containsAnyFold(values []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if containsFold(values, candidate) {
			return true
		}
	}
	return false
}

func intersectsFold(left, right []string) bool {
	for _, candidate := range right {
		if containsFold(left, candidate) {
			return true
		}
	}
	return false
}

func containsInt(values []int, candidate int) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func resourceFQDN(resource *models.Resource) string {
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
