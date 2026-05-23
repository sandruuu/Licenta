package dnsresolver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCGNATCIDR = "100.64.0.0/10"
	defaultTTL       = 5 * time.Minute
	StatusWaiting    = "waiting_for_catalog"
	StatusReady      = "ready"
	StatusError      = "error"
)

var (
	ErrResourceNotInCatalog = errors.New("resource is not present in catalog")
	ErrPoolExhausted        = errors.New("synthetic IP pool exhausted")
)

type Options struct {
	CGNATCIDR  string
	DefaultTTL time.Duration
	Clock      func() time.Time
}

type Policy struct {
	Version     string
	PolicyEpoch string
	Resources   []Resource
	TTLSeconds  int
}

type Resource struct {
	FQDN       string
	ResourceID string
	Protocol   string
	Port       int
}

type Mapping struct {
	FQDN        string
	ResourceID  string
	Protocol    string
	Port        int
	SyntheticIP string
	CreatedAt   time.Time
	LastAccess  time.Time
	ExpiresAt   time.Time
}

type Status struct {
	State              string
	CGNATRange         string
	ResourceCount      int
	ActiveMappingCount int
	CatalogVersion     string
	PolicyEpoch        string
	LastUpdatedAt      time.Time
	LastError          string
}

type Resolver struct {
	mu          sync.RWMutex
	clock       func() time.Time
	cgnatCIDR   string
	poolStart   uint32
	poolEnd     uint32
	nextIP      uint32
	defaultTTL  time.Duration
	policyTTL   time.Duration
	version     string
	policyEpoch string
	resources   map[string]Resource
	byName      map[string]*Mapping
	byIP        map[string]*Mapping
	state       string
	lastUpdated time.Time
	lastError   string
}

func New(options Options) (*Resolver, error) {
	cgnatCIDR := strings.TrimSpace(options.CGNATCIDR)
	if cgnatCIDR == "" {
		cgnatCIDR = DefaultCGNATCIDR
	}
	_, network, err := net.ParseCIDR(cgnatCIDR)
	if err != nil || network == nil || network.IP.To4() == nil {
		return nil, fmt.Errorf("invalid CGNAT CIDR %q", cgnatCIDR)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones >= 31 {
		return nil, fmt.Errorf("CGNAT CIDR %q is too small", cgnatCIDR)
	}
	start := binary.BigEndian.Uint32(network.IP.To4())
	size := uint32(1) << uint32(32-ones)
	end := start + size - 1
	defaultMappingTTL := options.DefaultTTL
	if defaultMappingTTL <= 0 {
		defaultMappingTTL = defaultTTL
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Resolver{
		clock:      clock,
		cgnatCIDR:  cgnatCIDR,
		poolStart:  start + 2,
		poolEnd:    end - 1,
		nextIP:     start + 2,
		defaultTTL: defaultMappingTTL,
		policyTTL:  defaultMappingTTL,
		resources:  make(map[string]Resource),
		byName:     make(map[string]*Mapping),
		byIP:       make(map[string]*Mapping),
		state:      StatusWaiting,
	}, nil
}

func (resolver *Resolver) ApplyPolicy(policy Policy) error {
	if resolver == nil {
		return errors.New("dns resolver is nil")
	}
	resources := normalizeResources(policy.Resources)
	now := resolver.clock().UTC()
	resourceSet := make(map[string]Resource, len(resources))
	for _, resource := range resources {
		resourceSet[resource.FQDN] = resource
	}

	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.resources = resourceSet
	resolver.version = strings.TrimSpace(policy.Version)
	resolver.policyEpoch = strings.TrimSpace(policy.PolicyEpoch)
	resolver.policyTTL = resolver.defaultTTL
	if policy.TTLSeconds > 0 {
		resolver.policyTTL = time.Duration(policy.TTLSeconds) * time.Second
	}
	resolver.lastUpdated = now
	resolver.lastError = ""
	resolver.state = StatusReady

	for fqdn, mapping := range resolver.byName {
		if _, ok := resolver.resources[fqdn]; !ok || !mapping.ExpiresAt.After(now) {
			resolver.releaseLocked(mapping.SyntheticIP)
		}
	}
	return nil
}

func (resolver *Resolver) Resolve(name string) (Mapping, error) {
	if resolver == nil {
		return Mapping{}, errors.New("dns resolver is nil")
	}
	fqdn := normalizeHost(name)
	if fqdn == "" {
		return Mapping{}, fmt.Errorf("%w: %q", ErrResourceNotInCatalog, name)
	}
	now := resolver.clock().UTC()

	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.resolveLocked(fqdn, now)
}

func (resolver *Resolver) EnsureMappings() ([]Mapping, error) {
	if resolver == nil {
		return nil, errors.New("dns resolver is nil")
	}
	now := resolver.clock().UTC()

	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	names := make([]string, 0, len(resolver.resources))
	for fqdn := range resolver.resources {
		names = append(names, fqdn)
	}
	sort.Strings(names)
	mappings := make([]Mapping, 0, len(names))
	for _, fqdn := range names {
		mapping, err := resolver.resolveLocked(fqdn, now)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, mapping)
	}
	return mappings, nil
}

func (resolver *Resolver) resolveLocked(fqdn string, now time.Time) (Mapping, error) {
	resource, ok := resolver.resources[fqdn]
	if !ok {
		resolver.lastError = ErrResourceNotInCatalog.Error()
		return Mapping{}, fmt.Errorf("%w: %s", ErrResourceNotInCatalog, fqdn)
	}
	if mapping, ok := resolver.byName[fqdn]; ok && mapping.ExpiresAt.After(now) {
		mapping.LastAccess = now
		mapping.ExpiresAt = now.Add(resolver.policyTTL)
		return copyMapping(mapping), nil
	}
	if mapping, ok := resolver.byName[fqdn]; ok {
		resolver.releaseLocked(mapping.SyntheticIP)
	}
	ip, err := resolver.allocateLocked()
	if err != nil {
		resolver.lastError = err.Error()
		resolver.state = StatusError
		return Mapping{}, err
	}
	mapping := &Mapping{
		FQDN:        resource.FQDN,
		ResourceID:  resource.ResourceID,
		Protocol:    resource.Protocol,
		Port:        resource.Port,
		SyntheticIP: ip,
		CreatedAt:   now,
		LastAccess:  now,
		ExpiresAt:   now.Add(resolver.policyTTL),
	}
	resolver.byName[fqdn] = mapping
	resolver.byIP[ip] = mapping
	resolver.lastError = ""
	resolver.state = StatusReady
	return copyMapping(mapping), nil
}

func (resolver *Resolver) Lookup(ip string) (Mapping, bool) {
	if resolver == nil {
		return Mapping{}, false
	}
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil {
		return Mapping{}, false
	}
	ip = parsed.String()
	now := resolver.clock().UTC()
	resolver.mu.RLock()
	mapping, ok := resolver.byIP[ip]
	if ok && mapping.ExpiresAt.After(now) {
		copyValue := copyMapping(mapping)
		resolver.mu.RUnlock()
		return copyValue, true
	}
	resolver.mu.RUnlock()
	if ok {
		resolver.mu.Lock()
		resolver.releaseLocked(ip)
		resolver.mu.Unlock()
	}
	return Mapping{}, false
}

func (resolver *Resolver) Status() Status {
	if resolver == nil {
		return Status{State: StatusWaiting}
	}
	now := resolver.clock().UTC()
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.collectExpiredLocked(now)
	return Status{
		State:              resolver.state,
		CGNATRange:         resolver.cgnatCIDR,
		ResourceCount:      len(resolver.resources),
		ActiveMappingCount: len(resolver.byIP),
		CatalogVersion:     resolver.version,
		PolicyEpoch:        resolver.policyEpoch,
		LastUpdatedAt:      resolver.lastUpdated,
		LastError:          resolver.lastError,
	}
}

func (resolver *Resolver) allocateLocked() (string, error) {
	for candidate := resolver.nextIP; candidate <= resolver.poolEnd; candidate++ {
		ip := uint32ToIP(candidate)
		if _, ok := resolver.byIP[ip]; !ok {
			resolver.nextIP = candidate + 1
			if resolver.nextIP > resolver.poolEnd {
				resolver.nextIP = resolver.poolStart
			}
			return ip, nil
		}
	}
	for candidate := resolver.poolStart; candidate < resolver.nextIP; candidate++ {
		ip := uint32ToIP(candidate)
		if _, ok := resolver.byIP[ip]; !ok {
			resolver.nextIP = candidate + 1
			return ip, nil
		}
	}
	return "", ErrPoolExhausted
}

func (resolver *Resolver) releaseLocked(ip string) {
	mapping, ok := resolver.byIP[ip]
	if !ok {
		return
	}
	delete(resolver.byIP, ip)
	delete(resolver.byName, mapping.FQDN)
}

func (resolver *Resolver) collectExpiredLocked(now time.Time) {
	for ip, mapping := range resolver.byIP {
		if !mapping.ExpiresAt.After(now) {
			resolver.releaseLocked(ip)
		}
	}
}

func copyMapping(mapping *Mapping) Mapping {
	if mapping == nil {
		return Mapping{}
	}
	return *mapping
}

func uint32ToIP(value uint32) string {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return net.IPv4(raw[0], raw[1], raw[2], raw[3]).String()
}

func normalizeResources(values []Resource) []Resource {
	seen := make(map[string]Resource, len(values))
	for _, value := range values {
		fqdn := normalizeHost(value.FQDN)
		if fqdn == "" {
			continue
		}
		resource := Resource{
			FQDN:       fqdn,
			ResourceID: strings.TrimSpace(value.ResourceID),
			Protocol:   strings.ToLower(strings.TrimSpace(value.Protocol)),
			Port:       value.Port,
		}
		if resource.Protocol == "" {
			resource.Protocol = "tcp"
		}
		if resource.Port < 0 {
			resource.Port = 0
		}
		seen[fqdn] = resource
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

func normalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
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
