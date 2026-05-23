package dnsresolver

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestResolverResolvesOnlyCatalogResources(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	resolver, err := New(Options{Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := resolver.ApplyPolicy(Policy{
		Version:     "v1",
		PolicyEpoch: "epoch-1",
		TTLSeconds:  60,
		Resources: []Resource{{
			FQDN:       "Admin.Example.Test.",
			ResourceID: "res-1",
			Protocol:   "HTTPS",
			Port:       443,
		}},
	}); err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	mapping, err := resolver.Resolve("admin.example.test.")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if mapping.FQDN != "admin.example.test" || mapping.ResourceID != "res-1" || mapping.Protocol != "https" || mapping.Port != 443 {
		t.Fatalf("mapping = %+v", mapping)
	}
	if ip := net.ParseIP(mapping.SyntheticIP); ip == nil || !mustCIDR(t, DefaultCGNATCIDR).Contains(ip) {
		t.Fatalf("synthetic IP %q is outside CGNAT range", mapping.SyntheticIP)
	}
	if got := int(mapping.ExpiresAt.Sub(now).Seconds()); got != 60 {
		t.Fatalf("mapping TTL = %d, want 60", got)
	}
	lookup, ok := resolver.Lookup(mapping.SyntheticIP)
	if !ok || lookup.FQDN != mapping.FQDN {
		t.Fatalf("Lookup() = %+v, %t", lookup, ok)
	}
	status := resolver.Status()
	if status.State != StatusReady || status.ResourceCount != 1 || status.ActiveMappingCount != 1 || status.CatalogVersion != "v1" {
		t.Fatalf("status = %+v", status)
	}
}

func TestResolverRejectsUnknownResources(t *testing.T) {
	resolver, err := New(Options{})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := resolver.ApplyPolicy(Policy{}); err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	_, err = resolver.Resolve("unknown.example.test")
	if !errors.Is(err, ErrResourceNotInCatalog) {
		t.Fatalf("Resolve error = %v, want ErrResourceNotInCatalog", err)
	}
	if status := resolver.Status(); status.ActiveMappingCount != 0 || status.ResourceCount != 0 {
		t.Fatalf("status = %+v", status)
	}
}

func TestResolverReusesAndPurgesMappings(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	resolver, err := New(Options{Clock: func() time.Time { return now }, DefaultTTL: time.Minute})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := resolver.ApplyPolicy(Policy{Resources: []Resource{{FQDN: "app.example.test", ResourceID: "res-1"}}}); err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	first, err := resolver.Resolve("app.example.test")
	if err != nil {
		t.Fatalf("first Resolve returned error: %v", err)
	}
	now = now.Add(30 * time.Second)
	second, err := resolver.Resolve("app.example.test")
	if err != nil {
		t.Fatalf("second Resolve returned error: %v", err)
	}
	if second.SyntheticIP != first.SyntheticIP || !second.ExpiresAt.After(first.ExpiresAt) {
		t.Fatalf("mapping was not reused and refreshed: first=%+v second=%+v", first, second)
	}
	if err := resolver.ApplyPolicy(Policy{Resources: []Resource{{FQDN: "other.example.test", ResourceID: "res-2"}}}); err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	if _, ok := resolver.Lookup(first.SyntheticIP); ok {
		t.Fatalf("stale mapping for removed resource remained active")
	}
}

func TestResolverEnsuresMappingsForCatalogResources(t *testing.T) {
	now := time.Unix(3000, 0).UTC()
	resolver, err := New(Options{Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := resolver.ApplyPolicy(Policy{Resources: []Resource{
		{FQDN: "b.example.test", ResourceID: "res-b", Protocol: "tcp", Port: 443},
		{FQDN: "a.example.test", ResourceID: "res-a", Protocol: "tcp", Port: 8443},
	}}); err != nil {
		t.Fatalf("ApplyPolicy returned error: %v", err)
	}
	mappings, err := resolver.EnsureMappings()
	if err != nil {
		t.Fatalf("EnsureMappings returned error: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("EnsureMappings returned %d mappings, want 2", len(mappings))
	}
	if mappings[0].FQDN != "a.example.test" || mappings[1].FQDN != "b.example.test" {
		t.Fatalf("mappings are not sorted by FQDN: %+v", mappings)
	}
	for _, mapping := range mappings {
		if ip := net.ParseIP(mapping.SyntheticIP); ip == nil || !mustCIDR(t, DefaultCGNATCIDR).Contains(ip) {
			t.Fatalf("synthetic IP %q is outside CGNAT range", mapping.SyntheticIP)
		}
		if _, ok := resolver.Lookup(mapping.SyntheticIP); !ok {
			t.Fatalf("mapping %q was not indexed by synthetic IP", mapping.SyntheticIP)
		}
	}
}

func mustCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatalf("ParseCIDR returned error: %v", err)
	}
	return network
}
