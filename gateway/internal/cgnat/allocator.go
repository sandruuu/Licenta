// Package cgnat implements a dynamic CGNAT (Carrier-Grade NAT) IP allocator
// for the ZTNA gateway. It assigns IPs from the 100.64.0.0/10 pool to internal
// resources on demand, tracks mappings with TTL-based expiration, and runs a
// background garbage collector that removes stale entries.
//
// Academic context — RFC 6598 reserves 100.64.0.0/10 for shared address space.
// Using this range avoids collisions with client-side private LANs, making it
// ideal for overlay tunnel addressing in a Zero Trust architecture.
package cgnat

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Mapping represents a single CGNAT allocation — a virtual tunnel IP
// assigned to a specific internal resource for a particular client session.
type Mapping struct {
	CGNATIP    string    // 100.64.x.x address assigned to this resource
	InternalIP string    // real IP of the backend server (e.g. 10.0.0.50)
	Port       int       // target port on the internal host
	Domain     string    // FQDN that triggered the allocation
	CreatedAt  time.Time // when the mapping was first allocated
	ExpiresAt  time.Time // when the mapping will be garbage-collected
	LastAccess time.Time // refreshed on every DNS re-query or data access
	TTL        time.Duration
}

// Allocator manages the CGNAT address pool, enforcing per-mapping TTLs
// and cleaning up expired entries via a background goroutine.
type Allocator struct {
	mu sync.RWMutex

	// Pool boundaries (big-endian uint32 of the IP)
	poolStart uint32
	poolEnd   uint32

	// Next IP to try (simple linear scan)
	nextIP uint32

	// Active mappings: CGNAT IP → Mapping
	byIP map[string]*Mapping

	// Reverse index: "internalIP:port" → CGNAT IP (prevents duplicate allocations)
	byInternal map[string]string

	// Domain index: domain (lowercase, trailing dot) → CGNAT IP
	byDomain map[string]string

	// Default TTL for new allocations
	defaultTTL time.Duration

	// GC ticker stop channel
	stopGC chan struct{}
}

// NewAllocator creates a new CGNAT allocator with the given pool boundaries
// and TTL. It starts a background garbage collector that runs every gcInterval.
func NewAllocator(poolStart, poolEnd string, defaultTTL, gcInterval time.Duration) (*Allocator, error) {
	startIP := net.ParseIP(poolStart).To4()
	endIP := net.ParseIP(poolEnd).To4()
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid pool range: %s – %s", poolStart, poolEnd)
	}

	startU := binary.BigEndian.Uint32(startIP)
	endU := binary.BigEndian.Uint32(endIP)
	if startU >= endU {
		return nil, fmt.Errorf("pool start must be less than pool end")
	}

	a := &Allocator{
		poolStart:  startU,
		poolEnd:    endU,
		nextIP:     startU + 1, // skip the first address (used by TUN itself)
		byIP:       make(map[string]*Mapping),
		byInternal: make(map[string]string),
		byDomain:   make(map[string]string),
		defaultTTL: defaultTTL,
		stopGC:     make(chan struct{}),
	}

	// Start background garbage collector
	go a.gcLoop(gcInterval)

	log.Printf("[CGNAT] Allocator started: pool %s – %s, TTL %s, GC every %s",
		poolStart, poolEnd, defaultTTL, gcInterval)
	return a, nil
}

// Allocate assigns a CGNAT IP to the given internal resource. If a mapping
// already exists (same domain or same internal IP:port), its TTL is refreshed
// and the existing CGNAT IP is returned.
func (a *Allocator) Allocate(domain, internalIP string, port int) (*Mapping, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	internalKey := fmt.Sprintf("%s:%d", internalIP, port)

	// Check if we already have a mapping for this domain
	if cgnatIP, ok := a.byDomain[domain]; ok {
		m := a.byIP[cgnatIP]
		if m != nil {
			// Refresh TTL
			m.ExpiresAt = time.Now().Add(m.TTL)
			m.LastAccess = time.Now()
			log.Printf("[CGNAT] Refreshed mapping: %s → %s (TTL %s)", domain, cgnatIP, m.TTL)
			return m, nil
		}
	}

	// Check if we already have a mapping for this internal IP:port
	if cgnatIP, ok := a.byInternal[internalKey]; ok {
		m := a.byIP[cgnatIP]
		if m != nil {
			// Refresh TTL and add domain alias
			m.ExpiresAt = time.Now().Add(m.TTL)
			m.LastAccess = time.Now()
			if domain != "" {
				a.byDomain[domain] = cgnatIP
				m.Domain = domain
			}
			log.Printf("[CGNAT] Reused mapping: %s → %s (internal %s)", domain, cgnatIP, internalKey)
			return m, nil
		}
	}

	// Allocate a new CGNAT IP
	ip, err := a.nextFreeIP()
	if err != nil {
		// Pool exhausted — run aggressive GC and retry
		a.collectGarbageLocked()
		ip, err = a.nextFreeIP()
		if err != nil {
			// Still full — evict the oldest-accessed mapping (LRU)
			if evicted := a.evictOldest(); evicted != "" {
				log.Printf("[CGNAT] Pool full: evicted oldest mapping %s", evicted)
				ip, err = a.nextFreeIP()
			}
		}
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()
	m := &Mapping{
		CGNATIP:    ip,
		InternalIP: internalIP,
		Port:       port,
		Domain:     domain,
		CreatedAt:  now,
		ExpiresAt:  now.Add(a.defaultTTL),
		LastAccess: now,
		TTL:        a.defaultTTL,
	}

	a.byIP[ip] = m
	a.byInternal[internalKey] = ip
	if domain != "" {
		a.byDomain[domain] = ip
	}

	log.Printf("[CGNAT] Allocated: %s → %s (%s:%d), TTL %s",
		domain, ip, internalIP, port, a.defaultTTL)
	return m, nil
}

// Resolve returns the internal IP for a given CGNAT tunnel IP.
// Returns ("", false) if the mapping does not exist or has expired.
func (a *Allocator) Resolve(cgnatIP string) (string, int, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	m, ok := a.byIP[cgnatIP]
	if !ok || time.Now().After(m.ExpiresAt) {
		return "", 0, false
	}
	return m.InternalIP, m.Port, true
}

// ResolveByDomain returns the CGNAT IP for a domain, if a mapping exists.
func (a *Allocator) ResolveByDomain(domain string) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	cgnatIP, ok := a.byDomain[domain]
	if !ok {
		return "", false
	}
	m := a.byIP[cgnatIP]
	if m == nil || time.Now().After(m.ExpiresAt) {
		return "", false
	}
	return cgnatIP, true
}

// Touch refreshes the TTL for a mapping identified by its CGNAT IP.
// Called when data flows through the mapping (keep-alive).
func (a *Allocator) Touch(cgnatIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if m, ok := a.byIP[cgnatIP]; ok {
		m.ExpiresAt = time.Now().Add(m.TTL)
		m.LastAccess = time.Now()
	}
}

// Release explicitly removes a mapping (e.g. when a client disconnects).
func (a *Allocator) Release(cgnatIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseLocked(cgnatIP)
}

// ActiveMappings returns a snapshot of all active (non-expired) mappings.
func (a *Allocator) ActiveMappings() []*Mapping {
	a.mu.RLock()
	defer a.mu.RUnlock()

	now := time.Now()
	result := make([]*Mapping, 0, len(a.byIP))
	for _, m := range a.byIP {
		if now.Before(m.ExpiresAt) {
			// Return a copy to avoid race conditions
			copy := *m
			result = append(result, &copy)
		}
	}
	return result
}

// PoolStats returns statistics about the CGNAT pool utilization.
func (a *Allocator) PoolStats() (total, allocated, expired int) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	total = int(a.poolEnd - a.poolStart)
	now := time.Now()
	for _, m := range a.byIP {
		if now.Before(m.ExpiresAt) {
			allocated++
		} else {
			expired++
		}
	}
	return
}

// Stop terminates the background garbage collector.
func (a *Allocator) Stop() {
	close(a.stopGC)
	log.Printf("[CGNAT] Allocator stopped")
}

// ── Internal helpers ────────────────────────────────────────────

// nextFreeIP finds the next available IP in the pool (linear scan).
func (a *Allocator) nextFreeIP() (string, error) {
	start := a.nextIP
	for {
		ip := uint32ToIP(a.nextIP)
		if _, taken := a.byIP[ip]; !taken {
			a.nextIP++
			if a.nextIP > a.poolEnd {
				a.nextIP = a.poolStart + 1
			}
			return ip, nil
		}
		a.nextIP++
		if a.nextIP > a.poolEnd {
			a.nextIP = a.poolStart + 1
		}
		if a.nextIP == start {
			return "", fmt.Errorf("CGNAT pool exhausted — no free IPs")
		}
	}
}

// releaseLocked removes a mapping (caller must hold a.mu write lock).
func (a *Allocator) releaseLocked(cgnatIP string) {
	m, ok := a.byIP[cgnatIP]
	if !ok {
		return
	}

	internalKey := fmt.Sprintf("%s:%d", m.InternalIP, m.Port)
	delete(a.byInternal, internalKey)
	delete(a.byIP, cgnatIP)
	if m.Domain != "" {
		delete(a.byDomain, m.Domain)
	}

	log.Printf("[CGNAT] Released: %s (was %s → %s)", cgnatIP, m.Domain, m.InternalIP)
}

// gcLoop is the background garbage collector. It periodically removes
// expired mappings whose TTL has elapsed without a refresh.
func (a *Allocator) gcLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.collectGarbage()
		case <-a.stopGC:
			return
		}
	}
}

// collectGarbage removes all expired mappings.
func (a *Allocator) collectGarbage() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.collectGarbageLocked()
}

// collectGarbageLocked removes expired mappings (caller must hold a.mu write lock).
func (a *Allocator) collectGarbageLocked() {
	now := time.Now()
	expired := make([]string, 0)

	for ip, m := range a.byIP {
		if now.After(m.ExpiresAt) {
			expired = append(expired, ip)
		}
	}

	for _, ip := range expired {
		a.releaseLocked(ip)
	}

	if len(expired) > 0 {
		log.Printf("[CGNAT] GC: cleaned %d expired mapping(s), %d active",
			len(expired), len(a.byIP))
	}
}

// evictOldest removes the mapping with the oldest LastAccess time (LRU eviction).
// Caller must hold a.mu write lock. Returns the evicted CGNAT IP or "" if pool is empty.
func (a *Allocator) evictOldest() string {
	var oldestIP string
	var oldestTime time.Time

	for ip, m := range a.byIP {
		if oldestIP == "" || m.LastAccess.Before(oldestTime) {
			oldestIP = ip
			oldestTime = m.LastAccess
		}
	}

	if oldestIP != "" {
		a.releaseLocked(oldestIP)
	}
	return oldestIP
}

// uint32ToIP converts a big-endian uint32 to a dotted-quad IP string.
func uint32ToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
