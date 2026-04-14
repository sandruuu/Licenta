package dns

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"gateway/internal/config"
	"gateway/store"

	mdns "github.com/miekg/dns"
)

// validDNSLabel matches a valid DNS label: alphanumeric and hyphens, not starting/ending with hyphen.
var validDNSLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// IsValidResourceName checks if a resource name is safe to use as a DNS domain component.
func IsValidResourceName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	return validDNSLabel.MatchString(name)
}

// Resolver handles internal DNS resolution for the gateway.
// It resolves resource names to their internal IPs.
type Resolver struct {
	cfg      *config.Config
	upstream string
	mappings map[string]string // domain -> internal IP
	server   *mdns.Server

	// Upstream query cache
	cacheMu  sync.RWMutex
	cache    map[string]*cacheEntry
	cacheTTL time.Duration
}

// cacheEntry stores a cached upstream DNS result.
type cacheEntry struct {
	ip       string
	cachedAt time.Time
	ttl      time.Duration
}

// New creates a new DNS resolver
func New(cfg *config.Config, db *store.Store) *Resolver {
	mappings := make(map[string]string)
	if db != nil {
		resources, _ := db.ListResources()
		for _, res := range resources {
			if !IsValidResourceName(res.Name) {
				log.Printf("[DNS] Skipping resource with invalid name: %q", res.Name)
				continue
			}
			if net.ParseIP(res.InternalIP) == nil {
				log.Printf("[DNS] Skipping resource %q with invalid IP: %q", res.Name, res.InternalIP)
				continue
			}
			domain := strings.ToLower(res.Name) + ".internal."
			mappings[domain] = res.InternalIP
		}
	}

	return &Resolver{
		cfg:      cfg,
		upstream: cfg.InternalDNS,
		mappings: mappings,
		cache:    make(map[string]*cacheEntry),
		cacheTTL: 60 * time.Second,
	}
}

// Resolve looks up an internal IP for a resource name
func (r *Resolver) Resolve(name string) (string, bool) {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	ip, ok := r.mappings[name]
	return ip, ok
}

// Start begins the DNS server (optional, for internal use)
func (r *Resolver) Start(listenAddr string) error {
	handler := mdns.NewServeMux()
	handler.HandleFunc(".", r.handleQuery)

	r.server = &mdns.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: handler,
	}

	log.Printf("[DNS] Gateway DNS resolver starting on %s", listenAddr)
	for domain, ip := range r.mappings {
		log.Printf("[DNS]   %s → %s", domain, ip)
	}

	go func() {
		if err := r.server.ListenAndServe(); err != nil {
			log.Printf("[DNS] Server error: %v", err)
		}
	}()

	return nil
}

// Stop shuts down the DNS server
func (r *Resolver) Stop() {
	if r.server != nil {
		r.server.Shutdown()
	}
}

func (r *Resolver) handleQuery(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	for _, q := range req.Question {
		name := strings.ToLower(q.Name)
		if q.Qtype == mdns.TypeA {
			if ip, ok := r.mappings[name]; ok {
				rr := &mdns.A{
					Hdr: mdns.RR_Header{
						Name:   q.Name,
						Rrtype: mdns.TypeA,
						Class:  mdns.ClassINET,
						Ttl:    60,
					},
					A: net.ParseIP(ip),
				}
				resp.Answer = append(resp.Answer, rr)
				log.Printf("[DNS] Resolved %s → %s", name, ip)
				continue
			}
		}

		// Forward to upstream
		upstream, err := r.forwardQuery(req)
		if err != nil {
			log.Printf("[DNS] Forward error: %v", err)
			resp.Rcode = mdns.RcodeServerFailure
		} else {
			resp.Answer = append(resp.Answer, upstream.Answer...)
		}
	}

	w.WriteMsg(resp)
}

func (r *Resolver) forwardQuery(req *mdns.Msg) (*mdns.Msg, error) {
	if r.upstream == "" {
		return nil, fmt.Errorf("no upstream DNS configured")
	}
	client := &mdns.Client{}
	resp, _, err := client.Exchange(req, r.upstream)
	return resp, err
}

// ResolveHostA resolves a hostname to an IPv4 address using local mappings first
// and then forwarding to the configured upstream DNS server.
func (r *Resolver) ResolveHostA(host string) (string, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return "", fmt.Errorf("empty host")
	}

	// If the input is already an IP, return it directly.
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}

	fqdn := strings.TrimSuffix(host, ".") + "."

	// Try local static mappings first.
	if ip, ok := r.mappings[fqdn]; ok {
		return ip, nil
	}

	// Check upstream cache.
	r.cacheMu.RLock()
	if entry, ok := r.cache[fqdn]; ok && time.Since(entry.cachedAt) < entry.ttl {
		r.cacheMu.RUnlock()
		return entry.ip, nil
	}
	r.cacheMu.RUnlock()

	if r.upstream == "" {
		return "", fmt.Errorf("no upstream DNS configured")
	}

	msg := new(mdns.Msg)
	msg.SetQuestion(fqdn, mdns.TypeA)

	client := &mdns.Client{}
	resp, _, err := client.Exchange(msg, r.upstream)
	if err != nil {
		return "", fmt.Errorf("dns query failed: %w", err)
	}

	if resp == nil || len(resp.Answer) == 0 {
		return "", fmt.Errorf("no A record for %s", host)
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*mdns.A); ok && a.A != nil {
			ip := a.A.String()
			// Cache the result
			r.cacheMu.Lock()
			r.cache[fqdn] = &cacheEntry{ip: ip, cachedAt: time.Now(), ttl: r.cacheTTL}
			r.cacheMu.Unlock()
			return ip, nil
		}
	}

	return "", fmt.Errorf("no A record for %s", host)
}
