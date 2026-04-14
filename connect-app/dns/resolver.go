package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"connect-app/config"

	"github.com/miekg/dns"
)

type TunnelResolver interface {
	ResolveDomain(ctx context.Context, domain string) (cgnatIP string, ttl int, err error)
}

type CacheEntry struct {
	CGNATIP   string
	ExpiresAt time.Time
}

var cgnatNet = &net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0),
	Mask: net.CIDRMask(10, 32),
}

func isCGNAT(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && cgnatNet.Contains(ip)
}

type Resolver struct {
	listenAddr     string
	upstreamDNS    string
	internalSuffix string
	tunnel         TunnelResolver
	server         *dns.Server
	serverTCP      *dns.Server

	cacheMu sync.RWMutex
	cache   map[string]*CacheEntry
}

func New(cfg *config.Config, tunnelResolver TunnelResolver) *Resolver {
	suffix := cfg.InternalSuffix
	if suffix != "" && !strings.HasPrefix(suffix, ".") {
		suffix = "." + suffix
	}

	return &Resolver{
		listenAddr:     cfg.DNSListenAddr,
		upstreamDNS:    cfg.UpstreamDNS,
		internalSuffix: strings.ToLower(suffix),
		tunnel:         tunnelResolver,
		cache:          make(map[string]*CacheEntry),
	}
}

func (r *Resolver) Start() error {
	handler := dns.NewServeMux()
	handler.HandleFunc(".", r.handleQuery)

	r.server = &dns.Server{
		Addr:    r.listenAddr,
		Net:     "udp",
		Handler: handler,
	}
	r.serverTCP = &dns.Server{
		Addr:    r.listenAddr,
		Net:     "tcp",
		Handler: handler,
	}

	slog.Info("Starting Magic DNS resolver", "addr", r.listenAddr, "proto", "UDP+TCP")
	slog.Info("Internal suffix configured", "suffix", r.internalSuffix)
	slog.Info("External queries forwarded", "upstream", r.upstreamDNS)

	go func() {
		if err := r.server.ListenAndServe(); err != nil {
			slog.Error("DNS UDP server error", "error", err)
		}
	}()
	go func() {
		if err := r.serverTCP.ListenAndServe(); err != nil {
			slog.Error("DNS TCP server error", "error", err)
		}
	}()

	return nil
}

func (r *Resolver) Stop() {
	if r.server != nil {
		r.server.Shutdown()
	}
	if r.serverTCP != nil {
		r.serverTCP.Shutdown()
	}
	slog.Info("Resolver stopped")
}

func (r *Resolver) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	handled := false

	for _, q := range req.Question {
		name := strings.ToLower(q.Name)

		if q.Qtype == dns.TypeA && r.isInternalDomain(name) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			cgnatIP, ttl, err := r.resolveInternal(ctx, name)
			cancel()

			if err != nil {
				slog.Warn("Internal resolve failed", "domain", name, "error", err)
				continue
			}

			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(ttl),
				},
				A: net.ParseIP(cgnatIP),
			}
			resp.Answer = append(resp.Answer, rr)
			handled = true
			slog.Debug("Internal DNS resolved", "domain", name, "cgnat_ip", cgnatIP, "ttl", ttl)
		}
	}

	if !handled {
		upstream, err := r.forwardQuery(req)
		if err != nil {
			slog.Warn("Upstream query failed", "error", err)
			resp.Rcode = dns.RcodeServerFailure
		} else {
			resp.Answer = upstream.Answer
			resp.Ns = upstream.Ns
			resp.Extra = upstream.Extra
		}
	}

	w.WriteMsg(resp)
}

func (r *Resolver) isInternalDomain(name string) bool {
	if r.internalSuffix == "" {
		return false
	}
	cleaned := strings.TrimSuffix(name, ".")
	return strings.HasSuffix(cleaned, r.internalSuffix)
}

func (r *Resolver) resolveInternal(ctx context.Context, name string) (string, int, error) {
	r.cacheMu.RLock()
	entry, ok := r.cache[name]
	r.cacheMu.RUnlock()

	if ok && time.Now().Before(entry.ExpiresAt) {
		return entry.CGNATIP, int(time.Until(entry.ExpiresAt).Seconds()), nil
	}

	if r.tunnel == nil {
		return "", 0, fmt.Errorf("tunnel not connected — cannot resolve %s", name)
	}

	cgnatIP, ttl, err := r.tunnel.ResolveDomain(ctx, name)
	if err != nil {
		slog.Warn("Failed to resolve via gateway", "domain", name, "error", err)
		return "", 0, err
	}

	if !isCGNAT(cgnatIP) {
		return "", 0, fmt.Errorf("rejected non-CGNAT IP %s for %s", cgnatIP, name)
	}

	r.cacheMu.Lock()
	r.cache[name] = &CacheEntry{
		CGNATIP:   cgnatIP,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	r.cacheMu.Unlock()

	return cgnatIP, ttl, nil
}

func (r *Resolver) forwardQuery(req *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.Exchange(req, r.upstreamDNS)
	if err == nil && resp.Truncated {
		tcpClient := &dns.Client{Timeout: 5 * time.Second, Net: "tcp"}
		resp, _, err = tcpClient.Exchange(req, r.upstreamDNS)
	}
	return resp, err
}
