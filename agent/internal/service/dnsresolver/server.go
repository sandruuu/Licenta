package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const DefaultListenAddress = "127.0.0.1:53"

type QueryResolver interface {
	Resolve(string) (Mapping, error)
}

type ServerOptions struct {
	ListenAddress string
	Resolver      QueryResolver
	ShutdownGrace time.Duration
}

type Server struct {
	listenAddress string
	resolver      QueryResolver
	shutdownGrace time.Duration

	readyOnce sync.Once
	ready     chan struct{}

	mu        sync.RWMutex
	localAddr string
}

func NewServer(options ServerOptions) (*Server, error) {
	listenAddress := strings.TrimSpace(options.ListenAddress)
	if listenAddress == "" {
		listenAddress = DefaultListenAddress
	}
	if _, _, err := net.SplitHostPort(listenAddress); err != nil {
		if ip := net.ParseIP(listenAddress); ip != nil {
			listenAddress = net.JoinHostPort(ip.String(), "53")
		} else {
			return nil, fmt.Errorf("invalid DNS listen address %q", listenAddress)
		}
	}
	if options.Resolver == nil {
		return nil, errors.New("DNS query resolver is required")
	}
	shutdownGrace := options.ShutdownGrace
	if shutdownGrace <= 0 {
		shutdownGrace = 2 * time.Second
	}
	return &Server{
		listenAddress: listenAddress,
		resolver:      options.Resolver,
		shutdownGrace: shutdownGrace,
		ready:         make(chan struct{}),
	}, nil
}

func (server *Server) Ready() <-chan struct{} {
	if server == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return server.ready
}

func (server *Server) LocalAddr() string {
	if server == nil {
		return ""
	}
	server.mu.RLock()
	defer server.mu.RUnlock()
	return server.localAddr
}

func (server *Server) Run(ctx context.Context) error {
	if server == nil {
		return errors.New("DNS server is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	udpConn, tcpListener, err := server.listen()
	if err != nil {
		server.signalReady()
		return err
	}
	defer udpConn.Close()
	defer tcpListener.Close()

	handler := dns.NewServeMux()
	handler.HandleFunc(".", server.handleQuery)

	udpServer := &dns.Server{PacketConn: udpConn, Handler: handler}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: handler}
	done := make(chan error, 2)
	go func() { done <- udpServer.ActivateAndServe() }()
	go func() { done <- tcpServer.ActivateAndServe() }()
	server.signalReady()

	select {
	case <-ctx.Done():
		server.shutdown(udpServer, tcpServer)
		<-done
		<-done
		return nil
	case err := <-done:
		server.shutdown(udpServer, tcpServer)
		<-done
		if err != nil {
			return fmt.Errorf("DNS server stopped: %w", err)
		}
		return nil
	}
}

func (server *Server) listen() (net.PacketConn, net.Listener, error) {
	udpConn, err := net.ListenPacket("udp", server.listenAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("listen DNS UDP %s: %w", server.listenAddress, err)
	}
	localAddr := udpConn.LocalAddr().String()
	tcpListener, err := net.Listen("tcp", localAddr)
	if err != nil {
		udpConn.Close()
		return nil, nil, fmt.Errorf("listen DNS TCP %s: %w", localAddr, err)
	}
	server.mu.Lock()
	server.localAddr = localAddr
	server.mu.Unlock()
	return udpConn, tcpListener, nil
}

func (server *Server) signalReady() {
	server.readyOnce.Do(func() { close(server.ready) })
}

func (server *Server) shutdown(udpServer, tcpServer *dns.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), server.shutdownGrace)
	defer cancel()
	if udpServer != nil {
		_ = udpServer.ShutdownContext(shutdownCtx)
	}
	if tcpServer != nil {
		_ = tcpServer.ShutdownContext(shutdownCtx)
	}
}

func (server *Server) handleQuery(writer dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true

	for _, question := range request.Question {
		switch question.Qtype {
		case dns.TypeA:
			mapping, err := server.resolver.Resolve(question.Name)
			if err != nil {
				if errors.Is(err, ErrResourceNotInCatalog) {
					response.Rcode = dns.RcodeNameError
					continue
				}
				response.Rcode = dns.RcodeServerFailure
				continue
			}
			ip := net.ParseIP(mapping.SyntheticIP).To4()
			if ip == nil {
				response.Rcode = dns.RcodeServerFailure
				continue
			}
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    mappingTTL(mapping, time.Now().UTC()),
				},
				A: ip,
			})
		case dns.TypeAAAA:
			response.Rcode = dns.RcodeSuccess
		default:
			response.Rcode = dns.RcodeNotImplemented
		}
	}
	_ = writer.WriteMsg(response)
}

func mappingTTL(mapping Mapping, now time.Time) uint32 {
	if mapping.ExpiresAt.IsZero() || !mapping.ExpiresAt.After(now) {
		return 1
	}
	seconds := mapping.ExpiresAt.Sub(now).Seconds()
	if seconds < 1 {
		return 1
	}
	if seconds > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(seconds)
}
