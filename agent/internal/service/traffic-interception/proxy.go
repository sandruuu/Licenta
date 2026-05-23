package trafficinterception

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wfpcontrol "agent/internal/service/wfp-control"
)

type proxyServer struct {
	logger     *slog.Logger
	listenAddr string
	controller wfpcontrol.Controller
	connector  StreamConnector
	timeout    time.Duration

	readyOnce sync.Once
	ready     chan struct{}

	mu        sync.RWMutex
	localAddr string
	routes    routeTable

	acceptedCount atomic.Int64
	deniedCount   atomic.Int64
}

func newProxyServer(config Config, logger *slog.Logger, controller wfpcontrol.Controller, connector StreamConnector) *proxyServer {
	listenAddr := strings.TrimSpace(config.ProxyListenAddress)
	if listenAddr == "" {
		listenAddr = DefaultProxyListenAddress
	}
	timeout := config.StreamTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &proxyServer{
		logger:     logger,
		listenAddr: listenAddr,
		controller: controller,
		connector:  connector,
		timeout:    timeout,
		ready:      make(chan struct{}),
		routes:     routeTable{byDestination: map[string]route{}},
	}
}

func (server *proxyServer) Run(ctx context.Context) error {
	if server == nil {
		return errors.New("traffic interception proxy is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	listener, err := net.Listen("tcp", server.listenAddr)
	if err != nil {
		server.signalReady()
		return fmt.Errorf("listen local traffic proxy %s: %w", server.listenAddr, err)
	}
	defer listener.Close()

	server.mu.Lock()
	server.localAddr = listener.Addr().String()
	server.mu.Unlock()
	server.signalReady()
	server.logger.Info("TrustAgent local traffic proxy listening", "address", listener.Addr().String())

	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		close(done)
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-done:
				return nil
			default:
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("accept local traffic proxy connection: %w", err)
			}
		}
		server.acceptedCount.Add(1)
		go server.handle(ctx, conn)
	}
}

func (server *proxyServer) Ready() <-chan struct{} {
	if server == nil {
		ready := make(chan struct{})
		close(ready)
		return ready
	}
	return server.ready
}

func (server *proxyServer) LocalAddr() string {
	if server == nil {
		return ""
	}
	server.mu.RLock()
	defer server.mu.RUnlock()
	return server.localAddr
}

func (server *proxyServer) SetRoutes(table routeTable) {
	if server == nil {
		return
	}
	server.mu.Lock()
	server.routes = table
	server.mu.Unlock()
}

func (server *proxyServer) RouteCount() int {
	if server == nil {
		return 0
	}
	server.mu.RLock()
	defer server.mu.RUnlock()
	return server.routes.Len()
}

func (server *proxyServer) AcceptedCount() int64 {
	if server == nil {
		return 0
	}
	return server.acceptedCount.Load()
}

func (server *proxyServer) DeniedCount() int64 {
	if server == nil {
		return 0
	}
	return server.deniedCount.Load()
}

func (server *proxyServer) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	requestCtx, cancel := context.WithTimeout(ctx, server.timeout)
	defer cancel()

	destination, err := server.controller.ResolveOriginalDestination(requestCtx, client)
	if err != nil {
		server.deny("original destination unavailable", err)
		return
	}
	server.mu.RLock()
	item, ok := server.routes.Lookup(destination.IP, destination.Port, destination.Protocol)
	server.mu.RUnlock()
	if !ok {
		server.deny("original destination is not in the active catalog", fmt.Errorf("%s/%s:%d", destination.Protocol, destination.IP, destination.Port))
		return
	}
	if server.connector == nil {
		server.deny("gateway stream connector is not configured", nil)
		return
	}
	upstream, err := server.connector.OpenResourceStream(requestCtx, StreamRequest{
		ResourceID:   item.ResourceID,
		FQDN:         item.FQDN,
		Protocol:     item.Protocol,
		Port:         item.Port,
		SyntheticIP:  item.SyntheticIP,
		ClientAddr:   client.RemoteAddr().String(),
		OriginalAddr: net.JoinHostPort(destination.IP, fmt.Sprint(destination.Port)),
	})
	if err != nil {
		server.deny("gateway stream rejected", err)
		return
	}
	defer upstream.Close()
	copyBidirectional(client, upstream)
}

func (server *proxyServer) deny(message string, err error) {
	server.deniedCount.Add(1)
	if err == nil {
		server.logger.Warn("traffic proxy denied connection", "reason", message)
		return
	}
	server.logger.Warn("traffic proxy denied connection", "reason", message, "error", err)
}

func (server *proxyServer) signalReady() {
	server.readyOnce.Do(func() { close(server.ready) })
}

func copyBidirectional(left, right net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(left, right)
		closeWrite(left)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(right, left)
		closeWrite(right)
		done <- struct{}{}
	}()
	<-done
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	_ = conn.Close()
}
