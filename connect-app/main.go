package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "connect-app/logger"

	"connect-app/config"
	"connect-app/dns"
	"connect-app/routing"
	"connect-app/tcpproxy"
	"connect-app/tpmauth"
	"connect-app/tun"
	"connect-app/tunnel"
)

// connKey identifies a unique TCP flow
type connKey struct {
	srcPort int
	dstIP   string
	dstPort int
}

// activeConn holds a yamux stream and TCP state for a tracked flow
type activeConn struct {
	stream net.Conn
	flow   *tcpproxy.Flow
	mu     sync.Mutex
	closed bool

	// auth-pending state
	pendingAuth   bool
	pendingSince  time.Time
	buffer        [][]byte
	bufferedBytes int

	// handshake deferral
	pendingSyn       bool
	pendingClientISN uint32
}

// connTracker manages active TCP flows → yamux streams
type connTracker struct {
	mu    sync.RWMutex
	conns map[connKey]*activeConn
}

func newConnTracker() *connTracker {
	return &connTracker{
		conns: make(map[connKey]*activeConn),
	}
}

const (
	maxPendingBufferBytes = 1 << 20 // 1 MB
	maxAuthWait           = 2 * time.Minute
)

func (ct *connTracker) get(key connKey) *activeConn {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.conns[key]
}

func (ct *connTracker) getOrCreate(key connKey) (*activeConn, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ac, ok := ct.conns[key]; ok {
		return ac, false
	}

	ac := &activeConn{}
	ct.conns[key] = ac
	return ac, true
}

func (ct *connTracker) remove(key connKey) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ac, ok := ct.conns[key]; ok {
		ac.mu.Lock()
		if !ac.closed && ac.stream != nil {
			ac.stream.Close()
		}
		ac.closed = true
		ac.mu.Unlock()
		delete(ct.conns, key)
	}
}

func (ct *connTracker) closeAll() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for k, ac := range ct.conns {
		ac.mu.Lock()
		if !ac.closed && ac.stream != nil {
			ac.stream.Close()
		}
		ac.closed = true
		ac.mu.Unlock()
		delete(ct.conns, k)
	}
}

func main() {
	flag.Parse()

	// Load config
	cfg, err := config.LoadConfig("connect-config.json")
	if err != nil {
		slog.Error("Failed to load config", "file", "connect-config.json", "error", err)
		os.Exit(1)
	}
	slog.Info("Config loaded", "file", "connect-config.json")

	// TUN
	tunDev, err := tun.New(cfg.TUNName, cfg.TUNIP, cfg.TUNNetmask)
	if err != nil {
		slog.Error("TUN creation failed (need admin?)", "error", err)
		os.Exit(1)
	}
	defer tunDev.Close()

	// Routing CGNAT
	routeMgr := routing.New(cfg.TUNIP)
	if err := routeMgr.AddCGNATRoute(); err != nil {
		slog.Warn("Failed to add CGNAT route", "error", err)
	} else {
		defer routeMgr.RemoveAllRoutes()
	}

	// ── Device enrollment / mTLS key setup ──────────────────────────
	// If cert_file/key_file are set, use static files (legacy mode).
	// Otherwise, use TPM-backed enrollment to obtain a certificate.
	var enrollResult *tpmauth.EnrollmentResult
	var keyMgr *tpmauth.KeyManager

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		slog.Info("Using static certificate files (legacy mode)", "cert", cfg.CertFile, "key", cfg.KeyFile)
	} else {
		// TPM / software enrollment flow
		dataDir := cfg.DataDir
		if dataDir == "" {
			dataDir = "./data"
		}

		km, err := tpmauth.NewKeyManager(dataDir)
		if err != nil {
			slog.Error("Key manager init failed", "error", err)
			os.Exit(1)
		}
		keyMgr = km

		cloudURL := cfg.CloudURL
		if cloudURL == "" {
			slog.Error("cloud_url is required for enrollment (or set cert_file/key_file for static certs)")
			os.Exit(1)
		}

		deviceID := cfg.DeviceID
		if deviceID == "" {
			var err error
			deviceID, err = km.DeviceFingerprint()
			if err != nil {
				slog.Warn("Failed to derive device ID from TPM/MachineGuid, falling back to hostname", "error", err)
				deviceID, _ = os.Hostname()
			}
		}
		hostname, _ := os.Hostname()

		// Enrollment with 5-minute timeout — user authenticates in browser
		enrollCtx, enrollCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		result, err := tpmauth.EnrollAndWait(enrollCtx, km, cloudURL, cfg.CAFile, cfg.CloudCertSHA256, deviceID, hostname, dataDir)
		enrollCancel()
		if err != nil {
			slog.Error("Enrollment failed", "error", err)
			os.Exit(1)
		}
		enrollResult = result
		slog.Info("Device enrolled", "tpm", km.IsTPM())

		// Start background auto-renewal for short-lived certs (24h validity, renew at 12h)
		go tpmauth.StartAutoRenewal(context.Background(), km, cloudURL, cfg.CAFile, cfg.CloudCertSHA256, deviceID, hostname, dataDir)
	}

	// Root context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TLS Tunnel to Gateway — with graceful retry at startup
	tun_ := connectWithRetry(cfg, keyMgr, enrollResult, 5)

	// Magic DNS Resolver
	dnsResolver := dns.New(cfg, tun_)
	if err := dnsResolver.Start(); err != nil {
		slog.Warn("DNS resolver failed to start", "error", err)
	} else {
		defer dnsResolver.Stop()
	}

	// Configure Windows NRPT (Name Resolution Policy Table) so that
	// queries for *.lab.local are sent to our Magic DNS resolver instead
	// of the default system resolver. This is the standard ZTNA approach.
	if cfg.InternalSuffix != "" {
		setupNRPT(cfg.InternalSuffix, cfg.DNSListenAddr)
		defer removeNRPT(cfg.InternalSuffix)
	}

	// Connection tracker for TCP flows
	tracker := newConnTracker()
	defer tracker.closeAll()

	// Health-monitoring goroutine — reconnects on tunnel drop
	if tun_ != nil {
		go tunnelHealthLoop(ctx, tun_)
	}

	// TUN Packet Capture & Forwarding
	if tunDev != nil && tun_ != nil {
		go tunPacketLoop(ctx, tunDev, tun_, tracker)
	}

	// Wait for shutdown signal
	printStatus(cfg, tunDev != nil)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	slog.Info("Shutting down...")
	cancel()
}

// connectWithRetry attempts to create and connect the TLS tunnel with exponential backoff
func connectWithRetry(cfg *config.Config, keyMgr *tpmauth.KeyManager, enrollResult *tpmauth.EnrollmentResult, maxAttempts int) *tunnel.Tunnel {
	backoff := 1 * time.Second
	serverName := resolveServerName(cfg.PEPAddress, cfg.ServerName)

	for i := 0; i < maxAttempts; i++ {
		var tun_ *tunnel.Tunnel
		var err error

		if enrollResult != nil && keyMgr != nil {
			// Enrollment-based: use TPM/software signer + enrollment cert
			// Combine enrollment CA (signs client certs) + infra CA (signs gateway TLS cert)
			caPEM := enrollResult.CAPEM
			if cfg.CAFile != "" {
				if infraCA, err := os.ReadFile(cfg.CAFile); err == nil {
					caPEM = append(caPEM, infraCA...)
				}
			}
			tun_, err = tunnel.NewWithSigner(cfg.PEPAddress, enrollResult.CertPEM, caPEM, keyMgr.Signer(), serverName)
		} else {
			// Legacy: static cert files
			tun_, err = tunnel.New(cfg.PEPAddress, cfg.CertFile, cfg.KeyFile, cfg.CAFile, serverName)
		}

		if err != nil {
			slog.Warn("TLS tunnel config failed", "attempt", i+1, "max", maxAttempts, "error", err)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 15*time.Second {
				backoff = 15 * time.Second
			}
			continue
		}

		if err := tun_.Connect(); err != nil {
			slog.Warn("TLS tunnel connection failed", "attempt", i+1, "max", maxAttempts, "error", err)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 15*time.Second {
				backoff = 15 * time.Second
			}
			continue
		}

		slog.Info("TLS tunnel connected to Gateway")
		return tun_
	}

	slog.Error("Could not establish tunnel after retries, running in degraded mode", "attempts", maxAttempts)
	return nil
}

func resolveServerName(pepAddr, configured string) string {
	if strings.TrimSpace(configured) != "" {
		return strings.TrimSpace(configured)
	}
	host, _, err := net.SplitHostPort(pepAddr)
	if err == nil && host != "" {
		return host
	}
	return pepAddr
}

// tunnelHealthLoop checks tunnel connectivity periodically and reconnects on drop
func tunnelHealthLoop(ctx context.Context, tun_ *tunnel.Tunnel) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !tun_.IsConnected() {
				slog.Warn("Tunnel disconnected, attempting reconnect...")
				if err := tun_.Reconnect(5); err != nil {
					slog.Error("Reconnect failed", "error", err)
				} else {
					slog.Info("Tunnel reconnected successfully")
				}
			}
		}
	}
}

// tunPacketLoop reads IP packets from the TUN device and dispatches TCP handling.
// Instead of forwarding raw IP packets, it implements a userspace TCP proxy:
// SYN → open yamux stream + SYN-ACK; data → extract payload → yamux; yamux → TCP/IP → TUN.
func tunPacketLoop(ctx context.Context, dev *tun.NetworkDevice, tun_ *tunnel.Tunnel, tracker *connTracker) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		packet, err := dev.ReadPacket()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("TUN read error", "error", err)
			return
		}

		if len(packet) < 20 || packet[9] != 6 { // Only handle TCP
			continue
		}

		srcIP, dstIP, srcPort, dstPort, seq, _, flags, payload, parseErr := tcpproxy.ParsePacket(packet)
		if parseErr != nil {
			continue
		}

		key := connKey{srcPort: int(srcPort), dstIP: dstIP.String(), dstPort: int(dstPort)}

		switch {
		case flags&tcpproxy.FlagRST != 0:
			slog.Debug("TCP RST", "src", fmt.Sprintf("%s:%d", srcIP, srcPort), "dst", fmt.Sprintf("%s:%d", dstIP, dstPort))
			tracker.remove(key)

		case flags&tcpproxy.FlagSYN != 0 && flags&tcpproxy.FlagACK == 0:
			slog.Debug("TCP SYN", "src", fmt.Sprintf("%s:%d", srcIP, srcPort), "dst", fmt.Sprintf("%s:%d", dstIP, dstPort))
			go handleSYN(tun_, dev, tracker, key, srcIP, dstIP, srcPort, dstPort, seq)

		case len(payload) > 0:
			slog.Debug("TCP DATA", "src", fmt.Sprintf("%s:%d", srcIP, srcPort), "dst", fmt.Sprintf("%s:%d", dstIP, dstPort), "bytes", len(payload))
			handleTCPData(dev, tracker, key, seq, payload)
			if flags&tcpproxy.FlagFIN != 0 {
				slog.Debug("TCP FIN+DATA", "src", fmt.Sprintf("%s:%d", srcIP, srcPort), "dst", fmt.Sprintf("%s:%d", dstIP, dstPort))
				handleFIN(dev, tracker, key, seq+uint32(len(payload)))
			}

		case flags&tcpproxy.FlagFIN != 0:
			slog.Debug("TCP FIN", "src", fmt.Sprintf("%s:%d", srcIP, srcPort), "dst", fmt.Sprintf("%s:%d", dstIP, dstPort))
			handleFIN(dev, tracker, key, seq)

		default:
			// Pure ACK — complete handshake
			slog.Debug("TCP ACK", "src", fmt.Sprintf("%s:%d", srcIP, srcPort), "dst", fmt.Sprintf("%s:%d", dstIP, dstPort))
			handleTCPAck(tracker, key)
		}
	}
}

// handleSYN processes a TCP SYN: opens a yamux stream to the gateway, then
// sends SYN-ACK back through the TUN device.
func handleSYN(tun_ *tunnel.Tunnel, dev *tun.NetworkDevice, tracker *connTracker, key connKey, srcIP, dstIP net.IP, srcPort, dstPort uint16, clientISN uint32) {
	ac, isNew := tracker.getOrCreate(key)
	if !isNew {
		return // already handling this flow
	}

	flow := tcpproxy.NewFlow(srcIP, dstIP, srcPort, dstPort)
	ac.mu.Lock()
	ac.flow = flow
	ac.mu.Unlock()

	// Open yamux stream to gateway
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stream, err := tun_.OpenResourceStream(ctx, key.dstIP, key.dstPort)
	cancel()

	if err != nil {
		var authErr *tunnel.ErrAuthRequired
		if errors.As(err, &authErr) {
			slog.Info("Gateway requires authentication", "dst", key.dstIP, "port", key.dstPort)
			triggerAuth(authErr.AuthURL)

			ac.mu.Lock()
			if !ac.pendingAuth {
				ac.pendingAuth = true
				ac.pendingSince = time.Now()
				ac.pendingSyn = true
				ac.pendingClientISN = clientISN
				ac.mu.Unlock()
				go waitForAuthAndConnect(tun_, dev, tracker, key)
			} else {
				ac.mu.Unlock()
			}
			return
		}

		slog.Warn("Failed to open resource stream", "dst", key.dstIP, "port", key.dstPort, "error", err)
		rst := tcpproxy.BuildRST(srcIP, dstIP, srcPort, dstPort, clientISN+1)
		dev.WritePacket(rst)
		tracker.remove(key)
		return
	}

	ac.mu.Lock()
	ac.stream = stream
	ac.mu.Unlock()
	resetAuthOnce()
	slog.Info("TCP flow established via yamux", "dst", key.dstIP, "port", key.dstPort)

	// Complete the TCP 3-way handshake now that the stream is ready.
	synAck := flow.HandleSYN(clientISN)
	dev.WritePacket(synAck)
	slog.Debug("TCP SYN-ACK sent", "dst", fmt.Sprintf("%s:%d", dstIP, dstPort))

	// Start reader goroutine: yamux stream → TUN device
	go streamToTUN(dev, stream, flow, tracker, key)
}

// handleTCPData extracts TCP payload, ACKs the client, and writes the payload
// to the yamux stream (gateway will relay it to the internal resource).
func handleTCPData(dev *tun.NetworkDevice, tracker *connTracker, key connKey, seq uint32, payload []byte) {
	ac := tracker.get(key)
	if ac == nil || ac.flow == nil {
		return
	}

	ackPkt, data := ac.flow.HandleData(seq, payload)
	if ackPkt != nil {
		dev.WritePacket(ackPkt)
	}
	if len(data) > 0 {
		ac.mu.Lock()
		stream := ac.stream
		closed := ac.closed
		if stream == nil {
			// Buffer data until auth completes.
			if ac.bufferedBytes+len(data) > maxPendingBufferBytes {
				ac.mu.Unlock()
				slog.Warn("Pending auth buffer full, closing flow", "dst", key.dstIP, "port", key.dstPort)
				tracker.remove(key)
				return
			}
			buf := make([]byte, len(data))
			copy(buf, data)
			ac.buffer = append(ac.buffer, buf)
			ac.bufferedBytes += len(buf)
			slog.Debug("Buffered TCP data pending auth", "dst", fmt.Sprintf("%s:%d", key.dstIP, key.dstPort), "bytes", len(buf), "buffered_bytes", ac.bufferedBytes)
			ac.mu.Unlock()
			return
		}
		ac.mu.Unlock()
		if closed {
			return
		}
		_, err := stream.Write(data)
		if err != nil {
			slog.Debug("Yamux write error", "error", err)
			tracker.remove(key)
		}
	}
}

// handleTCPAck processes a pure ACK (e.g., completing the 3-way handshake).
func handleTCPAck(tracker *connTracker, key connKey) {
	ac := tracker.get(key)
	if ac == nil || ac.flow == nil {
		return
	}
	ac.flow.HandleACK()
	slog.Debug("TCP handshake complete (ACK)", "dst", fmt.Sprintf("%s:%d", key.dstIP, key.dstPort))
}

// handleFIN processes a client FIN — sends FIN-ACK and tears down the flow.
func handleFIN(dev *tun.NetworkDevice, tracker *connTracker, key connKey, seq uint32) {
	ac := tracker.get(key)
	if ac == nil || ac.flow == nil {
		return
	}
	finAck := ac.flow.HandleFIN(seq)
	if finAck != nil {
		dev.WritePacket(finAck)
	}
	slog.Debug("TCP FIN-ACK sent", "dst", fmt.Sprintf("%s:%d", key.dstIP, key.dstPort))
	tracker.remove(key)
}

// streamToTUN reads TCP payload bytes from the yamux stream, wraps them in
// TCP/IP packets with correct headers and checksums, and injects into TUN.
func streamToTUN(dev *tun.NetworkDevice, stream net.Conn, flow *tcpproxy.Flow, tracker *connTracker, key connKey) {
	defer func() {
		// Send FIN to client when gateway/resource closes the stream
		finPkt := flow.BuildFIN()
		dev.WritePacket(finPkt)
		tracker.remove(key)
	}()

	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			pkts := flow.BuildDataPackets(buf[:n])
			for _, pkt := range pkts {
				if wErr := dev.WritePacket(pkt); wErr != nil {
					slog.Warn("TUN write error", "error", wErr)
					return
				}
			}
			slog.Debug("TCP data to client", "dst", fmt.Sprintf("%s:%d", key.dstIP, key.dstPort), "bytes", n)
		}
		if err != nil {
			if err != io.EOF {
				slog.Debug("Yamux read error", "dst", key.dstIP, "port", key.dstPort, "error", err)
			}
			return
		}
	}
}

// waitForAuthAndConnect retries opening the resource stream until OIDC completes or timeout.
func waitForAuthAndConnect(tun_ *tunnel.Tunnel, dev *tun.NetworkDevice, tracker *connTracker, key connKey) {
	deadline := time.Now().Add(maxAuthWait)
	backoff := 2 * time.Second

	for time.Now().Before(deadline) {
		ac := tracker.get(key)
		if ac == nil {
			return
		}

		ac.mu.Lock()
		if ac.closed {
			ac.mu.Unlock()
			return
		}
		if ac.stream != nil {
			ac.mu.Unlock()
			return
		}
		ac.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		stream, err := tun_.OpenResourceStream(ctx, key.dstIP, key.dstPort)
		cancel()

		if err == nil {
			ac.mu.Lock()
			if ac.closed {
				ac.mu.Unlock()
				stream.Close()
				return
			}
			ac.stream = stream
			ac.pendingAuth = false
			pendingSyn := ac.pendingSyn
			clientISN := ac.pendingClientISN
			ac.pendingSyn = false
			buffered := ac.buffer
			bufferedBytes := ac.bufferedBytes
			ac.buffer = nil
			ac.bufferedBytes = 0
			ac.mu.Unlock()

			resetAuthOnce()
			slog.Info("Auth complete, TCP flow authorized", "dst", key.dstIP, "port", key.dstPort, "buffered_bytes", bufferedBytes)

			if pendingSyn {
				synAck := ac.flow.HandleSYN(clientISN)
				dev.WritePacket(synAck)
				slog.Debug("TCP SYN-ACK sent (post-auth)", "dst", fmt.Sprintf("%s:%d", key.dstIP, key.dstPort))
			}

			go streamToTUN(dev, stream, ac.flow, tracker, key)

			for _, b := range buffered {
				if _, werr := stream.Write(b); werr != nil {
					slog.Debug("Yamux write error after auth", "error", werr)
					tracker.remove(key)
					return
				}
			}
			return
		}

		var authErr *tunnel.ErrAuthRequired
		if errors.As(err, &authErr) {
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}

		slog.Warn("Retry open resource stream failed", "dst", key.dstIP, "port", key.dstPort, "error", err)
		time.Sleep(backoff)
		if backoff < 10*time.Second {
			backoff *= 2
		}
	}

	slog.Warn("Auth wait timeout, closing flow", "dst", key.dstIP, "port", key.dstPort)
	tracker.remove(key)
}

// Auth handling — resettable sync.Once
var (
	oidcAuthOnce = &sync.Once{}
	oidcAuthMu   sync.Mutex
)

func resetAuthOnce() {
	oidcAuthMu.Lock()
	oidcAuthOnce = &sync.Once{}
	oidcAuthMu.Unlock()
}

func isValidAuthURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != ""
}

func triggerAuth(authURL string) {
	oidcAuthMu.Lock()
	once := oidcAuthOnce
	oidcAuthMu.Unlock()

	once.Do(func() {
		if !isValidAuthURL(authURL) {
			slog.Warn("Rejected invalid auth URL", "url", authURL)
			return
		}
		if openErr := openBrowser(authURL); openErr != nil {
			slog.Warn("Could not open browser automatically", "error", openErr)
		} else {
			slog.Info("Browser opened for authentication")
		}
	})
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func printStatus(cfg *config.Config, tunActive bool) {
	slog.Info("──────────────────────────────")
	if tunActive {
		slog.Info("Status", "tun", cfg.TUNName, "ip", cfg.TUNIP)
		slog.Info("Status", "route", cfg.CGNATRange)
	} else {
		slog.Info("Status", "tun", "disabled")
	}
	slog.Info("Status", "dns", cfg.DNSListenAddr)
	slog.Info("Status", "internal", "*."+cfg.InternalSuffix)
	slog.Info("Status", "pep", cfg.PEPAddress)
	slog.Info("──────────────────────────────")
}

// setupNRPT adds a Windows NRPT rule so that queries for the internal suffix
// (e.g. .lab.local) are resolved by the Magic DNS resolver at 127.0.0.1.
// This is the standard approach used by ZTNA and split-tunnel VPN clients.
func setupNRPT(suffix, dnsAddr string) {
	// Extract just the IP (without port)
	host, _, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		host = dnsAddr
	}

	nrptPath := fmt.Sprintf(`HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\ZTNA-%s`, suffix)
	cmds := []struct {
		name string
		args []string
	}{
		{"reg", []string{"add", nrptPath, "/v", "Name", "/t", "REG_MULTI_SZ", "/d", "." + suffix, "/f"}},
		{"reg", []string{"add", nrptPath, "/v", "GenericDNSServers", "/t", "REG_SZ", "/d", host, "/f"}},
		{"reg", []string{"add", nrptPath, "/v", "ConfigOptions", "/t", "REG_DWORD", "/d", "0x8", "/f"}},
		{"reg", []string{"add", nrptPath, "/v", "Version", "/t", "REG_DWORD", "/d", "0x2", "/f"}},
	}

	for _, c := range cmds {
		cmd := exec.Command(c.name, c.args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("NRPT setup failed", "cmd", c.args, "error", err, "output", string(out))
			return
		}
	}

	// Flush DNS cache to pick up the new rule
	exec.Command("ipconfig", "/flushdns").Run()

	slog.Info("NRPT rule added", "suffix", "."+suffix, "dns", host)
}

// removeNRPT removes the NRPT rule created by setupNRPT.
func removeNRPT(suffix string) {
	nrptPath := fmt.Sprintf(`HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\ZTNA-%s`, suffix)
	cmd := exec.Command("reg", "delete", nrptPath, "/f")
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("NRPT removal failed", "error", err, "output", string(out))
	} else {
		slog.Info("NRPT rule removed", "suffix", "."+suffix)
	}

	exec.Command("ipconfig", "/flushdns").Run()
}
