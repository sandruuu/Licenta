package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "connect-app/logger"

	"connect-app/appid"
	"connect-app/config"
	"connect-app/dns"
	nativeoidc "connect-app/oidc"
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

	// process identity captured at TCP SYN time
	process *tunnel.ProcessIdentity
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
	runtimeDeviceID := strings.TrimSpace(cfg.DeviceID)

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

		// S5.1 — clock-skew sanity check. Certificate validation,
		// JWT exp, and TOTP all break silently when the local clock
		// drifts. Compare against the cloud's HTTP Date header and
		// log a warning above 60s; refuse enrollment above 5 minutes
		// since the issued cert's NotBefore would be in the future.
		if skew, err := checkClockSkew(cloudURL, cfg.CAFile); err == nil {
			abs := skew
			if abs < 0 {
				abs = -abs
			}
			switch {
			case abs > 5*time.Minute:
				slog.Error("System clock is too far out of sync with cloud — fix NTP before enrolling", "skew", skew)
				os.Exit(1)
			case abs > time.Minute:
				slog.Warn("System clock differs from cloud server", "skew", skew)
			default:
				slog.Debug("Clock skew within tolerance", "skew", skew)
			}
		} else {
			slog.Warn("Clock skew check failed (continuing anyway)", "error", err)
		}

		deviceID := runtimeDeviceID
		if deviceID == "" {
			var err error
			deviceID, err = km.DeviceFingerprint()
			if err != nil {
				slog.Warn("Failed to derive device ID from TPM/MachineGuid, falling back to hostname", "error", err)
				deviceID, _ = os.Hostname()
			}
		}
		runtimeDeviceID = deviceID
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
	if runtimeDeviceID == "" {
		runtimeDeviceID, _ = os.Hostname()
	}

	// Root context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// S5.3 — mutual watchdog. Expose a tiny loopback /watchdog
	// endpoint so device-health-app can detect when connect-app is
	// not running, and start a poller in the other direction.
	go startWatchdogServer(ctx)
	go startWatchdogClient(ctx, "http://127.0.0.1:12080/health", "device-health-app")

	// TLS Tunnel to Gateway — with graceful retry at startup
	tun_ := connectWithRetry(cfg, keyMgr, enrollResult, 5)
	if tun_ != nil {
		if err := configureUserOIDC(cfg, tun_, runtimeDeviceID); err != nil {
			slog.Error("OIDC user authentication setup failed", "error", err)
			os.Exit(1)
		}
	}

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
	process := processIdentityForFlow(srcIP, srcPort, dstIP, dstPort)
	ac.mu.Lock()
	ac.flow = flow
	ac.process = process
	ac.mu.Unlock()

	// Open yamux stream to gateway
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stream, err := tun_.OpenResourceStreamWithProcess(ctx, key.dstIP, key.dstPort, process)
	cancel()

	if err != nil {
		var authErr *tunnel.ErrAuthRequired
		if errors.As(err, &authErr) {
			slog.Info("Gateway requires authentication", "dst", key.dstIP, "port", key.dstPort)
			triggerAuth(authErr)

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
	slog.Info("TCP flow established via yamux", "dst", key.dstIP, "port", key.dstPort, "process", processLogName(process))

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

func processIdentityForFlow(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) *tunnel.ProcessIdentity {
	identity, err := appid.LookupTCPProcess(appid.FlowKey{
		LocalIP:    srcIP,
		LocalPort:  srcPort,
		RemoteIP:   dstIP,
		RemotePort: dstPort,
	})
	if err != nil {
		slog.Debug("Process identity lookup failed", "src", fmt.Sprintf("%s:%d", srcIP, srcPort), "dst", fmt.Sprintf("%s:%d", dstIP, dstPort), "error", err)
		return nil
	}
	if identity == nil {
		return nil
	}
	return &tunnel.ProcessIdentity{
		PID:    int(identity.PID),
		Name:   identity.Name,
		Path:   identity.Path,
		SHA256: identity.SHA256,
		Signer: identity.Signer,
	}
}

func processLogName(process *tunnel.ProcessIdentity) string {
	if process == nil {
		return "unknown"
	}
	if process.Name != "" {
		return process.Name
	}
	if process.Path != "" {
		return process.Path
	}
	if process.PID != 0 {
		return fmt.Sprintf("pid:%d", process.PID)
	}
	return "unknown"
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
		process := ac.process
		ac.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		stream, err := tun_.OpenResourceStreamWithProcess(ctx, key.dstIP, key.dstPort, process)
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
			slog.Info("Auth complete, TCP flow authorized", "dst", key.dstIP, "port", key.dstPort, "process", processLogName(process), "buffered_bytes", bufferedBytes)

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
			triggerAuth(authErr)
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
	userOIDC     *nativeoidc.Authenticator
)

func configureUserOIDC(cfg *config.Config, tun_ *tunnel.Tunnel, deviceID string) error {
	issuer := strings.TrimSpace(cfg.OIDCIssuerURL)
	if issuer == "" {
		issuer = strings.TrimSpace(cfg.CloudURL)
	}
	hostname, _ := os.Hostname()
	authn, err := nativeoidc.NewAuthenticator(nativeoidc.Config{
		IssuerURL:   issuer,
		ClientID:    cfg.OIDCClientID,
		Scopes:      cfg.OIDCScopes,
		DeviceID:    deviceID,
		Hostname:    hostname,
		CAFile:      cfg.CAFile,
		OpenBrowser: openBrowser,
	})
	if err != nil {
		return err
	}
	userOIDC = authn
	tun_.SetAuthProvider(func() (string, string) {
		return authn.CurrentAccessToken(), authn.DeviceID()
	})
	return nil
}

func resetAuthOnce() {
	oidcAuthMu.Lock()
	oidcAuthOnce = &sync.Once{}
	oidcAuthMu.Unlock()
}

func triggerAuth(authErr *tunnel.ErrAuthRequired) {
	oidcAuthMu.Lock()
	once := oidcAuthOnce
	oidcAuthMu.Unlock()

	once.Do(func() {
		if userOIDC == nil {
			slog.Warn("OIDC authenticator is not configured")
			return
		}
		acrValues := ""
		if authErr != nil {
			acrValues = authErr.ACRValues
			if authErr.Code == tunnel.CodeMFARequired && acrValues == "" {
				acrValues = "urn:ztna:loa:2"
			}
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), maxAuthWait)
			defer cancel()
			if _, err := userOIDC.Authenticate(ctx, acrValues); err != nil {
				slog.Warn("OIDC authentication failed", "error", err)
			} else {
				slog.Info("OIDC authentication completed")
			}
		}()
	})
}

// checkClockSkew returns local-clock minus cloud-clock by parsing the
// HTTP Date header from a cheap HEAD request. Network round-trip is
// included in the skew (a few ms) and ignored — the thresholds we
// alert on are seconds-to-minutes wide.
func checkClockSkew(cloudURL, caFile string) (time.Duration, error) {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		if pem, err := os.ReadFile(caFile); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tlsConf.RootCAs = pool
			}
		}
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}
	req, err := http.NewRequest(http.MethodHead, strings.TrimRight(cloudURL, "/")+"/healthz", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	dateHdr := resp.Header.Get("Date")
	if dateHdr == "" {
		return 0, fmt.Errorf("no Date header in cloud response")
	}
	cloudTime, err := http.ParseTime(dateHdr)
	if err != nil {
		return 0, err
	}
	return time.Since(cloudTime), nil
}

// startWatchdogServer exposes a 200 OK endpoint on loopback so the
// sibling device-health-app can detect when connect-app is alive.
func startWatchdogServer(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/watchdog", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: "127.0.0.1:12082", Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Warn("Watchdog server failed", "error", err)
	}
}

// startWatchdogClient polls a sibling process every 30s and logs a
// warning after three consecutive failures (so a transient blip does
// not flap). The expectation is operators wire this log into their
// alerting pipeline; auto-restart is left to the OS service manager.
func startWatchdogClient(ctx context.Context, target, name string) {
	client := &http.Client{Timeout: 3 * time.Second}
	consecutiveFailures := 0
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode >= 500 {
				if resp != nil {
					resp.Body.Close()
				}
				consecutiveFailures++
				if consecutiveFailures == 3 {
					slog.Warn("Sibling watchdog failing", "sibling", name, "target", target, "consecutive_failures", consecutiveFailures)
				}
			} else {
				resp.Body.Close()
				if consecutiveFailures >= 3 {
					slog.Info("Sibling watchdog recovered", "sibling", name)
				}
				consecutiveFailures = 0
			}
		}
	}
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
