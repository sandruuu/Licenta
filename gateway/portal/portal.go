// Package portal implements the gateway data plane (PEP).
// It handles TLS connections from connect-app, manages yamux sessions,
// validates authentication via the cloud, enforces access policies,
// and relays traffic to internal resources.
package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/anomaly"
	"gateway/internal/auth"
	"gateway/internal/cgnat"
	"gateway/internal/config"
	"gateway/internal/dns"
	"gateway/internal/models"
	"gateway/internal/relay"
	"gateway/sessionstore"
	"gateway/store"
	"gateway/syslog"

	"github.com/hashicorp/yamux"
)

// Portal is the data plane PEP
type Portal struct {
	cfg            *config.Config
	cloud          *auth.CloudClient
	sessions       *sessionstore.Client
	relay          *relay.Relay
	dns            *dns.Resolver
	cgnat          *cgnat.Allocator
	syslogClient   *syslog.Client
	store          *store.Store
	oidcCallback   *OIDCCallbackServer
	anomaly        *anomaly.Detector
	revokedSerials sync.Map // cert serial (string) → struct{}

	// Connection limiting
	activeConns    int64 // atomic counter
	maxConnections int64 // max concurrent connections (0 = unlimited)

	// OIDC health tracking
	oidcHealthy atomic.Bool
}

// New creates a new Portal data plane
func New(cfg *config.Config, cloud *auth.CloudClient, sessClient *sessionstore.Client, relayMgr *relay.Relay, dnsResolver *dns.Resolver, cgnatAlloc *cgnat.Allocator, syslogClient *syslog.Client, db *store.Store) *Portal {
	p := &Portal{
		cfg:            cfg,
		cloud:          cloud,
		sessions:       sessClient,
		relay:          relayMgr,
		dns:            dnsResolver,
		cgnat:          cgnatAlloc,
		syslogClient:   syslogClient,
		store:          db,
		anomaly:        anomaly.New(),
		maxConnections: 1000,
	}
	p.oidcHealthy.Store(true)

	// Initialize OIDC callback server (Gateway as Relying Party)
	if cfg.AuthSource != nil && cfg.AuthSource.AuthURL != "" {
		p.oidcCallback = NewOIDCCallbackServer(cfg, cloud, sessClient, syslogClient)
	}

	return p
}

// ListenAndServe starts the portal TLS/TCP listener
func (p *Portal) ListenAndServe() error {
	var listener net.Listener
	var err error

	if p.cfg.TLSCert != "" && p.cfg.TLSKey != "" {
		// TLS mode
		cert, err := tls.LoadX509KeyPair(p.cfg.TLSCert, p.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("load TLS cert: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}

		// Add CA for client cert validation if configured
		clientCAPath := strings.TrimSpace(p.cfg.ClientCA)
		if clientCAPath == "" {
			clientCAPath = strings.TrimSpace(p.cfg.TLSCA)
		}
		if clientCAPath != "" {
			caCert, err := os.ReadFile(clientCAPath)
			if err != nil {
				log.Printf("[PORTAL] Warning: could not read client CA file %s: %v", clientCAPath, err)
			} else {
				// Also fetch Cloud's internal CA (signs enrollment client certs)
				if cloudCA, err := p.cloud.GetCACert(); err == nil && len(cloudCA) > 0 {
					caCert = append(caCert, cloudCA...)
					log.Printf("[PORTAL] Added Cloud CA to client cert pool")
				} else if err != nil {
					log.Printf("[PORTAL] Warning: could not fetch Cloud CA: %v", err)
				}
				caCertPool := x509.NewCertPool()
				if caCertPool.AppendCertsFromPEM(caCert) {
					tlsConfig.ClientCAs = caCertPool
					if p.cfg.RequireClientCert {
						tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
					} else {
						tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
						if !p.cfg.DevMode {
							log.Printf("[PORTAL] ⚠ WARNING: require_client_cert is disabled in production — device identity enforcement weakened")
						}
					}
					// VerifyConnection callback — reject revoked certificate serials
					tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
						if len(cs.PeerCertificates) > 0 {
							serial := cs.PeerCertificates[0].SerialNumber.String()
							if _, revoked := p.revokedSerials.Load(serial); revoked {
								log.Printf("[PORTAL] Rejected revoked certificate serial %s", serial)
								return fmt.Errorf("certificate serial %s is revoked", serial)
							}
						}
						return nil
					}
				} else {
					log.Printf("[PORTAL] Warning: could not parse client CA file %s", clientCAPath)
				}
			}
		} else if p.cfg.RequireClientCert {
			return fmt.Errorf("require_client_cert is enabled but no client CA is configured")
		}

		listener, err = tls.Listen("tcp", p.cfg.ListenAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS listen: %w", err)
		}
		log.Printf("[PORTAL] TLS listener on %s", p.cfg.ListenAddr)
	} else {
		// Plain TCP (development mode)
		listener, err = net.Listen("tcp", p.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("TCP listen: %w", err)
		}
		log.Printf("[PORTAL] TCP listener on %s (development mode — no TLS)", p.cfg.ListenAddr)
	}

	p.syslogClient.Info("portal.start", fmt.Sprintf("Portal data plane listening on %s", p.cfg.ListenAddr), map[string]string{
		"tls": fmt.Sprintf("%v", p.cfg.TLSCert != ""),
	})

	// Start background revoked-serials sync (BeyondCorp model)
	p.syncRevokedSerials()
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			p.syncRevokedSerials()
		}
	}()

	// Start background resource sync from cloud (2-minute interval)
	p.syncResources()
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			p.syncResources()
		}
	}()

	// Start certificate expiration monitoring
	p.checkCertExpiry() // initial check at startup
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			p.checkCertExpiry()
		}
	}()

	// Start OIDC callback HTTPS server on a separate port (default :443 or configured)
	if p.oidcCallback != nil {
		callbackAddr := ":443"
		if p.cfg.AuthSource != nil && p.cfg.AuthSource.CallbackListenAddr != "" {
			callbackAddr = p.cfg.AuthSource.CallbackListenAddr
		}
		go func() {
			if err := p.oidcCallback.ListenAndServe(callbackAddr); err != nil {
				p.oidcHealthy.Store(false)
				log.Printf("[PORTAL] OIDC callback server error: %v", err)
				p.syslogClient.Error("portal.oidc_down", "OIDC callback server failed", map[string]string{
					"error": err.Error(),
				})
			}
		}()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[PORTAL] Accept error: %v", err)
			continue
		}

		// Enforce connection limit
		if p.maxConnections > 0 && atomic.LoadInt64(&p.activeConns) >= p.maxConnections {
			log.Printf("[PORTAL] Connection limit reached (%d), rejecting %s", p.maxConnections, conn.RemoteAddr())
			p.syslogClient.Warn("portal.conn_limit", fmt.Sprintf("Connection rejected: limit %d reached", p.maxConnections), map[string]string{
				"remote_addr": conn.RemoteAddr().String(),
			})
			conn.Close()
			continue
		}
		atomic.AddInt64(&p.activeConns, 1)
		go p.handleConnection(conn)
	}
}

// handleConnection manages a single connect-app connection via yamux
func (p *Portal) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer atomic.AddInt64(&p.activeConns, -1)
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[PORTAL] New connection from %s", remoteAddr)

	p.syslogClient.Info("portal.connection", fmt.Sprintf("New connection from %s", remoteAddr), map[string]string{
		"remote_addr": remoteAddr,
	})

	// Create yamux server session with secure defaults
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.MaxStreamWindowSize = 256 * 1024 // 256 KB per stream
	yamuxCfg.StreamOpenTimeout = 30 * time.Second
	yamuxCfg.StreamCloseTimeout = 5 * time.Minute
	session, err := yamux.Server(conn, yamuxCfg)
	if err != nil {
		log.Printf("[PORTAL] Yamux server error: %v", err)
		return
	}
	defer session.Close()

	// Connection state
	state := &connectionState{
		remoteAddr: remoteAddr,
	}

	// Extract device ID from mTLS client certificate CN
	if tlsConn, ok := conn.(*tls.Conn); ok {
		cs := tlsConn.ConnectionState()
		if len(cs.PeerCertificates) > 0 {
			state.certDeviceID = cs.PeerCertificates[0].Subject.CommonName
		}
	}

	// Accept streams from the multiplexed connection
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err != io.EOF {
				log.Printf("[PORTAL] Stream accept error: %v", err)
			}
			break
		}
		go p.handleStream(stream, state)
	}
}

// connectionState tracks authentication state per connection
type connectionState struct {
	mu            sync.RWMutex
	remoteAddr    string
	certDeviceID  string // CN extracted from client mTLS certificate
	authenticated bool
	userID        string
	username      string
	deviceID      string
	authToken     string
	refreshToken  string
	sessionID     string
}

// handleStream processes a single yamux stream
func (p *Portal) handleStream(stream net.Conn, state *connectionState) {
	defer stream.Close()

	// Read the request
	decoder := json.NewDecoder(stream)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		log.Printf("[PORTAL] Stream decode error: %v", err)
		return
	}

	// Determine request type
	var typeCheck struct {
		Type string `json:"type"`
	}
	json.Unmarshal(raw, &typeCheck)

	switch typeCheck.Type {
	case "auth_request":
		var req auth.AuthRequest
		json.Unmarshal(raw, &req)
		p.handleAuthRequest(stream, &req, state)

	case "connect":
		var req auth.ConnectRequest
		json.Unmarshal(raw, &req)
		p.handleConnectRequest(stream, &req, state)

	case "dns_resolve":
		var req auth.DNSResolveRequest
		json.Unmarshal(raw, &req)
		p.handleDNSResolve(stream, &req, state)

	default:
		log.Printf("[PORTAL] Unknown request type: %s", typeCheck.Type)
		json.NewEncoder(stream).Encode(map[string]string{
			"type":    "error",
			"message": "unknown request type",
		})
	}
}

// handleAuthRequest validates a token with the cloud and creates a local session
func (p *Portal) handleAuthRequest(stream net.Conn, req *auth.AuthRequest, state *connectionState) {
	encoder := json.NewEncoder(stream)

	log.Printf("[PORTAL] Auth request from %s (device=%s)", state.remoteAddr, req.DeviceID)

	// Verify device_id from request matches the mTLS certificate CN
	if state.certDeviceID != "" && req.DeviceID != state.certDeviceID {
		log.Printf("[PORTAL] Device ID mismatch: cert=%s req=%s", state.certDeviceID, req.DeviceID)
		p.syslogClient.Warn("auth.device_mismatch", fmt.Sprintf("Device ID mismatch from %s: cert=%s claimed=%s", state.remoteAddr, state.certDeviceID, req.DeviceID), map[string]string{
			"remote_addr":    state.remoteAddr,
			"cert_device_id": state.certDeviceID,
			"claimed_device": req.DeviceID,
		})
		encoder.Encode(auth.AuthResponse{
			Type:    "auth_response",
			Status:  "denied",
			Message: "Device identity mismatch",
		})
		return
	}

	// Reject device identity claims without mTLS proof (Zero Trust: no implicit trust)
	if state.certDeviceID == "" && req.DeviceID != "" {
		log.Printf("[PORTAL] Device ID claimed without client cert: claimed=%s from %s", req.DeviceID, state.remoteAddr)
		p.syslogClient.Warn("auth.device_no_cert", fmt.Sprintf("Device ID claimed without client certificate from %s", state.remoteAddr), map[string]string{
			"remote_addr":    state.remoteAddr,
			"claimed_device": req.DeviceID,
		})
		encoder.Encode(auth.AuthResponse{
			Type:    "auth_response",
			Status:  "denied",
			Message: "Client certificate required for device identity verification",
		})
		return
	}

	// Validate token with cloud
	claims, err := p.cloud.ValidateToken(req.Token)
	if err != nil {
		log.Printf("[PORTAL] Token validation failed: %v", err)
		p.syslogClient.Warn("auth.failed", fmt.Sprintf("Token validation failed from %s: %v", state.remoteAddr, err), map[string]string{
			"remote_addr": state.remoteAddr,
			"device_id":   req.DeviceID,
		})
		encoder.Encode(auth.AuthResponse{
			Type:    "auth_response",
			Status:  "denied",
			Message: "Authentication failed",
		})
		return
	}

	// Extract user info from claims
	userID, _ := claims["user_id"].(string)
	username, _ := claims["username"].(string)

	// Create session in the session store
	sessionID := generateSessionID()
	sess := &models.Session{
		ID:           sessionID,
		UserID:       userID,
		Username:     username,
		DeviceID:     req.DeviceID,
		SourceIP:     state.remoteAddr,
		AuthToken:    req.Token,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(p.cfg.SessionTimeout) * time.Second),
		LastActivity: time.Now(),
		Active:       true,
	}

	if err := p.sessions.Create(sess); err != nil {
		log.Printf("[PORTAL] Session store error: %v", err)
		// Fall through — portal still works even if store is down
	}

	// Update connection state
	state.mu.Lock()
	state.authenticated = true
	state.userID = userID
	state.username = username
	state.deviceID = req.DeviceID
	state.authToken = req.Token
	state.sessionID = sessionID
	state.mu.Unlock()

	log.Printf("[PORTAL] Auth SUCCESS: user=%s session=%s", username, sessionID)
	p.syslogClient.Info("auth.success", fmt.Sprintf("User %s authenticated from %s", username, state.remoteAddr), map[string]string{
		"user_id":    userID,
		"username":   username,
		"device_id":  req.DeviceID,
		"session_id": sessionID,
	})

	encoder.Encode(auth.AuthResponse{
		Type:    "auth_response",
		Status:  "authorized",
		Message: fmt.Sprintf("Welcome, %s! Session: %s", username, sessionID),
	})
}

// handleConnectRequest authorizes and relays traffic to an internal resource
func (p *Portal) handleConnectRequest(stream net.Conn, req *auth.ConnectRequest, state *connectionState) {
	encoder := json.NewEncoder(stream)

	// Check authentication
	state.mu.RLock()
	authenticated := state.authenticated
	userID := state.userID
	username := state.username
	deviceID := state.deviceID
	authToken := state.authToken
	sessionID := state.sessionID
	state.mu.RUnlock()

	if !authenticated {
		// ── OIDC Flow: redirect to Cloud IdP instead of denying ──
		// For TCP protocols (RDP, SSH): return auth_required with auth_url metadata
		// For HTTP/Web: could return HTTP 302 redirect (handled at stream level)
		if p.oidcCallback != nil && p.oidcHealthy.Load() {
			authURL, err := p.oidcCallback.GenerateAuthURL(state)
			if err != nil {
				log.Printf("[PORTAL] Failed to generate auth URL: %v", err)
				encoder.Encode(auth.ConnectResponse{
					Type:    "connect_response",
					Status:  "denied",
					Message: "Authentication required but OIDC is unavailable",
				})
				return
			}

			log.Printf("[PORTAL] Auth required for %s → redirecting to OIDC (state in URL)", state.remoteAddr)
			p.syslogClient.Info("connect.auth_required", fmt.Sprintf("Auth required for %s, OIDC redirect generated", state.remoteAddr), map[string]string{
				"remote_addr": state.remoteAddr,
				"resource":    fmt.Sprintf("%s:%d", req.RemoteAddr, req.RemotePort),
			})

			encoder.Encode(map[string]string{
				"type":     "connect_response",
				"status":   "auth_required",
				"auth_url": authURL,
				"message":  "Authentication required. Please complete login in the browser.",
			})
			return
		}

		// Fallback: no OIDC configured, deny directly
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "denied",
			Message: "Not authenticated — send auth_request first",
		})
		return
	}

	log.Printf("[PORTAL] Connect request: user=%s → %s:%d", username, req.RemoteAddr, req.RemotePort)

	// ── CGNAT tunnel IP resolution ──
	// The connect-app sends a CGNAT address (100.64.x.x) from the dynamic
	// allocation. First try the dynamic CGNAT allocator, then fall back to
	// the static relay mapping for backwards compatibility.
	resolvedIP := req.RemoteAddr
	resolvedPort := req.RemotePort
	cgnatResolved := false

	if p.cgnat != nil {
		if internalIP, port, ok := p.cgnat.Resolve(req.RemoteAddr); ok {
			resolvedIP = internalIP
			resolvedPort = port
			cgnatResolved = true
			// Refresh the TTL on data access (keep-alive)
			p.cgnat.Touch(req.RemoteAddr)
			log.Printf("[PORTAL] CGNAT dynamic resolve: %s → %s:%d", req.RemoteAddr, resolvedIP, resolvedPort)
			p.syslogClient.Info("cgnat.resolve", fmt.Sprintf("Dynamic CGNAT %s → %s:%d", req.RemoteAddr, resolvedIP, resolvedPort), nil)
		} else {
			// Fall back to static config mapping
			resolvedIP = p.relay.ResolveTunnelIP(req.RemoteAddr, req.RemotePort)
		}
	} else {
		resolvedIP = p.relay.ResolveTunnelIP(req.RemoteAddr, req.RemotePort)
	}

	if resolvedIP != req.RemoteAddr {
		log.Printf("[PORTAL] CGNAT resolved %s → %s", req.RemoteAddr, resolvedIP)
		p.syslogClient.Info("cgnat.resolve", fmt.Sprintf("Tunnel %s:%d → %s:%d", req.RemoteAddr, req.RemotePort, resolvedIP, resolvedPort), nil)
	}

	// Check if the resource is known (uses internal IP after resolution)
	if !cgnatResolved && !p.relay.IsResourceAllowed(resolvedIP, resolvedPort) {
		log.Printf("[PORTAL] Resource not found: %s:%d (resolved=%s:%d)", req.RemoteAddr, req.RemotePort, resolvedIP, resolvedPort)
		p.syslogClient.Warn("connect.denied", fmt.Sprintf("Resource not found: %s:%d (resolved=%s:%d)", req.RemoteAddr, req.RemotePort, resolvedIP, resolvedPort), map[string]string{
			"username": username,
			"resource": fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
		})
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "denied",
			Message: "Resource not found or not allowed",
		})
		return
	}

	// Look up the resource config to check Enabled flag and get cloud app ID
	resource, _ := p.store.FindResourceByIP(resolvedIP, resolvedPort)
	if resource == nil {
		resource, _ = p.store.FindResourceByTunnelIP(resolvedIP, resolvedPort)
	}
	if resource == nil {
		log.Printf("[PORTAL] Resource not configured: %s:%d", resolvedIP, resolvedPort)
		p.syslogClient.Warn("connect.denied", fmt.Sprintf("Resource not configured: %s:%d", resolvedIP, resolvedPort), map[string]string{
			"username": username,
			"resource": fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
		})
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "denied",
			Message: "Resource not configured",
		})
		return
	}
	if !resource.Enabled {
		log.Printf("[PORTAL] Resource disabled: %s", resource.Name)
		p.syslogClient.Warn("connect.denied", fmt.Sprintf("Resource disabled: %s", resource.Name), map[string]string{
			"username": username,
			"resource": resource.Name,
		})
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "denied",
			Message: "Application is currently disabled",
		})
		return
	}
	appID := resource.CloudAppID

	// Determine protocol
	protocol := p.relay.GetResourceProtocol(resolvedIP, resolvedPort)

	// Collect anomaly signals for this user to forward to the cloud PDP
	anomalyAlerts, anomalyScore := p.anomaly.GetActiveAlerts(userID)

	// Ask the cloud (PA + PE) to authorize this access request
	decision, err := p.cloud.AuthorizeAccess(
		userID, username, deviceID, state.remoteAddr,
		resolvedIP, resolvedPort, protocol, authToken, appID,
		anomalyAlerts, anomalyScore,
	)
	if err != nil {
		log.Printf("[PORTAL] Authorization request failed: %v", err)
		p.syslogClient.Error("authorize.error", fmt.Sprintf("Authorization service unavailable: %v", err), nil)
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "denied",
			Message: "Authorization service unavailable",
		})
		return
	}

	// Act on the decision
	switch decision.Decision {
	case "allow":
		log.Printf("[PORTAL] Access GRANTED: user=%s → %s:%d (risk=%d)",
			username, resolvedIP, resolvedPort, decision.RiskScore)
		p.syslogClient.Info("access.granted", fmt.Sprintf("Access granted: %s → %s:%d", username, resolvedIP, resolvedPort), map[string]string{
			"username":   username,
			"resource":   fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
			"protocol":   protocol,
			"risk_score": fmt.Sprintf("%d", decision.RiskScore),
		})
		p.anomaly.RecordEvent(anomaly.Event{
			Type:     anomaly.EventConnect,
			UserID:   userID,
			Username: username,
			SourceIP: state.remoteAddr,
			Resource: fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
		})

	case "deny":
		log.Printf("[PORTAL] Access DENIED: user=%s → %s:%d reason=%s",
			username, resolvedIP, resolvedPort, decision.Reason)
		p.syslogClient.Warn("access.denied", fmt.Sprintf("Access denied: %s → %s:%d (%s)", username, resolvedIP, resolvedPort, decision.Reason), map[string]string{
			"username": username,
			"resource": fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
			"reason":   decision.Reason,
		})
		p.anomaly.RecordEvent(anomaly.Event{
			Type:     anomaly.EventAccessDeny,
			UserID:   userID,
			Username: username,
			SourceIP: state.remoteAddr,
			Resource: fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
		})
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "denied",
			Message: decision.Reason,
		})
		return

	case "mfa_required":
		log.Printf("[PORTAL] MFA REQUIRED: user=%s → %s:%d — triggering OIDC MFA step-up",
			username, resolvedIP, resolvedPort)
		p.syslogClient.Warn("access.mfa_required", fmt.Sprintf("MFA required: %s → %s:%d", username, resolvedIP, resolvedPort), map[string]string{
			"username": username,
			"resource": fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
		})

		// Generate OIDC auth URL with mfa_step hint so the login page
		// skips the password step and shows MFA selection directly.
		if p.oidcCallback != nil && p.oidcHealthy.Load() {
			authURL, err := p.oidcCallback.GenerateAuthURL(state)
			if err != nil {
				log.Printf("[PORTAL] Failed to generate MFA step-up URL: %v", err)
				encoder.Encode(auth.ConnectResponse{
					Type:    "connect_response",
					Status:  "denied",
					Message: "MFA required but OIDC is unavailable",
				})
				return
			}
			// Append mfa_step hint for the login page
			authURL += "&mfa_step=true"

			encoder.Encode(map[string]string{
				"type":     "connect_response",
				"status":   "auth_required",
				"auth_url": authURL,
				"message":  "Multi-factor authentication required for this resource",
			})
			return
		}

		// Fallback: no OIDC configured
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "denied",
			Message: "Multi-factor authentication required but OIDC is unavailable",
		})
		return

	default:
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "denied",
			Message: "Unknown policy decision",
		})
		return
	}

	// Connect to internal resource (using resolved internal IP, not tunnel IP)
	targetConn, err := p.relay.Connect(resolvedIP, resolvedPort)
	if err != nil {
		log.Printf("[PORTAL] Relay connect failed: %v", err)
		p.syslogClient.Error("relay.failed", fmt.Sprintf("Relay connection failed: %s:%d — %v", resolvedIP, resolvedPort, err), nil)
		encoder.Encode(auth.ConnectResponse{
			Type:    "connect_response",
			Status:  "error",
			Message: "Failed to connect to internal resource",
		})
		return
	}
	defer targetConn.Close()

	// Send success response
	encoder.Encode(auth.ConnectResponse{
		Type:    "connect_response",
		Status:  "connected",
		Message: fmt.Sprintf("Connected to %s:%d", resolvedIP, resolvedPort),
	})

	// Relay data bidirectionally between connect-app and internal resource
	// with periodic session re-validation (continuous posture check)
	log.Printf("[PORTAL] Relaying: %s ↔ %s:%d", username, resolvedIP, resolvedPort)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream (connect-app) → Target (internal resource)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, stream)
		log.Printf("[PORTAL] client→target: %d bytes", n)
	}()

	// Target → Stream
	go func() {
		defer wg.Done()
		n, _ := io.Copy(stream, targetConn)
		log.Printf("[PORTAL] target→client: %d bytes", n)
	}()

	// Continuous posture re-validation: periodically re-check with cloud
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// Auto-refresh token if close to expiry (within 5 minutes)
				state.mu.RLock()
				currentRefresh := state.refreshToken
				state.mu.RUnlock()

				if currentRefresh != "" && p.cfg.AuthSource != nil {
					// Try to refresh the access token proactively
					newTokens, err := p.cloud.RefreshAccessToken(
						p.cfg.AuthSource.TokenURL,
						p.cfg.AuthSource.ClientID,
						p.cfg.AuthSource.ClientSecret,
						currentRefresh,
					)
					if err != nil {
						log.Printf("[PORTAL] Token refresh failed for %s (will retry): %v", username, err)
					} else {
						state.mu.Lock()
						state.authToken = newTokens.AccessToken
						state.refreshToken = newTokens.RefreshToken
						authToken = newTokens.AccessToken
						state.mu.Unlock()
						log.Printf("[PORTAL] Token refreshed for %s", username)
					}
				}

				_, err := p.cloud.ValidateSession(sessionID)
				if err != nil {
					log.Printf("[PORTAL] Session %s re-validation failed: %v — terminating relay", sessionID, err)
					p.syslogClient.Warn("posture.session_revoked", fmt.Sprintf("Session revoked during relay: %s user=%s", sessionID, username), map[string]string{
						"session_id": sessionID,
						"username":   username,
						"resource":   fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
					})
					// Close both ends to terminate the relay
					stream.Close()
					targetConn.Close()
					return
				}

				// Re-check device posture via AuthorizeAccess
				recheckAlerts, recheckScore := p.anomaly.GetActiveAlerts(userID)
				recheck, err := p.cloud.AuthorizeAccess(
					userID, username, deviceID, state.remoteAddr,
					resolvedIP, resolvedPort, protocol, authToken, appID,
					recheckAlerts, recheckScore,
				)
				if err != nil || recheck.Decision != "allow" {
					reason := "authorization re-check failed"
					if recheck != nil {
						reason = recheck.Reason
					}
					log.Printf("[PORTAL] Posture re-check failed for %s: %s — terminating relay", username, reason)
					p.syslogClient.Warn("posture.recheck_failed", fmt.Sprintf("Posture re-check denied: %s user=%s reason=%s", sessionID, username, reason), map[string]string{
						"session_id": sessionID,
						"username":   username,
						"resource":   fmt.Sprintf("%s:%d", resolvedIP, resolvedPort),
						"reason":     reason,
					})
					stream.Close()
					targetConn.Close()
					return
				}
			}
		}
	}()

	wg.Wait()
	close(done)
	log.Printf("[PORTAL] Relay closed: %s ↔ %s:%d", username, resolvedIP, resolvedPort)
	p.syslogClient.Info("relay.closed", fmt.Sprintf("Relay closed: %s ↔ %s:%d", username, resolvedIP, resolvedPort), nil)
}

// handleDNSResolve processes a DNS resolution request from connect-app.
// When connect-app intercepts a query for an internal domain (e.g.
// bob.external.lab.local), it sends a dns_resolve request over the yamux
// tunnel. The portal:
//  1. Looks up the domain in configured resources (matching by name or suffix)
//  2. Dynamically allocates a CGNAT tunnel IP from the pool
//  3. Returns the CGNAT IP with a TTL so the client can answer the DNS query
//
// This is the core of the "Magic DNS" resolution flow described in the
// ZTNA architecture: the client never needs static IP mappings — everything
// is resolved dynamically through the authenticated tunnel.
func (p *Portal) handleDNSResolve(stream net.Conn, req *auth.DNSResolveRequest, state *connectionState) {
	encoder := json.NewEncoder(stream)

	// DNS resolution is allowed without authentication.
	// It only returns a CGNAT IP mapping — actual access control
	// is enforced at the "connect" step (handleConnectRequest).
	state.mu.RLock()
	username := state.username
	state.mu.RUnlock()
	if username == "" {
		username = "anonymous"
	}

	domain := strings.ToLower(strings.TrimSuffix(req.Domain, "."))
	log.Printf("[PORTAL] DNS resolve request from %s: %s", username, domain)

	// Look up the domain in configured resources.
	// Matching strategy:
	//   - Exact name match: "rdp-server" matches "rdp-server.internal.lab.local"
	//   - The domain's first label is the resource name
	resource, _ := p.store.FindResourceByDomain(domain)
	if resource == nil {
		log.Printf("[PORTAL] DNS resolve: domain %s not found in resources", domain)
		p.syslogClient.Info("dns.resolve.miss", fmt.Sprintf("Domain not found: %s (user: %s)", domain, username), nil)
		encoder.Encode(auth.DNSResolveResponse{
			Type:    "dns_resolve_response",
			Status:  "not_found",
			Domain:  req.Domain,
			Message: "Domain does not match any internal resource",
		})
		return
	}

	if p.cgnat == nil {
		log.Printf("[PORTAL] DNS resolve failed: CGNAT allocator is not enabled")
		encoder.Encode(auth.DNSResolveResponse{
			Type:    "dns_resolve_response",
			Status:  "error",
			Domain:  req.Domain,
			Message: "CGNAT allocator is not enabled on the gateway",
		})
		return
	}

	targetIP, targetPort, err := p.resolveResourceTarget(resource)
	if err != nil {
		log.Printf("[PORTAL] DNS resolve target failed for %s: %v", domain, err)
		p.syslogClient.Warn("dns.resolve.target_invalid", fmt.Sprintf("Target resolution failed for %s: %v", domain, err), nil)
		encoder.Encode(auth.DNSResolveResponse{
			Type:    "dns_resolve_response",
			Status:  "error",
			Domain:  req.Domain,
			Message: "Resource target cannot be resolved via private DNS",
		})
		return
	}

	// Allocate or refresh a CGNAT IP for this resource
	mapping, err := p.cgnat.Allocate(domain, targetIP, targetPort)
	if err != nil {
		log.Printf("[PORTAL] CGNAT allocation failed: %v", err)
		p.syslogClient.Error("cgnat.alloc.fail", fmt.Sprintf("CGNAT allocation failed for %s: %v", domain, err), nil)
		encoder.Encode(auth.DNSResolveResponse{
			Type:    "dns_resolve_response",
			Status:  "error",
			Domain:  req.Domain,
			Message: "CGNAT pool exhausted",
		})
		return
	}

	ttlSeconds := int(time.Until(mapping.ExpiresAt).Seconds())

	log.Printf("[PORTAL] DNS resolved: %s → %s (CGNAT) → %s:%d (internal), TTL %ds",
		domain, mapping.CGNATIP, targetIP, targetPort, ttlSeconds)
	p.syslogClient.Info("dns.resolve.ok", fmt.Sprintf("Resolved %s → %s for user %s", domain, mapping.CGNATIP, username), map[string]string{
		"domain":        domain,
		"cgnat_ip":      mapping.CGNATIP,
		"internal_ip":   targetIP,
		"internal_port": fmt.Sprintf("%d", targetPort),
		"ttl":           fmt.Sprintf("%d", ttlSeconds),
	})

	encoder.Encode(auth.DNSResolveResponse{
		Type:    "dns_resolve_response",
		Status:  "resolved",
		Domain:  req.Domain,
		CGNATIP: mapping.CGNATIP,
		TTL:     ttlSeconds,
	})
}

// resolveResourceTarget returns the effective backend IP:port for a resource.
// If internal_url is configured, the host part is resolved through the gateway
// private DNS resolver; otherwise it falls back to internal_ip/port.
func (p *Portal) resolveResourceTarget(res *config.Resource) (string, int, error) {
	targetIP := strings.TrimSpace(res.InternalIP)
	targetPort := res.Port

	if strings.TrimSpace(res.InternalURL) == "" {
		if targetIP == "" || targetPort <= 0 {
			return "", 0, fmt.Errorf("resource %s has no valid internal target", res.Name)
		}
		return targetIP, targetPort, nil
	}

	host, port, err := parseTargetFromInternalURL(res.InternalURL, res.Port)
	if err != nil {
		return "", 0, fmt.Errorf("invalid internal_url for %s: %w", res.Name, err)
	}

	targetPort = port
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), targetPort, nil
	}

	if p.dns == nil {
		return "", 0, fmt.Errorf("private DNS resolver is not configured")
	}

	resolvedIP, err := p.dns.ResolveHostA(host)
	if err != nil {
		return "", 0, fmt.Errorf("resolve host %s: %w", host, err)
	}

	return resolvedIP, targetPort, nil
}

func parseTargetFromInternalURL(raw string, fallbackPort int) (string, int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", 0, fmt.Errorf("empty internal_url")
	}

	parsed := value
	if !strings.Contains(parsed, "://") {
		parsed = "tcp://" + parsed
	}

	u, err := url.Parse(parsed)
	if err != nil {
		return "", 0, err
	}

	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", 0, fmt.Errorf("missing hostname")
	}

	port := fallbackPort
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %w", err)
		}
		port = p
	}

	if port <= 0 {
		return "", 0, fmt.Errorf("missing target port")
	}

	return strings.ToLower(host), port, nil
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "gw_" + hex.EncodeToString(b)
}

// syncRevokedSerials fetches revoked certificate serials from the cloud and
// rebuilds the local cache used by the VerifyConnection TLS callback.
func (p *Portal) syncRevokedSerials() {
	serials, err := p.cloud.GetRevokedSerials()
	if err != nil {
		log.Printf("[PORTAL] Failed to sync revoked serials: %v", err)
		// If cloud returned 403, our own cert may have been revoked — flush session cache
		if strings.Contains(err.Error(), "403") {
			log.Printf("[PORTAL] Cloud returned 403 — flushing session cache (possible cert revocation)")
			p.cloud.FlushSessionCache()
		}
		return
	}

	// Clear and rebuild
	p.revokedSerials.Range(func(key, _ interface{}) bool {
		p.revokedSerials.Delete(key)
		return true
	})
	for _, s := range serials {
		p.revokedSerials.Store(s, struct{}{})
	}

	if len(serials) > 0 {
		log.Printf("[PORTAL] Synced %d revoked certificate serials", len(serials))
	}
}

// syncResources fetches the gateway's assigned resources from the cloud
// and upserts them into the local SQLite store. Resources removed from
// the cloud are deleted locally to keep the gateway in sync.
func (p *Portal) syncResources() {
	cloudResources, err := p.cloud.GetResources()
	if err != nil {
		log.Printf("[PORTAL] Failed to sync resources from cloud: %v", err)
		return
	}

	localResources, err := p.store.ListResources()
	if err != nil {
		log.Printf("[PORTAL] Failed to list local resources: %v", err)
		return
	}

	// Index local resources by name for fast lookup
	localByName := make(map[string]*config.Resource, len(localResources))
	for i := range localResources {
		localByName[localResources[i].Name] = &localResources[i]
	}

	// Track which cloud resource names we see (for deletion detection)
	cloudNames := make(map[string]struct{}, len(cloudResources))

	var created, updated int
	for _, cr := range cloudResources {
		cloudNames[cr.Name] = struct{}{}

		r := &config.Resource{
			Name:          cr.Name,
			Type:          cr.Type,
			InternalIP:    cr.Host,
			Port:          cr.Port,
			CloudAppID:    cr.ID,
			CloudClientID: cr.ClientID,
			CloudSecret:   cr.ClientSecret,
			MFARequired:   cr.RequireMFA,
			Enabled:       cr.Enabled,
		}

		if existing, ok := localByName[cr.Name]; ok {
			// Preserve locally-managed fields that cloud doesn't track
			r.TunnelIP = existing.TunnelIP
			r.Protocol = existing.Protocol
			r.ExternalURL = existing.ExternalURL
			r.InternalURL = existing.InternalURL
			r.InternalHosts = existing.InternalHosts
			r.SessionDuration = existing.SessionDuration
			r.CertSource = existing.CertSource
			r.CertPEM = existing.CertPEM
			r.KeyPEM = existing.KeyPEM
			r.PassHeaders = existing.PassHeaders
			r.Description = existing.Description
			r.CreatedAt = existing.CreatedAt
			if err := p.store.UpdateResource(cr.Name, r); err != nil {
				log.Printf("[PORTAL] Failed to update resource %s: %v", cr.Name, err)
			} else {
				updated++
			}
		} else {
			r.CreatedAt = time.Now().Format(time.RFC3339)
			if err := p.store.CreateResource(r); err != nil {
				log.Printf("[PORTAL] Failed to create resource %s: %v", cr.Name, err)
			} else {
				created++
			}
		}
	}

	// Delete local resources that no longer exist in cloud
	var deleted int
	for name := range localByName {
		if _, exists := cloudNames[name]; !exists {
			if err := p.store.DeleteResource(name); err != nil {
				log.Printf("[PORTAL] Failed to delete resource %s: %v", name, err)
			} else {
				deleted++
			}
		}
	}

	if created > 0 || updated > 0 || deleted > 0 {
		log.Printf("[PORTAL] Resource sync: %d created, %d updated, %d deleted", created, updated, deleted)
		p.syslogClient.Info("portal.resource_sync", fmt.Sprintf("Resource sync: %d created, %d updated, %d deleted", created, updated, deleted), map[string]string{
			"created": strconv.Itoa(created),
			"updated": strconv.Itoa(updated),
			"deleted": strconv.Itoa(deleted),
		})
	}
}

// checkCertExpiry inspects configured TLS and mTLS certificates and logs
// warnings via syslog when they are approaching expiration.
func (p *Portal) checkCertExpiry() {
	certFiles := map[string]string{
		"tls_cert":  p.cfg.TLSCert,
		"mtls_cert": p.cfg.MTLSCert,
		"client_ca": p.cfg.ClientCA,
		"cloud_ca":  p.cfg.CloudCA,
	}

	for label, path := range certFiles {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[PORTAL] Cannot read cert %s (%s): %v", label, path, err)
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		remaining := time.Until(cert.NotAfter)
		if remaining < 0 {
			log.Printf("[PORTAL] CRITICAL: Certificate %s EXPIRED on %s", label, cert.NotAfter.Format(time.RFC3339))
			p.syslogClient.Error("cert.expired", fmt.Sprintf("Certificate %s expired on %s", label, cert.NotAfter.Format(time.RFC3339)), map[string]string{
				"cert":    label,
				"path":    path,
				"expires": cert.NotAfter.Format(time.RFC3339),
			})
		} else if remaining < 7*24*time.Hour {
			log.Printf("[PORTAL] WARNING: Certificate %s expires in %s", label, remaining.Round(time.Hour))
			p.syslogClient.Warn("cert.expiring_soon", fmt.Sprintf("Certificate %s expires in %s", label, remaining.Round(time.Hour)), map[string]string{
				"cert":      label,
				"path":      path,
				"expires":   cert.NotAfter.Format(time.RFC3339),
				"remaining": remaining.Round(time.Hour).String(),
			})
		} else if remaining < 30*24*time.Hour {
			log.Printf("[PORTAL] Notice: Certificate %s expires in %d days", label, int(remaining.Hours()/24))
			p.syslogClient.Info("cert.expiring", fmt.Sprintf("Certificate %s expires in %d days", label, int(remaining.Hours()/24)), map[string]string{
				"cert":    label,
				"path":    path,
				"expires": cert.NotAfter.Format(time.RFC3339),
			})
		}
	}
}

// StartCertRenewalLoop runs a background goroutine that checks the mTLS certificate
// and automatically renews it before expiration. It generates a fresh ECDSA P-256 key
// for each renewal (forward secrecy) and reloads the CloudClient TLS configuration.
func (p *Portal) StartCertRenewalLoop(stop <-chan struct{}) {
	const checkInterval = 6 * time.Hour
	const renewThreshold = 48 * time.Hour

	// Initial check at startup
	p.renewCertIfNeeded(renewThreshold)

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.renewCertIfNeeded(renewThreshold)
		case <-stop:
			log.Printf("[PORTAL] Certificate renewal loop stopped")
			return
		}
	}
}

// renewCertIfNeeded checks the mTLS certificate expiry and renews if within threshold.
func (p *Portal) renewCertIfNeeded(threshold time.Duration) {
	certPath := p.cfg.MTLSCert
	keyPath := p.cfg.MTLSKey
	if certPath == "" || keyPath == "" {
		return
	}

	// Read and parse current certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Printf("[PORTAL] Cannot read mTLS cert for renewal check: %v", err)
		return
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		log.Printf("[PORTAL] Cannot decode mTLS cert PEM for renewal check")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("[PORTAL] Cannot parse mTLS cert for renewal check: %v", err)
		return
	}

	remaining := time.Until(cert.NotAfter)
	if remaining > threshold {
		return // Not yet time to renew
	}

	log.Printf("[PORTAL] mTLS certificate expires in %s (threshold %s) — starting renewal", remaining.Round(time.Minute), threshold)
	p.syslogClient.Info("cert.renewal.start", fmt.Sprintf("mTLS cert expires in %s, initiating renewal", remaining.Round(time.Minute)), nil)

	// Generate fresh ECDSA P-256 key (forward secrecy)
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("[PORTAL] Failed to generate new key for cert renewal: %v", err)
		p.syslogClient.Error("cert.renewal.keygen_failed", err.Error(), nil)
		return
	}

	// Build CSR with FQDN as CN
	fqdn := p.cfg.FQDN
	if fqdn == "" {
		fqdn = cert.Subject.CommonName // fallback to current cert CN
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: fqdn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, newKey)
	if err != nil {
		log.Printf("[PORTAL] Failed to create CSR for cert renewal: %v", err)
		p.syslogClient.Error("cert.renewal.csr_failed", err.Error(), nil)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Send CSR to cloud
	result, err := p.cloud.RenewCert(string(csrPEM))
	if err != nil {
		log.Printf("[PORTAL] Certificate renewal request failed: %v", err)
		p.syslogClient.Error("cert.renewal.request_failed", err.Error(), nil)
		return
	}

	// Write new key to disk
	keyDER, err := x509.MarshalECPrivateKey(newKey)
	if err != nil {
		log.Printf("[PORTAL] Failed to marshal new private key: %v", err)
		p.syslogClient.Error("cert.renewal.key_marshal_failed", err.Error(), nil)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := config.AtomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		log.Printf("[PORTAL] Failed to write new private key: %v", err)
		p.syslogClient.Error("cert.renewal.key_write_failed", err.Error(), nil)
		return
	}

	// Write new cert to disk (atomic)
	if err := config.AtomicWriteFile(certPath, []byte(result.CertPEM), 0644); err != nil {
		log.Printf("[PORTAL] Failed to write new certificate: %v", err)
		p.syslogClient.Error("cert.renewal.cert_write_failed", err.Error(), nil)
		return
	}

	// Update CA if changed (atomic)
	if result.CAPEM != "" && p.cfg.CloudCA != "" {
		if err := config.AtomicWriteFile(p.cfg.CloudCA, []byte(result.CAPEM), 0644); err != nil {
			log.Printf("[PORTAL] Failed to write updated CA: %v", err)
		}
	}

	// Reload mTLS cert in CloudClient for subsequent requests
	if err := p.cloud.ReloadTLSCert(certPath, keyPath); err != nil {
		log.Printf("[PORTAL] Failed to hot-reload mTLS cert: %v", err)
		p.syslogClient.Error("cert.renewal.reload_failed", err.Error(), nil)
		return
	}

	log.Printf("[PORTAL] mTLS certificate renewed successfully (new expiry: 7 days)")
	p.syslogClient.Info("cert.renewal.success", "mTLS certificate renewed successfully", map[string]string{
		"fqdn": fqdn,
	})
}
