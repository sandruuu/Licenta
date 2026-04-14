package portal

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"sync"
	"time"

	"gateway/internal/auth"
	"gateway/internal/config"
	"gateway/internal/models"
	"gateway/sessionstore"
	"gateway/syslog"
)

// ──────────────────────────────────────────────────────────────────────
// OIDC Callback Server — Gateway acts as Relying Party (RP)
//
// This module implements:
//   - An HTTP(S) server for the OIDC callback (/auth/callback)
//   - State management linking browser auth to yamux connections
//   - Token exchange with the Cloud (IdP) via backend-to-backend call
//
// Flow:
//  1. User tries to access a resource via connect-app
//  2. Gateway detects no session → generates OIDC state, sends auth_url to connect-app
//  3. Connect-app opens user's browser to Cloud /auth/authorize
//  4. User authenticates at Cloud, Cloud redirects browser to Gateway /auth/callback
//  5. Gateway exchanges code for JWT (POST to Cloud /auth/token)
//  6. Gateway marks the yamux connection as authorized
//  7. User can now access resources through connect-app
// ──────────────────────────────────────────────────────────────────────

// OIDCCallbackServer handles the browser callback from the Cloud IdP
type OIDCCallbackServer struct {
	cfg          *config.Config
	cloud        *auth.CloudClient
	sessions     *sessionstore.Client
	syslogClient *syslog.Client

	mu sync.RWMutex
	// pendingStates maps OIDC state tokens to the yamux connectionState.
	// When the browser callback arrives, we use the state to find and
	// authorize the correct yamux connection.
	pendingStates map[string]*PendingOIDCAuth
	// serverNonce is a random value generated at startup for state hashing (anti-replay).
	serverNonce string
	// callbackAttempts tracks per-IP callback requests for rate limiting.
	callbackAttempts   map[string]*callbackRateInfo
	callbackAttemptsMu sync.Mutex
}

// callbackRateInfo tracks callback attempts per source IP for rate limiting.
type callbackRateInfo struct {
	count     int
	firstSeen time.Time
}

// PendingOIDCAuth represents a pending OIDC authentication linked to a yamux connection
type PendingOIDCAuth struct {
	State        string
	StateHash    string // SHA256(state + server nonce + identity) for anti-replay
	ConnState    *connectionState
	CreatedAt    time.Time
	ExpiresAt    time.Time
	CodeVerifier string // PKCE code_verifier (RFC 7636)
	Nonce        string // OIDC nonce for replay protection (OIDC Core 1.0 §3.1.2.1)
	RemoteAddr   string // IP of the connect-app that initiated the auth
}

// NewOIDCCallbackServer creates a new OIDC callback HTTP server
func NewOIDCCallbackServer(cfg *config.Config, cloud *auth.CloudClient, sessions *sessionstore.Client, syslogClient *syslog.Client) *OIDCCallbackServer {
	// Generate a per-startup server nonce for state hashing
	nonceBytes := make([]byte, 32)
	rand.Read(nonceBytes)

	s := &OIDCCallbackServer{
		cfg:              cfg,
		cloud:            cloud,
		sessions:         sessions,
		syslogClient:     syslogClient,
		pendingStates:    make(map[string]*PendingOIDCAuth),
		serverNonce:      hex.EncodeToString(nonceBytes),
		callbackAttempts: make(map[string]*callbackRateInfo),
	}

	// Start cleanup loop for expired pending states
	go s.cleanupLoop()

	return s
}

// ListenAndServe starts the HTTPS callback server.
// This listens on a separate port (default: the same :9443 or a configured callback port)
// that is accessible from the user's browser.
func (s *OIDCCallbackServer) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback", s.handleCallback)
	mux.HandleFunc("/auth/status", s.handleAuthStatusPage)

	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
		server := &http.Server{
			Addr:              addr,
			Handler:           mux,
			TLSConfig:         tlsConfig,
			ReadTimeout:       15 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		log.Printf("[OIDC-CALLBACK] HTTPS callback server listening on %s", addr)
		return server.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}

	// Refuse plain HTTP in production — OIDC authorization codes must not travel in cleartext
	if !s.cfg.DevMode {
		return fmt.Errorf("OIDC callback requires TLS certificates (tls_cert / tls_key) in production mode")
	}

	log.Printf("[OIDC-CALLBACK] WARNING: HTTP callback server on %s — INSECURE, dev mode only", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server.ListenAndServe()
}

// GenerateAuthURL creates an OIDC authorization URL and registers a pending state
// linked to the given yamux connection. Returns the full auth URL.
func (s *OIDCCallbackServer) GenerateAuthURL(connState *connectionState) (string, error) {
	// Generate random state token
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	// Generate PKCE code_verifier (RFC 7636) — 32 random bytes, base64url-encoded
	cvBytes := make([]byte, 32)
	if _, err := rand.Read(cvBytes); err != nil {
		return "", fmt.Errorf("generate code_verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(cvBytes)

	// code_challenge = BASE64URL(SHA256(code_verifier))
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// Generate OIDC nonce for replay protection (OIDC Core 1.0 §3.1.2.1)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	// Register the pending state
	s.mu.Lock()
	if len(s.pendingStates) >= 500 {
		s.mu.Unlock()
		return "", fmt.Errorf("too many pending OIDC authentications (limit 500)")
	}
	s.pendingStates[state] = &PendingOIDCAuth{
		State:        state,
		StateHash:    s.hashState(state, connState.certDeviceID, connState.remoteAddr),
		ConnState:    connState,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute),
		CodeVerifier: codeVerifier,
		Nonce:        nonce,
		RemoteAddr:   connState.remoteAddr,
	}
	s.mu.Unlock()

	// Build the OIDC authorization URL
	authSource := s.cfg.AuthSource
	if authSource == nil {
		return "", fmt.Errorf("auth_source not configured in gateway config")
	}

	authURL := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&state=%s&scope=%s&code_challenge=%s&code_challenge_method=S256&nonce=%s",
		authSource.AuthURL,
		authSource.ClientID,
		authSource.RedirectURI,
		state,
		authSource.Scopes,
		codeChallenge,
		nonce,
	)

	log.Printf("[OIDC-CALLBACK] Auth URL generated for connection %s: state=%s", connState.remoteAddr, state)
	s.syslogClient.Info("oidc.auth_url_generated", fmt.Sprintf("Auth URL generated for %s", connState.remoteAddr), map[string]string{
		"state":       state,
		"remote_addr": connState.remoteAddr,
	})

	return authURL, nil
}

// handleCallback processes the browser redirect from the Cloud IdP.
// GET /auth/callback?code=abc123&state=xyz789
func (s *OIDCCallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit callback attempts per IP — max 10 per minute
	clientIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientIP = fwd
	}
	if s.isCallbackRateLimited(clientIP) {
		s.syslogClient.Warn("oidc.rate_limited", "OIDC callback rate limited", map[string]string{"ip": clientIP})
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}
	s.recordCallbackAttempt(clientIP)

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Handle error from IdP
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.Printf("[OIDC-CALLBACK] IdP returned error: %s — %s", errorParam, errorDesc)
		// Don't leak IdP error details to the browser
		s.serveErrorPage(w, "Autentificare eșuată", "Autentificarea a eșuat. Încearcă din nou.")
		return
	}

	if code == "" || state == "" {
		s.serveErrorPage(w, "Parametri lipsă", "Codul de autorizare sau starea lipsesc din cerere.")
		return
	}

	// Look up the pending state
	s.mu.Lock()
	pending, ok := s.pendingStates[state]
	if ok {
		delete(s.pendingStates, state) // one-time use
	}
	s.mu.Unlock()

	if !ok {
		log.Printf("[OIDC-CALLBACK] Unknown or expired state: %s", state)
		s.syslogClient.Warn("oidc.invalid_state", "OIDC callback with unknown state", map[string]string{
			"state": state,
		})
		s.serveErrorPage(w, "Sesiune expirată", "Starea autentificării a expirat sau este invalidă. Încearcă din nou.")
		return
	}

	// Check expiration
	if time.Now().After(pending.ExpiresAt) {
		log.Printf("[OIDC-CALLBACK] State expired: %s", state)
		s.serveErrorPage(w, "Sesiune expirată", "Sesiunea de autentificare a expirat. Încearcă din nou.")
		return
	}

	// Validate state integrity — recompute hash and compare (Fix 3: anti-replay)
	expectedHash := s.hashState(state, pending.ConnState.certDeviceID, pending.ConnState.remoteAddr)
	if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(pending.StateHash)) != 1 {
		log.Printf("[OIDC-CALLBACK] State integrity check failed: %s", state)
		s.syslogClient.Warn("oidc.state_integrity_failed", "State integrity check failed", map[string]string{
			"state": state,
		})
		s.serveErrorPage(w, "Eroare de securitate", "Verificarea integrității stării a eșuat. Încearcă din nou.")
		return
	}

	log.Printf("[OIDC-CALLBACK] Processing callback: state=%s code=%s...%s",
		state, code[:min(4, len(code))], code[max(0, len(code)-4):])

	// ── Step 5: Exchange authorization code for token (Backend-to-Backend) ──
	authSource := s.cfg.AuthSource
	tokenResp, err := s.cloud.ExchangeCodeForToken(
		authSource.TokenURL,
		authSource.ClientID,
		authSource.ClientSecret,
		code,
		authSource.RedirectURI,
		pending.CodeVerifier,
	)
	if err != nil {
		log.Printf("[OIDC-CALLBACK] Token exchange failed: %v", err)
		s.syslogClient.Error("oidc.token_exchange_failed", fmt.Sprintf("Token exchange failed: %v", err), map[string]string{
			"state": state,
		})
		s.serveErrorPage(w, "Eroare la autentificare", "Schimbul de token a eșuat. Încearcă din nou.")
		return
	}

	// ── Step 6: Validate nonce and authorize the yamux connection ──
	// Validate OIDC nonce — the id_token must contain the same nonce we sent
	if pending.Nonce != "" && tokenResp.Nonce != pending.Nonce {
		log.Printf("[OIDC-CALLBACK] Nonce mismatch: expected=%s got=%s", pending.Nonce, tokenResp.Nonce)
		s.syslogClient.Error("oidc.nonce_mismatch", "OIDC nonce validation failed (replay attack?)", map[string]string{
			"state": state,
		})
		s.serveErrorPage(w, "Eroare de securitate", "Validarea nonce a eșuat. Încearcă din nou.")
		return
	}

	connState := pending.ConnState

	// Create a session in the session store
	sessionID := generateSessionID()
	sess := &models.Session{
		ID:           sessionID,
		UserID:       tokenResp.UserID,
		Username:     tokenResp.Username,
		DeviceID:     connState.certDeviceID, // bind session to device from mTLS cert
		SourceIP:     connState.remoteAddr,
		AuthToken:    tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(s.cfg.SessionTimeout) * time.Second),
		LastActivity: time.Now(),
		Active:       true,
	}

	if err := s.sessions.Create(sess); err != nil {
		log.Printf("[OIDC-CALLBACK] Session store error: %v", err)
		// Fall through — portal still works
	}

	// Mark the yamux connection as authenticated
	connState.mu.Lock()
	connState.authenticated = true
	connState.userID = tokenResp.UserID
	connState.username = tokenResp.Username
	connState.authToken = tokenResp.AccessToken
	connState.refreshToken = tokenResp.RefreshToken
	connState.sessionID = sessionID
	connState.mu.Unlock()

	log.Printf("[OIDC-CALLBACK] Auth SUCCESS via OIDC: user=%s session=%s connection=%s",
		tokenResp.Username, sessionID, connState.remoteAddr)

	s.syslogClient.Info("oidc.auth_success", fmt.Sprintf("OIDC auth success: user=%s via callback", tokenResp.Username), map[string]string{
		"user_id":     tokenResp.UserID,
		"username":    tokenResp.Username,
		"session_id":  sessionID,
		"remote_addr": connState.remoteAddr,
	})

	// ── Step 6b: Show success page to the browser ──
	s.serveSuccessPage(w, tokenResp.Username)
}

// handleAuthStatusPage serves a simple status check endpoint.
// Connect-app can poll this to know when auth is complete (optional).
func (s *OIDCCallbackServer) handleAuthStatusPage(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "state parameter required"})
		return
	}

	s.mu.RLock()
	_, pending := s.pendingStates[state]
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if pending {
		// Still pending (state exists = not yet consumed by callback)
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	} else {
		// State consumed = callback was processed (auth complete or expired)
		json.NewEncoder(w).Encode(map[string]string{"status": "completed"})
	}
}

// serveSuccessPage renders an HTML success page after OIDC callback
func (s *OIDCCallbackServer) serveSuccessPage(w http.ResponseWriter, username string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Autentificare Reușită</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%%, #1e293b 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #f8fafc;
        }
        .card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(100, 116, 139, 0.3);
            border-radius: 16px;
            padding: 48px;
            text-align: center;
            max-width: 440px;
            width: 90%%;
            backdrop-filter: blur(10px);
        }
        .icon {
            width: 80px; height: 80px;
            background: #22c55e;
            border-radius: 50%%;
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 24px;
            font-size: 40px;
        }
        h1 { font-size: 24px; margin-bottom: 12px; color: #22c55e; }
        p { color: #94a3b8; line-height: 1.6; margin-bottom: 8px; }
        .user { color: #60a5fa; font-weight: 600; }
        .hint {
            margin-top: 24px;
            padding: 16px;
            background: rgba(30, 58, 138, 0.3);
            border-radius: 8px;
            border: 1px solid rgba(96, 165, 250, 0.2);
            font-size: 14px;
            color: #93c5fd;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">✓</div>
        <h1>Autentificare Reușită!</h1>
        <p>Bine ai venit, <span class="user">%s</span>!</p>
        <p>Sesiunea ta a fost activată cu succes.</p>
        <div class="hint">
            Poți închide această fereastră și te poți reconecta la aplicație.
        </div>
    </div>
</body>
</html>`, html.EscapeString(username))
}

// serveErrorPage renders an HTML error page
func (s *OIDCCallbackServer) serveErrorPage(w http.ResponseWriter, title string, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Eroare Autentificare</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%%, #1e293b 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #f8fafc;
        }
        .card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(100, 116, 139, 0.3);
            border-radius: 16px;
            padding: 48px;
            text-align: center;
            max-width: 440px;
            width: 90%%;
        }
        .icon {
            width: 80px; height: 80px;
            background: #ef4444;
            border-radius: 50%%;
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 24px;
            font-size: 40px;
        }
        h1 { font-size: 24px; margin-bottom: 12px; color: #ef4444; }
        p { color: #94a3b8; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">✗</div>
        <h1>%s</h1>
        <p>%s</p>
    </div>
</body>
</html>`, html.EscapeString(title), html.EscapeString(message))
}

// cleanupLoop removes expired pending states and stale rate-limiting entries.
func (s *OIDCCallbackServer) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for state, pending := range s.pendingStates {
			if now.After(pending.ExpiresAt) {
				delete(s.pendingStates, state)
			}
		}
		s.mu.Unlock()

		// Clean up stale rate-limiting entries (older than 2 minutes)
		s.callbackAttemptsMu.Lock()
		for ip, info := range s.callbackAttempts {
			if time.Since(info.firstSeen) > 2*time.Minute {
				delete(s.callbackAttempts, ip)
			}
		}
		s.callbackAttemptsMu.Unlock()
	}
}

// hashState creates a binding of the state to the server nonce and connection identity,
// preventing state prediction and cross-connection replay attacks.
func (s *OIDCCallbackServer) hashState(state, certDeviceID, remoteAddr string) string {
	h := sha256.Sum256([]byte(state + ":" + s.serverNonce + ":" + certDeviceID + ":" + remoteAddr))
	return hex.EncodeToString(h[:])
}

// isCallbackRateLimited returns true if the given IP has exceeded the callback attempt limit.
func (s *OIDCCallbackServer) isCallbackRateLimited(ip string) bool {
	s.callbackAttemptsMu.Lock()
	defer s.callbackAttemptsMu.Unlock()
	info, ok := s.callbackAttempts[ip]
	if !ok {
		return false
	}
	// Reset window after 1 minute
	if time.Since(info.firstSeen) > time.Minute {
		delete(s.callbackAttempts, ip)
		return false
	}
	return info.count >= 10
}

// recordCallbackAttempt increments the callback counter for the given IP.
func (s *OIDCCallbackServer) recordCallbackAttempt(ip string) {
	s.callbackAttemptsMu.Lock()
	defer s.callbackAttemptsMu.Unlock()
	info, ok := s.callbackAttempts[ip]
	if !ok || time.Since(info.firstSeen) > time.Minute {
		s.callbackAttempts[ip] = &callbackRateInfo{count: 1, firstSeen: time.Now()}
		return
	}
	info.count++
}
