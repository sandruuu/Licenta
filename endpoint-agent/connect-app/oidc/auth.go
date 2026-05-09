package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	DefaultClientID = "connect-app"
	DefaultScopes   = "openid profile email offline_access"
)

type BrowserOpener func(rawURL string) error

type Config struct {
	IssuerURL   string
	ClientID    string
	Scopes      string
	DeviceID    string
	Hostname    string
	CAFile      string
	OpenBrowser BrowserOpener
}

type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	UserID       string
	Username     string
	Role         string
	DeviceID     string
}

type Authenticator struct {
	cfg    Config
	client *http.Client

	mu     sync.RWMutex
	tokens *TokenSet
}

func NewAuthenticator(cfg Config) (*Authenticator, error) {
	cfg.IssuerURL = strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("issuer URL is required")
	}
	if cfg.ClientID == "" {
		cfg.ClientID = DefaultClientID
	}
	if cfg.Scopes == "" {
		cfg.Scopes = DefaultScopes
	}
	if cfg.DeviceID == "" {
		return nil, fmt.Errorf("device ID is required")
	}

	client, err := buildHTTPClient(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	return &Authenticator{cfg: cfg, client: client}, nil
}

func (a *Authenticator) CurrentAccessToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.tokens == nil || a.tokens.AccessToken == "" {
		return ""
	}
	if !a.tokens.ExpiresAt.IsZero() && time.Until(a.tokens.ExpiresAt) < 30*time.Second {
		return ""
	}
	return a.tokens.AccessToken
}

func (a *Authenticator) DeviceID() string {
	return a.cfg.DeviceID
}

func (a *Authenticator) Authenticate(ctx context.Context, acrValues string) (*TokenSet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if acrValues == "" && a.tokens != nil && a.tokens.RefreshToken != "" {
		if tokens, err := a.refreshLocked(ctx); err == nil {
			return tokens, nil
		} else {
			slog.Warn("OIDC refresh failed; falling back to browser authorization", "error", err)
		}
	}

	verifier, challenge, err := pkcePair()
	if err != nil {
		return nil, err
	}
	state, err := randomString(32)
	if err != nil {
		return nil, err
	}
	nonce, err := randomString(32)
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start loopback callback: %w", err)
	}
	defer ln.Close()

	redirectURI := "http://" + ln.Addr().String() + "/callback"
	codeCh := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			codeCh <- callbackResult{err: fmt.Errorf("authorization error: %s", errParam)}
			http.Error(w, "Authorization failed", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "<html><body><h3>Authentication complete</h3><p>You can close this window.</p></body></html>")
		codeCh <- callbackResult{code: code}
	})

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()
	defer srv.Shutdown(context.Background())

	authURL, err := a.authorizationURL(redirectURI, state, nonce, challenge, acrValues)
	if err != nil {
		return nil, err
	}
	if a.cfg.OpenBrowser == nil {
		return nil, fmt.Errorf("browser opener is not configured")
	}
	if err := a.cfg.OpenBrowser(authURL); err != nil {
		return nil, fmt.Errorf("open browser: %w", err)
	}
	slog.Info("Browser opened for OIDC authentication", "issuer", a.cfg.IssuerURL, "client_id", a.cfg.ClientID)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-serveErr:
		return nil, fmt.Errorf("loopback callback server: %w", err)
	case res := <-codeCh:
		if res.err != nil {
			return nil, res.err
		}
		tokens, err := a.exchangeCodeLocked(ctx, res.code, redirectURI, verifier)
		if err != nil {
			return nil, err
		}
		return tokens, nil
	}
}

func (a *Authenticator) authorizationURL(redirectURI, state, nonce, challenge, acrValues string) (string, error) {
	u, err := url.Parse(a.cfg.IssuerURL + "/auth/authorize")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", a.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", a.cfg.Scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("device_id", a.cfg.DeviceID)
	if a.cfg.Hostname != "" {
		q.Set("hostname", a.cfg.Hostname)
	}
	if acrValues != "" {
		q.Set("acr_values", acrValues)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (a *Authenticator) exchangeCodeLocked(ctx context.Context, code, redirectURI, verifier string) (*TokenSet, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", a.cfg.ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	return a.tokenRequestLocked(ctx, form)
}

func (a *Authenticator) refreshLocked(ctx context.Context) (*TokenSet, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", a.cfg.ClientID)
	form.Set("refresh_token", a.tokens.RefreshToken)
	return a.tokenRequestLocked(ctx, form)
}

func (a *Authenticator) tokenRequestLocked(ctx context.Context, form url.Values) (*TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.IssuerURL+"/auth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response did not include access_token")
	}
	if tr.ExpiresIn <= 0 {
		tr.ExpiresIn = 3600
	}
	tokens := &TokenSet{
		AccessToken:  tr.AccessToken,
		IDToken:      tr.IDToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		UserID:       tr.UserID,
		Username:     tr.Username,
		Role:         tr.Role,
		DeviceID:     tr.DeviceID,
	}
	if tokens.RefreshToken == "" && a.tokens != nil {
		tokens.RefreshToken = a.tokens.RefreshToken
	}
	a.tokens = tokens
	slog.Info("OIDC token acquired", "username", tokens.Username, "device_id", tokens.DeviceID, "expires_in", tr.ExpiresIn)
	return tokens, nil
}

type callbackResult struct {
	code string
	err  error
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
	DeviceID     string `json:"device_id"`
}

func pkcePair() (verifier, challenge string, err error) {
	verifier, err = randomString(32)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(digest[:])
	return verifier, challenge, nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func buildHTTPClient(caFile string) (*http.Client, error) {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read OIDC CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse OIDC CA file")
		}
		tlsConf.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}, nil
}
