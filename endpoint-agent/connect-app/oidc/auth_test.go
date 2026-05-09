package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestAuthenticateUsesLoopbackPKCEAndTokenExchange(t *testing.T) {
	var mu sync.Mutex
	var seen struct {
		challenge   string
		redirectURI string
		state       string
	}

	tokenEndpointHit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/token" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "parse form", http.StatusBadRequest)
			return
		}

		mu.Lock()
		challenge := seen.challenge
		redirectURI := seen.redirectURI
		mu.Unlock()

		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		if r.Form.Get("client_id") != DefaultClientID {
			http.Error(w, "wrong client_id", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != "auth-code-1" {
			http.Error(w, "wrong code", http.StatusBadRequest)
			return
		}
		if r.Form.Get("redirect_uri") != redirectURI {
			http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
			return
		}
		verifier := r.Form.Get("code_verifier")
		if verifier == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		if pkceS256(verifier) != challenge {
			http.Error(w, "PKCE mismatch", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken:  "access-token-1",
			IDToken:      "id-token-1",
			RefreshToken: "refresh-token-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			UserID:       "user-1",
			Username:     "alice",
			Role:         "user",
			DeviceID:     "device-1",
		})
		select {
		case tokenEndpointHit <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	callbackErr := make(chan error, 1)
	authenticator, err := NewAuthenticator(Config{
		IssuerURL: srv.URL,
		DeviceID:  "device-1",
		Hostname:  "host-1",
		OpenBrowser: func(rawURL string) error {
			authURL, err := url.Parse(rawURL)
			if err != nil {
				return err
			}
			if authURL.Path != "/auth/authorize" {
				return fmt.Errorf("authorization path = %q, want /auth/authorize", authURL.Path)
			}
			q := authURL.Query()
			if q.Get("client_id") != DefaultClientID {
				return fmt.Errorf("client_id = %q", q.Get("client_id"))
			}
			if q.Get("response_type") != "code" {
				return fmt.Errorf("response_type = %q", q.Get("response_type"))
			}
			if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
				return fmt.Errorf("missing PKCE S256 challenge")
			}
			if q.Get("device_id") != "device-1" || q.Get("hostname") != "host-1" {
				return fmt.Errorf("missing device binding metadata")
			}
			if q.Get("acr_values") != "urn:ztna:loa:2" {
				return fmt.Errorf("acr_values = %q", q.Get("acr_values"))
			}

			redirectURI := q.Get("redirect_uri")
			parsedRedirect, err := url.Parse(redirectURI)
			if err != nil {
				return err
			}
			if parsedRedirect.Scheme != "http" || parsedRedirect.Path != "/callback" {
				return fmt.Errorf("redirect_uri = %q", redirectURI)
			}
			host, port, err := net.SplitHostPort(parsedRedirect.Host)
			if err != nil {
				return fmt.Errorf("redirect host: %w", err)
			}
			if host != "127.0.0.1" || port == "" {
				return fmt.Errorf("redirect host = %q port = %q", host, port)
			}

			mu.Lock()
			seen.challenge = q.Get("code_challenge")
			seen.redirectURI = redirectURI
			seen.state = q.Get("state")
			state := seen.state
			mu.Unlock()

			go func() {
				callbackURL := redirectURI + "?code=auth-code-1&state=" + url.QueryEscape(state)
				resp, err := http.Get(callbackURL)
				if err != nil {
					callbackErr <- err
					return
				}
				defer resp.Body.Close()
				_, _ = io.Copy(io.Discard, resp.Body)
				if resp.StatusCode != http.StatusOK {
					callbackErr <- fmt.Errorf("callback status = %d", resp.StatusCode)
				}
			}()
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tokens, err := authenticator.Authenticate(ctx, "urn:ztna:loa:2")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if tokens.AccessToken != "access-token-1" || tokens.RefreshToken != "refresh-token-1" || tokens.DeviceID != "device-1" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
	if got := authenticator.CurrentAccessToken(); got != "access-token-1" {
		t.Fatalf("CurrentAccessToken() = %q", got)
	}

	select {
	case <-tokenEndpointHit:
	case <-time.After(time.Second):
		t.Fatal("token endpoint was not called")
	}
	select {
	case err := <-callbackErr:
		t.Fatalf("callback request failed: %v", err)
	default:
	}
}

func pkceS256(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
