package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetRevokedSerialsByProviderVaultFallbackWithoutPKIURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/gateway/revoked-serials" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string][]string{"revoked_serials": {"111", "222"}})
	}))
	defer srv.Close()

	client := newCloudClientForTests(srv.URL)

	serials, source, err := client.GetRevokedSerialsByProvider()
	if source != "cloud-fallback" {
		t.Fatalf("unexpected source: got %q want %q", source, "cloud-fallback")
	}
	if err == nil {
		t.Fatalf("expected warning error when vault fails and cloud fallback is used")
	}
	assertSameSerialSet(t, serials, []string{"111", "222"})
}

func TestGetRevokedSerialsByProviderVaultSuccess(t *testing.T) {
	crlPEM, _, expected := buildTestCRL(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pki_int/cert/crl/pem":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(crlPEM)
		case "/api/gateway/revoked-serials":
			_ = json.NewEncoder(w).Encode(map[string][]string{"revoked_serials": {"fallback"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newCloudClientForTests(srv.URL)
	client.pkiURL = srv.URL
	client.pkiPath = "pki_int"

	serials, source, err := client.GetRevokedSerialsByProvider()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != "vault" {
		t.Fatalf("unexpected source: got %q want %q", source, "vault")
	}
	assertSameSerialSet(t, serials, expected)
}

func TestGetRevokedSerialsByProviderVaultFallbackToCloud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pki_int/cert/crl/pem", "/v1/pki_int/crl/pem", "/v1/pki_int/cert/crl", "/v1/pki_int/crl":
			http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
		case "/api/gateway/revoked-serials":
			_ = json.NewEncoder(w).Encode(map[string][]string{"revoked_serials": {"987"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newCloudClientForTests(srv.URL)
	client.pkiURL = srv.URL
	client.pkiPath = "pki_int"

	serials, source, err := client.GetRevokedSerialsByProvider()
	if source != "cloud-fallback" {
		t.Fatalf("unexpected source: got %q want %q", source, "cloud-fallback")
	}
	if err == nil {
		t.Fatalf("expected warning error when vault fails and cloud fallback is used")
	}
	if !strings.Contains(err.Error(), "vault revocation sync failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
	assertSameSerialSet(t, serials, []string{"987"})
}

func TestGetVaultRevokedSerialsSendsToken(t *testing.T) {
	crlPEM, _, expected := buildTestCRL(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pki_int/cert/crl/pem" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("X-Vault-Token"); got != "token-123" {
			http.Error(w, "missing token", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crlPEM)
	}))
	defer srv.Close()

	client := newCloudClientForTests(srv.URL)
	client.pkiURL = srv.URL
	client.pkiPath = "pki_int"
	client.pkiToken = "token-123"

	serials, err := client.GetVaultRevokedSerials()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSameSerialSet(t, serials, expected)
}

func newCloudClientForTests(cloudURL string) *CloudClient {
	return &CloudClient{
		cloudURL:     strings.TrimRight(cloudURL, "/"),
		client:       &http.Client{Timeout: 2 * time.Second},
		pkiPath:      "pki_int",
		sessionCache: make(map[string]*CachedSession),
		breaker:      NewCircuitBreaker(),
		stopCh:       make(chan struct{}),
	}
}

func assertSameSerialSet(t *testing.T, got, expected []string) {
	t.Helper()

	if len(got) != len(expected) {
		t.Fatalf("unexpected serial count: got=%d expected=%d (got=%v)", len(got), len(expected), got)
	}

	expectedSet := make(map[string]struct{}, len(expected))
	for _, serial := range expected {
		expectedSet[serial] = struct{}{}
	}

	for _, serial := range got {
		if _, ok := expectedSet[serial]; !ok {
			t.Fatalf("unexpected serial %q in result %v", serial, got)
		}
	}
}
