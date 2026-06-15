package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"pdp/certs"
)

// ─────────────────────────────────────────────
// Public trust and health endpoints.
// ─────────────────────────────────────────────

// handleCACert returns the active issuer CA certificate (public info, no auth needed).
// Gateways use this to validate certificates issued via the PDP signer path.
func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	caPEM, err := s.getCAPEM()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "CA not initialized"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(caPEM)
}

// handleCertFingerprint returns the SHA-256 fingerprint of the PDP server's TLS certificate.
// Operators can use this value to configure pdp_cert_sha256 in gateway/connect/health configs.
func (s *Server) handleCertFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	certPath := s.pa.Cfg.TLSCert
	if certPath == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "TLS cert not configured"})
		return
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot read TLS cert"})
		return
	}
	fp, err := certs.CertFingerprint(certPEM)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot compute fingerprint"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sha256": fp})
}

func (s *Server) handleLiveCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "trustcloud",
	})
}

func (s *Server) handleReadyCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.IsDraining() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":  "draining",
			"service": "trustcloud",
		})
		return
	}
	checks, status := s.dependencyChecks(r.Context())
	httpStatus := http.StatusOK
	if status == "degraded" {
		httpStatus = http.StatusServiceUnavailable
	}
	writeJSON(w, httpStatus, map[string]interface{}{
		"status":  status,
		"service": "trustcloud",
		"checks":  checks,
	})
}

func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	checks, status := s.dependencyChecks(r.Context())
	httpStatus := http.StatusOK
	if status == "degraded" {
		httpStatus = http.StatusServiceUnavailable
	}
	writeJSON(w, httpStatus, map[string]interface{}{
		"status":  status,
		"service": "trustcloud",
		"checks":  checks,
	})
}

func (s *Server) dependencyChecks(ctx context.Context) (map[string]string, string) {
	if ctx == nil {
		ctx = context.Background()
	}
	checks := map[string]string{}
	status := "ok"

	// Check database connectivity
	if s == nil || s.pa == nil || s.pa.Store == nil {
		checks["db"] = "not_configured"
		status = "degraded"
	} else if err := s.pa.Store.Ping(); err != nil {
		checks["db"] = "error"
		status = "degraded"
	} else {
		checks["db"] = "ok"
	}

	redisCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if s == nil || s.pa == nil || s.pa.Runtime == nil {
		checks["redis"] = "not_configured"
		status = "degraded"
	} else if err := s.pa.Runtime.Ping(redisCtx); err != nil {
		checks["redis"] = "error"
		status = "degraded"
	} else {
		checks["redis"] = "ok"
	}

	// Check Vault issuer CA loaded
	if s != nil && len(s.externalCAPEM) > 0 {
		checks["ca"] = "ok"
	} else {
		checks["ca"] = "not_configured"
		status = "degraded"
	}

	// Check PA auth JWT signing keys
	if s == nil || s.pa == nil || s.pa.Auth == nil || s.pa.Auth.JWT == nil {
		checks["auth"] = "not_configured"
		status = "degraded"
	} else if _, err := s.pa.Auth.JWT.GetJWKSJSON(); err != nil {
		checks["auth"] = "error"
		status = "degraded"
	} else {
		checks["auth"] = "ok"
	}

	return checks, status
}

// handleJWKS serves the JSON Web Key Set for JWT verification (ES256 public key)
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	jwksJSON, err := s.pa.Auth.JWT.GetJWKSJSON()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate JWKS"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(jwksJSON)
}

// handleOIDCDiscovery serves the OpenID Connect Discovery 1.0 metadata document
// at /.well-known/openid-configuration. Allows OIDC clients (including our own
// gateway) to autodetect the authorization, token, userinfo and JWKS endpoints
// from the issuer URL alone, instead of hardcoding them.
func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	base := externalBaseURL(r)
	doc := map[string]interface{}{
		"issuer":                                base,
		"authorization_endpoint":                base + "/auth/authorize",
		"token_endpoint":                        base + "/auth/token",
		"userinfo_endpoint":                     base + "/auth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nbf", "jti", "user_id", "username", "role", "device_id", "mfa_done", "acr", "amr", "nonce"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// externalBaseURL returns the externally-visible base URL for this request,
// honouring X-Forwarded-Proto / X-Forwarded-Host when present (reverse proxy).
func externalBaseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	return scheme + "://" + host
}
