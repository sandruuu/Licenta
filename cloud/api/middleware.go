package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cloud/models"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const gatewayContextKey contextKey = "authenticatedGateway"

// gatewayFromContext extracts the authenticated gateway from the request context.
// Returns nil, false if the middleware did not set a gateway (e.g. non-gateway endpoint).
func gatewayFromContext(r *http.Request) (*models.Gateway, bool) {
	gw, ok := r.Context().Value(gatewayContextKey).(*models.Gateway)
	return gw, ok
}

// loggingMiddleware logs all HTTP requests with timing information
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		log.Printf("[API] %s %s %d %s (from %s)",
			r.Method, r.URL.Path, wrapped.statusCode, duration, r.RemoteAddr)
	})
}

// securityHeadersMiddleware adds standard security headers to all responses
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' http://127.0.0.1:12080; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers for web-based admin UI
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			// Restrict to dashboard and localhost origins
			if origin != "" && isAllowedCloudOrigin(origin, allowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isAllowedCloudOrigin(origin string, extraOrigins []string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}
	for _, allowed := range extraOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// requireClientCert enforces strict mTLS for gateway/device endpoints.
func (s *Server) requireClientCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.mtlsCAPool == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "mTLS is not configured on the cloud server",
			})
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "client certificate required",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// gatewayAuthMiddleware verifies that the calling gateway is enrolled by
// matching the mTLS client certificate's CN (FQDN) against the gateway
// database and checking the certificate fingerprint matches the enrollment record.
// On success, the authenticated gateway is stored in the request context
// and can be retrieved with gatewayFromContext(r).
func (s *Server) gatewayAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "client certificate required for gateway authentication",
			})
			return
		}

		peerCert := r.TLS.PeerCertificates[0]
		cn := peerCert.Subject.CommonName
		if cn == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "client certificate has no CommonName",
			})
			return
		}

		// Look up enrolled gateway by FQDN (certificate CN)
		gw, found := s.pa.Store.GetGatewayByFQDN(cn)
		if !found || gw.Status != "enrolled" {
			log.Printf("[AUTH] Rejected gateway request: CN=%q not found or not enrolled", cn)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "gateway not enrolled or certificate CN not recognized",
			})
			return
		}

		// Enrolled gateways must always have a certificate fingerprint on record
		if gw.CertFingerprint == "" {
			log.Printf("[AUTH] Rejected gateway request: CN=%q enrolled but has no certificate fingerprint on record", cn)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "gateway enrollment record is incomplete (missing certificate fingerprint)",
			})
			return
		}

		// Verify certificate fingerprint matches enrollment record (constant-time)
		fp := sha256.Sum256(peerCert.Raw)
		fingerprint := hex.EncodeToString(fp[:])
		if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(gw.CertFingerprint)) != 1 {
			log.Printf("[AUTH] Rejected gateway request: CN=%q fingerprint mismatch", cn)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "certificate fingerprint does not match enrollment record",
			})
			return
		}

		// Pass authenticated gateway identity to downstream handlers
		ctx := context.WithValue(r.Context(), gatewayContextKey, gw)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// adminAuthMiddleware validates the admin JWT token
func (s *Server) adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authorization header required",
			})
			return
		}

		// Extract Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid authorization header format (expected: Bearer <token>)",
			})
			return
		}

		claims, err := s.pa.IdP.ValidateToken(parts[1])
		if err != nil {
			log.Printf("[AUTH] Token validation failed: %v", err)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid or expired token",
			})
			return
		}

		// Check token revocation
		if claims.ID != "" && s.pa.Store.IsTokenRevoked(claims.ID) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "token has been revoked",
			})
			return
		}

		// Check admin role for admin endpoints
		if strings.HasPrefix(r.URL.Path, "/api/admin") && claims.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "admin access required",
			})
			return
		}

		// Store claims in request context via headers (lightweight approach)
		r.Header.Set("X-User-ID", claims.UserID)
		r.Header.Set("X-Username", claims.Username)
		r.Header.Set("X-User-Role", claims.Role)

		next.ServeHTTP(w, r)
	})
}

// statusResponseWriter wraps http.ResponseWriter to capture the status code
type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
