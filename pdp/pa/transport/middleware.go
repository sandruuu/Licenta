package transport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pdp/models"
	paauth "pdp/pa/auth"
	paenrollment "pdp/pa/enrollment"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const (
	deviceEnrollmentContextKey contextKey = "authenticatedDeviceEnrollment"
	adminClaimsContextKey      contextKey = "authenticatedAdminClaims"
	adminSessionContextKey     contextKey = "authenticatedAdminSession"
)

func deviceEnrollmentFromContext(r *http.Request) (*models.DeviceEnrollment, bool) {
	enrollment, ok := r.Context().Value(deviceEnrollmentContextKey).(*models.DeviceEnrollment)
	return enrollment, ok
}

func deviceEnrollmentFromContextValue(ctx context.Context) (*models.DeviceEnrollment, bool) {
	enrollment, ok := ctx.Value(deviceEnrollmentContextKey).(*models.DeviceEnrollment)
	return enrollment, ok
}

func adminClaimsFromContext(r *http.Request) (*paauth.CustomClaims, bool) {
	if r == nil {
		return nil, false
	}
	claims, ok := r.Context().Value(adminClaimsContextKey).(*paauth.CustomClaims)
	return claims, ok
}

func adminSessionFromContext(r *http.Request) (*adminSessionRecord, bool) {
	if r == nil {
		return nil, false
	}
	session, ok := r.Context().Value(adminSessionContextKey).(*adminSessionRecord)
	return session, ok
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

// securityHeadersMiddleware adds standard security headers to all responses.
func securityHeadersMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", contentSecurityPolicy(r))
			w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			next.ServeHTTP(w, r)
		})
	}
}

func contentSecurityPolicy(r *http.Request) string {
	if r != nil && strings.HasPrefix(r.URL.Path, "/browser/step-up/") {
		return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
	}
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
	if r == nil || (!strings.HasPrefix(r.URL.Path, "/browser/enroll/") && !strings.HasPrefix(r.URL.Path, "/browser/session/")) {
		policy += "; form-action 'self'"
	}
	return policy
}

// corsMiddleware adds CORS headers for configured public origins.
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && isAllowedPDPOrigin(origin, allowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
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

func isAllowedPDPOrigin(origin string, extraOrigins []string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
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
				"error": "mTLS is not configured on the PDP server",
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

func (s *Server) deviceAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerCert, ok := clientCertificateFromRequest(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "client certificate required for device authentication",
			})
			return
		}

		enrollment, statusCode, errorMessage := s.authenticateDeviceCertificate(peerCert)
		if statusCode != 0 {
			writeJSON(w, statusCode, map[string]string{"error": errorMessage})
			return
		}

		ctx := context.WithValue(r.Context(), deviceEnrollmentContextKey, enrollment)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authenticateDeviceCertificate(peerCert *x509.Certificate) (*models.DeviceEnrollment, int, string) {
	if peerCert == nil {
		return nil, http.StatusUnauthorized, "client certificate required for device authentication"
	}

	deviceID := paenrollment.CertificateDeviceID(peerCert)
	if deviceID == "" {
		return nil, http.StatusUnauthorized, "client certificate has no device identity"
	}

	enrollment, found := s.pa.Store.GetDeviceEnrollmentByComponent(deviceID, "endpoint")
	if !found || enrollment.Status != "approved" {
		log.Printf("[AUTH] Rejected device request: CN=%q not enrolled or not approved", deviceID)
		return nil, http.StatusForbidden, "device not enrolled or certificate CN not recognized"
	}

	if enrollment.CertFingerprint == "" {
		log.Printf("[AUTH] Rejected device request: CN=%q enrolled but has no certificate fingerprint on record", deviceID)
		return nil, http.StatusForbidden, "device enrollment record is incomplete (missing certificate fingerprint)"
	}

	fingerprint := clientCertificateFingerprint(peerCert)
	if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(enrollment.CertFingerprint)) != 1 {
		log.Printf("[AUTH] Rejected device request: CN=%q fingerprint mismatch", deviceID)
		return nil, http.StatusForbidden, "certificate fingerprint does not match enrollment record"
	}

	if !enrollment.ExpiresAt.IsZero() && time.Now().After(enrollment.ExpiresAt) {
		return nil, http.StatusForbidden, "device certificate enrollment has expired"
	}

	return enrollment, 0, ""
}

func clientCertificateFromRequest(r *http.Request) (*x509.Certificate, bool) {
	if r == nil || r.TLS == nil {
		return nil, false
	}
	if len(r.TLS.PeerCertificates) > 0 && r.TLS.PeerCertificates[0] != nil {
		return r.TLS.PeerCertificates[0], true
	}
	if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 && r.TLS.VerifiedChains[0][0] != nil {
		return r.TLS.VerifiedChains[0][0], true
	}
	return nil, false
}

func clientCertificateFingerprint(cert *x509.Certificate) string {
	fp := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fp[:])
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

		// Admin API tokens must be issued after the dashboard MFA step.
		claims, err := s.pa.Auth.ValidateToken(parts[1])
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

		if strings.TrimSpace(claims.Purpose) != "" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "token is not valid for dashboard access",
			})
			return
		}

		if strings.TrimSpace(claims.SessionID) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "dashboard session is required",
			})
			return
		}

		session, ok := s.adminSessions.validateAccess(claims)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "dashboard session is no longer active",
			})
			return
		}

		user, exists := s.pa.Auth.Users.GetUser(claims.UserID)
		if !exists || user == nil || user.Disabled || user.Role != "platform_admin" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "user is not available",
			})
			return
		}

		// Check admin role for admin endpoints
		if strings.HasPrefix(r.URL.Path, "/api/admin") && claims.Role != "platform_admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "platform administrator access required",
			})
			return
		}

		// Store claims in request context via headers (lightweight approach)
		r.Header.Set("X-User-ID", claims.UserID)
		r.Header.Set("X-Username", claims.Username)
		r.Header.Set("X-User-Role", claims.Role)

		ctx := context.WithValue(r.Context(), adminClaimsContextKey, claims)
		ctx = context.WithValue(ctx, adminSessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
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
