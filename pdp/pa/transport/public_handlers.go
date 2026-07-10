package transport

import (
	"context"
	"net/http"
	"os"
	"time"

	"pdp/certs"
)

// Public trust and health endpoints.

// handleCACert returns the active issuer CA certificate (public info, no auth needed).
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

// handleCertFingerprint returns the PDP server TLS certificate fingerprint.
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
