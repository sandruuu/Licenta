package transport

import (
	"crypto/x509"
	"log"
	"strings"
	"time"

	paenrollment "pdp/pa/enrollment"
)

// checkEnrollRateLimit enforces configured per-IP rate limiting on enrollment entry points.
func (s *Server) checkEnrollRateLimit(ip string) bool {
	s.enrollLimiterMu.Lock()
	now := time.Now()
	appCfg := s.appConfig()
	entry, ok := s.enrollLimiter[ip]
	if !ok || now.After(entry.resetAt) {
		s.enrollLimiter[ip] = &enrollRateEntry{count: 1, resetAt: now.Add(appCfg.Runtime.EnrollRateLimitWindow)}
		s.enrollLimiterMu.Unlock()
		if s.pa != nil && s.pa.Store != nil {
			go func() {
				if allowed, err := s.pa.Store.CheckEnrollRateLimit(ip, appCfg.Runtime.EnrollRateLimitWindow, appCfg.Runtime.EnrollRateLimitMax); err == nil && !allowed {
					log.Printf("[ENROLL] Persistent rate limiter denied IP %s (in-memory passed)", ip)
				}
			}()
		}
		return true
	}
	entry.count++
	if entry.count <= appCfg.Runtime.EnrollRateLimitMax {
		s.enrollLimiterMu.Unlock()
		return true
	}
	s.enrollLimiterMu.Unlock()
	if s.pa != nil && s.pa.Store != nil {
		allowed, err := s.pa.Store.CheckEnrollRateLimit(ip, appCfg.Runtime.EnrollRateLimitWindow, appCfg.Runtime.EnrollRateLimitMax)
		if err != nil {
			log.Printf("[ENROLL] Persistent rate limit check failed for IP %s: %v", ip, err)
			return false
		}
		return allowed
	}
	return false
}

func canonicalCSRPEM(input string) (string, error) {
	return paenrollment.CanonicalCSRPEM(input)
}

func parseCSR(input string) (*x509.CertificateRequest, []byte, error) {
	return paenrollment.ParseCSR(input)
}

func computeCSRFingerprint(csrPEM string) (string, error) {
	return paenrollment.ComputeCSRFingerprint(csrPEM)
}

func shortFingerprint(value string) string {
	return paenrollment.ShortFingerprint(value)
}

func enrollmentClientMessage(err error) string {
	message := err.Error()
	for _, prefix := range []string{
		paenrollment.ErrInvalidRequest.Error(),
		paenrollment.ErrForbidden.Error(),
		paenrollment.ErrNotFound.Error(),
		paenrollment.ErrInvalidState.Error(),
		paenrollment.ErrInvalidCSR.Error(),
	} {
		if strings.HasPrefix(message, prefix+": ") {
			return strings.TrimPrefix(message, prefix+": ")
		}
	}
	return message
}
