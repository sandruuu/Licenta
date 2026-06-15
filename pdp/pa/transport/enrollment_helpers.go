package transport

import (
	"log"
	"strings"

	paenrollment "pdp/pa/enrollment"
)

// checkEnrollRateLimit enforces configured per-IP rate limiting on enrollment entry points.
func (s *Server) checkEnrollRateLimit(ip string) bool {
	appCfg := s.appConfig()
	if s.pa == nil || s.pa.Runtime == nil {
		return false
	}
	allowed, err := s.pa.Runtime.Allow("enroll", ip, appCfg.Runtime.EnrollRateLimitWindow, appCfg.Runtime.EnrollRateLimitMax)
	if err != nil {
		log.Printf("[ENROLL] Redis rate limit check failed for IP %s: %v", ip, err)
		return false
	}
	return allowed
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
