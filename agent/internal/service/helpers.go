package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"agent/internal/shared/ipc"
)

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (service *Service) setEnrollmentLastError(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.enrollment.LastError = strings.TrimSpace(message)
}

func (service *Service) markEnrollmentFailed(err error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.enrollment.State = ipc.EnrollmentStateFailed
	service.enrollment.LastError = err.Error()
}

func randomNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("nonce-%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(buf)
}
