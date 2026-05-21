package transport

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	paenrollment "pdp/pa/enrollment"
)

func bearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("bearer token required")
	}
	return strings.TrimSpace(parts[1]), nil
}

func validateCSREmailIdentity(csr *x509.CertificateRequest, username string) error {
	return paenrollment.ValidateCSREmailIdentity(csr, username)
}
