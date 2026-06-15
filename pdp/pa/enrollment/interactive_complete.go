package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"pdp/certs"
	"pdp/models"
	"pdp/util"
)

func (s *Service) CompleteInteractiveSession(req InteractiveCompleteRequest) (*InteractiveCompleteResult, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	if s.interactiveIssuer == nil && s.signer == nil {
		return nil, fmt.Errorf("PKI signer not initialized")
	}

	var result *InteractiveCompleteResult
	err := s.withInteractiveSessionLock(req.SessionID, func() error {
		session, err := s.interactiveSessionForCompletion(req)
		if err != nil {
			return err
		}
		csrPEM, csr, csrDER, spkiHash, err := validateCompletionCSR(req.CSRPEM, session.CSRHash, session.SPKIHash)
		if err != nil {
			return err
		}
		canonicalPayload, err := canonicalEnrollmentProof(EnrollmentProofPayload{
			Type:                InteractiveProofType,
			EnrollmentSessionID: session.ID,
			DeviceNonce:         session.DeviceNonce,
			DeviceChallenge:     session.DeviceChallenge,
			CSRHash:             session.CSRHash,
			SPKIHash:            session.SPKIHash,
			PDPOrigin:           strings.TrimSpace(req.PDPOrigin),
		})
		if err != nil {
			return err
		}
		if len(req.ProofPayload) > 0 && string(req.ProofPayload) != string(canonicalPayload) {
			return fmt.Errorf("%w: proof payload does not match transaction", ErrForbidden)
		}
		if err := verifyEnrollmentProof(csr, canonicalPayload, req.ProofSignature); err != nil {
			return err
		}

		deviceID, err := s.newUniqueDeviceID()
		if err != nil {
			return err
		}
		certBundle, err := s.issueInteractiveCertificate([]byte(csrPEM), deviceID)
		if err != nil {
			return err
		}
		leafPEM, chainPEM := splitCertificateBundle(certBundle)
		if strings.TrimSpace(leafPEM) == "" {
			return fmt.Errorf("%w: certificate bundle is empty", ErrSigning)
		}
		if issuedDeviceID := certificateDeviceID([]byte(leafPEM)); issuedDeviceID != deviceID {
			return fmt.Errorf("%w: issued certificate identity %q does not match PDP device_id %q", ErrSigning, issuedDeviceID, deviceID)
		}
		certThumbprint, _ := certs.CertFingerprint([]byte(leafPEM))
		certSerial := certificateSerial([]byte(leafPEM))
		expiresAt := certificateExpiry([]byte(leafPEM))
		now := time.Now().UTC()
		enrollment := &models.DeviceEnrollment{
			ID:                   session.ID,
			DeviceID:             deviceID,
			Component:            "endpoint",
			Hostname:             session.Hostname,
			PublicKeyFingerprint: spkiHash,
			CertFingerprint:      certThumbprint,
			CertSerial:           certSerial,
			Status:               "approved",
			CSRPEM:               csrPEM,
			CertPEM:              string(certBundle),
			EnrolledAt:           now,
			ExpiresAt:            expiresAt,
			ApprovedBy:           session.AuthenticatedUsername,
			UserID:               session.AuthenticatedUserID,
			Username:             firstNonEmpty(session.AuthenticatedUserEmail, session.AuthenticatedUsername),
			OrganizationID:       session.AuthRealmID,
		}
		s.store.SaveDeviceEnrollment(enrollment)
		_ = csrDER // kept explicit: CSR DER was validated against session hash above.

		s.deleteInteractiveSession(session.ID)

		result = &InteractiveCompleteResult{
			DeviceID:               deviceID,
			AuthRealmID:            session.AuthRealmID,
			IDPProfileID:           session.IDPProfileID,
			CertificatePEM:         leafPEM,
			CertificateChainPEM:    chainPEM,
			CertificateThumbprint:  certThumbprint,
			ExpiresAt:              expiresAt,
			EnrolledByIDPProfileID: session.IDPProfileID,
		}
		return nil
	})
	return result, err
}

func (s *Service) interactiveSessionForCompletion(req InteractiveCompleteRequest) (*InteractiveSession, error) {
	session, ok := s.getInteractiveSession(req.SessionID)
	if !ok || session == nil {
		return nil, ErrNotFound
	}
	if err := validateInteractivePollSecrets(session, req.DeviceNonce, req.PollSecret); err != nil {
		return nil, err
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, ErrExpiredSession
	}
	if session.Status != InteractiveStatusReadyForDeviceProof {
		return nil, fmt.Errorf("%w: enrollment is not ready for device proof", ErrInvalidState)
	}
	if session.SingleUseConsumed {
		return nil, fmt.Errorf("%w: enrollment session already consumed", ErrForbidden)
	}
	copy := *session
	return &copy, nil
}

func validateInteractivePollSecrets(session *InteractiveSession, deviceNonce, pollSecret string) error {
	if session == nil {
		return ErrNotFound
	}
	if session.DeviceNonce != strings.TrimSpace(deviceNonce) {
		return fmt.Errorf("%w: device_nonce does not match enrollment session", ErrForbidden)
	}
	if session.PollSecretHash != sha256HexString(strings.TrimSpace(pollSecret)) {
		return fmt.Errorf("%w: poll_secret does not match enrollment session", ErrForbidden)
	}
	return nil
}

func validateCompletionCSR(rawCSR, expectedCSRHash, expectedSPKIHash string) (string, *x509.CertificateRequest, []byte, string, error) {
	csrPEM, err := CanonicalCSRPEM(rawCSR)
	if err != nil {
		return "", nil, nil, "", fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	csr, csrDER, err := ParseCSR(csrPEM)
	if err != nil {
		return "", nil, nil, "", fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if hashBytes(csrDER) != normalizeHex(expectedCSRHash) {
		return "", nil, nil, "", fmt.Errorf("%w: CSR hash does not match enrollment session", ErrForbidden)
	}
	spkiHash, err := ComputeCSRFingerprint(csrPEM)
	if err != nil {
		return "", nil, nil, "", fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if normalizeHex(spkiHash) != normalizeHex(expectedSPKIHash) {
		return "", nil, nil, "", fmt.Errorf("%w: SPKI hash does not match enrollment session", ErrForbidden)
	}
	return csrPEM, csr, csrDER, spkiHash, nil
}

func verifyEnrollmentProof(csr *x509.CertificateRequest, payload, signature []byte) error {
	if csr == nil {
		return fmt.Errorf("%w: CSR is required for proof verification", ErrInvalidCSR)
	}
	if len(signature) == 0 {
		return fmt.Errorf("%w: proof signature is required", ErrInvalidRequest)
	}
	digest := sha256.Sum256(payload)
	switch publicKey := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if publicKey.Curve != elliptic.P256() {
			return fmt.Errorf("%w: CSR public key must be ECDSA P-256", ErrInvalidCSR)
		}
		if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
			return fmt.Errorf("%w: proof signature is invalid", ErrForbidden)
		}
	default:
		return fmt.Errorf("%w: unsupported CSR public key type", ErrInvalidCSR)
	}
	return nil
}

func (s *Service) issueInteractiveCertificate(csrPEM []byte, deviceID string) ([]byte, error) {
	role := s.resolveDeviceRole("endpoint")
	if s.interactiveIssuer != nil {
		certPEM, err := s.interactiveIssuer(csrPEM, s.certificateValidityDays, role, deviceID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSigning, err)
		}
		return certPEM, nil
	}
	certPEM, err := s.signer(csrPEM, s.certificateValidityDays, role)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigning, err)
	}
	return certPEM, nil
}

func (s *Service) newUniqueDeviceID() (string, error) {
	for i := 0; i < 8; i++ {
		deviceID, err := util.GenerateID("dvc")
		if err != nil {
			return "", err
		}
		if _, found := s.store.GetDeviceEnrollmentByDeviceID(deviceID); !found {
			return deviceID, nil
		}
	}
	return "", fmt.Errorf("failed to allocate unique device_id")
}

func canonicalEnrollmentProof(payload EnrollmentProofPayload) ([]byte, error) {
	return json.Marshal(payload)
}

func randomURLToken(length int) (string, error) {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func sha256HexString(value string) string {
	return hashBytes([]byte(value))
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeHex(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func splitCertificateBundle(bundle []byte) (string, string) {
	remaining := bundle
	var leaf strings.Builder
	var chain strings.Builder
	first := true
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			encoded := string(pem.EncodeToMemory(block))
			if first {
				leaf.WriteString(encoded)
				first = false
			} else {
				chain.WriteString(encoded)
			}
		}
		remaining = rest
	}
	return leaf.String(), chain.String()
}

func certificateExpiry(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Now().UTC().Add(time.Duration(defaultCertificateValidityDays) * 24 * time.Hour)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Now().UTC().Add(time.Duration(defaultCertificateValidityDays) * 24 * time.Hour)
	}
	return cert.NotAfter.UTC()
}

func certificateDeviceID(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return CertificateDeviceID(cert)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
