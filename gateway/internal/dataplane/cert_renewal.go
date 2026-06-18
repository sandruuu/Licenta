package dataplane

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"net"
	"os"
	"strings"
	"time"

	gatewaycert "gateway/internal/cert"
	"gateway/internal/config"
)

func (gateway *Gateway) certExpiryLoop() {
	gateway.checkCertExpiry()
	ticker := time.NewTicker(certExpiryCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.checkCertExpiry()
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) checkCertExpiry() {
	certFiles := map[string]string{
		"gateway_cert": config.GatewayCertPath,
		"pa_ca":        config.PACAPath,
	}
	for label, path := range certFiles {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[GATEWAY] cannot read certificate %s (%s): %v", label, path, err)
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		remaining := time.Until(cert.NotAfter)
		if remaining < 0 {
			log.Printf("[GATEWAY] certificate %s expired on %s", label, cert.NotAfter.Format(time.RFC3339))
		} else if remaining < certExpiryCriticalWindow {
			log.Printf("[GATEWAY] certificate %s expires soon in %s", label, remaining.Round(time.Hour))
		} else if remaining < certExpiryWarningWindow {
			log.Printf("[GATEWAY] certificate %s expires in %d days", label, int(remaining.Hours()/24))
		}
	}
}

func (gateway *Gateway) StartCertRenewalLoop(ctx context.Context) {
	gateway.renewCertIfNeeded(certRenewalWindow)
	ticker := time.NewTicker(certRenewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.renewCertIfNeeded(certRenewalWindow)
		case <-ctx.Done():
			return
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) renewCertIfNeeded(threshold time.Duration) {
	if gateway.controlPlane == nil {
		return
	}
	certPath := config.GatewayCertPath
	keyPath := config.GatewayKeyPath
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Printf("[GATEWAY] cannot read mTLS certificate for renewal: %v", err)
		return
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		log.Printf("[GATEWAY] cannot decode mTLS certificate for renewal")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("[GATEWAY] cannot parse mTLS certificate for renewal: %v", err)
		return
	}
	remaining := time.Until(cert.NotAfter)
	if remaining > threshold {
		return
	}

	newKey, err := gatewaycert.GenerateGatewayPrivateKey()
	if err != nil {
		log.Printf("[GATEWAY] generate renewal key failed: %v", err)
		return
	}
	gatewayID := gateway.identityForCertificateRenewal()
	if gatewayID == "" {
		log.Printf("[GATEWAY] cannot renew mTLS certificate: gateway identity is required")
		return
	}
	ekuExtension, err := gatewaycert.GatewayExtendedKeyUsageExtension()
	if err != nil {
		log.Printf("[GATEWAY] build renewal EKU extension failed: %v", err)
		return
	}
	renewalCSR := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: gatewayID},
		DNSNames:    append([]string(nil), cert.DNSNames...),
		IPAddresses: append([]net.IP(nil), cert.IPAddresses...),
		ExtraExtensions: []pkix.Extension{
			ekuExtension,
		},
	}
	renewalCSR.URIs = append(renewalCSR.URIs, cert.URIs...)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, renewalCSR, newKey)
	if err != nil {
		log.Printf("[GATEWAY] create renewal CSR failed: %v", err)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	result, err := gateway.controlPlane.RenewCert(string(csrPEM))
	if err != nil {
		log.Printf("[GATEWAY] certificate renewal request failed: %v", err)
		return
	}
	renewedCert, err := gatewaycert.ParseGatewayCertificatePEM([]byte(result.CertPEM))
	if err != nil {
		log.Printf("[GATEWAY] renewed certificate parse failed: %v", err)
		return
	}
	if err := gatewaycert.ValidateGatewayCertificate(renewedCert); err != nil {
		log.Printf("[GATEWAY] renewed certificate rejected: %v", err)
		return
	}
	keyPEM, err := gatewaycert.EncodePrivateKeyPEM(newKey)
	if err != nil {
		log.Printf("[GATEWAY] encode renewal key failed: %v", err)
		return
	}
	if err := config.AtomicWriteFile(keyPath, keyPEM, 0o600); err != nil {
		log.Printf("[GATEWAY] write renewal key failed: %v", err)
		return
	}
	if err := config.AtomicWriteFile(certPath, []byte(result.CertPEM), 0o644); err != nil {
		log.Printf("[GATEWAY] write renewed certificate failed: %v", err)
		return
	}
	if result.CAPEM != "" {
		if err := config.AtomicWriteFile(config.PACAPath, []byte(result.CAPEM), 0o644); err != nil {
			log.Printf("[GATEWAY] write renewed CA failed: %v", err)
		}
	}
	if err := gateway.controlPlane.ReloadTLSCert(certPath, keyPath); err != nil {
		log.Printf("[GATEWAY] reload renewed mTLS certificate failed: %v", err)
		return
	}
	log.Printf("[GATEWAY] renewed mTLS certificate for gateway_id=%s", gatewayID)
}

func (gateway *Gateway) identityForCertificateRenewal() string {
	if gateway == nil || gateway.cfg == nil {
		return ""
	}
	if gateway.cfg.ControlPlane != nil {
		if gatewayID := strings.TrimSpace(gateway.cfg.ControlPlane.GatewayID); gatewayID != "" {
			return gatewayID
		}
	}
	return ""
}
