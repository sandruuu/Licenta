package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"pdp/config"
	"pdp/pki"
	"pdp/runtime/redisstate"
)

const (
	distributedLockTTL  = 2 * time.Minute
	distributedLockWait = 2 * time.Minute
)

type pdpIdentityState struct {
	active atomic.Pointer[tls.Certificate]
}

func initializePDPIdentity(ctx context.Context, cfg *config.Config, runtimeState *redisstate.Client) *pdpIdentityState {
	state := &pdpIdentityState{}
	vaultCfg, err := pdpVaultConfig(cfg)
	if err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Config error: %v", err)
	}
	privKey, cert, err := restoreOrEnrollPDPIdentity(ctx, cfg, vaultCfg, runtimeState)
	if err != nil {
		log.Fatalf("[PDP-SELF-ENROLL] Identity error: %v", err)
	}

	state.storeCertificate(cert)
	go maintainPDPIdentity(ctx, cfg, vaultCfg, privKey, runtimeState, state)
	return state
}

func pdpVaultConfig(cfg *config.Config) (pki.VaultConfig, error) {
	if cfg == nil {
		return pki.VaultConfig{}, fmt.Errorf("PDP config is required")
	}
	missing := []string{}
	required := map[string]string{
		"pdp_fqdn":               cfg.PDPFQDN,
		"pki_url":                cfg.PKIURL,
		"pki_token":              cfg.PKIToken,
		"pki_path":               cfg.PKIPath,
		"pki_role_pdp":           cfg.PKIRolePDP,
		"pki_transit_key":        cfg.PKITransitKey,
		"pdp_key_encrypted_path": cfg.PDPKeyEncryptedPath,
		"tls_cert":               cfg.TLSCert,
		"mtls_ca":                cfg.MTLSCA,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return pki.VaultConfig{}, fmt.Errorf("missing required production PKI settings: %s", strings.Join(missing, ", "))
	}
	return pki.VaultConfig{
		URL:            cfg.PKIURL,
		Token:          cfg.PKIToken,
		PKIPath:        cfg.PKIPath,
		TransitKeyName: cfg.PKITransitKey,
		CAFile:         cfg.PKICAFile,
		ServerName:     cfg.PKIServerName,
		Timeout:        cfg.PKITimeout,
	}, nil
}

func restoreOrEnrollPDPIdentity(ctx context.Context, cfg *config.Config, vaultCfg pki.VaultConfig, runtimeState *redisstate.Client) (*ecdsa.PrivateKey, *tls.Certificate, error) {
	if runtimeState == nil {
		return nil, nil, fmt.Errorf("Redis runtime state is required for PDP identity lock")
	}
	var privKey *ecdsa.PrivateKey
	var cert *tls.Certificate
	err := runtimeState.WithLock(ctx, "pdp-identity", distributedLockTTL, distributedLockWait, func() error {
		var err error
		privKey, err = pki.RestoreOrCreateKey(ctx, vaultCfg, cfg.PDPKeyEncryptedPath)
		if err != nil {
			return fmt.Errorf("restore PDP private key: %w", err)
		}
		if pdpCertificateReady(cfg) {
			cert, err = pki.LoadCertificateWithKey(cfg.TLSCert, privKey)
			if err == nil {
				log.Printf("[PDP-SELF-ENROLL] Loaded existing PDP certificate from %s", cfg.TLSCert)
				return nil
			}
			log.Printf("[PDP-SELF-ENROLL] Existing PDP certificate could not be loaded, requesting a new one: %v", err)
		}
		enrollResult, err := pki.SelfEnroll(ctx, vaultCfg, cfg.PDPFQDN, cfg.PKIRolePDP, cfg.CertificateDNSNames(), privKey)
		if err != nil {
			return fmt.Errorf("self-enroll PDP certificate: %w", err)
		}
		if err := pki.SaveEnrolledCert(enrollResult, cfg.TLSCert, cfg.MTLSCA, cfg.DataDir); err != nil {
			return fmt.Errorf("save PDP certificate: %w", err)
		}
		cert = enrollResult.Certificate
		log.Printf("[PDP-SELF-ENROLL] PDP certificate ready (expires=%s)", enrollResult.ExpiresAt.Format(time.RFC3339))
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return privKey, cert, nil
}

func pdpCertificateReady(cfg *config.Config) bool {
	if cfg == nil || pki.CertificateNeedsRenewalForNames(cfg.TLSCert, cfg.Runtime.CertificateRenewBefore, cfg.CertificateDNSNames()) {
		return false
	}
	if _, err := os.Stat(cfg.MTLSCA); err != nil {
		return false
	}
	return true
}

func maintainPDPIdentity(ctx context.Context, cfg *config.Config, vaultCfg pki.VaultConfig, privKey *ecdsa.PrivateKey, runtimeState *redisstate.Client, state *pdpIdentityState) {
	interval := cfg.Runtime.PKIRenewCheckInterval
	if interval <= 0 || interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if pdpCertificateReady(cfg) {
				if cert, err := pki.LoadCertificateWithKey(cfg.TLSCert, privKey); err == nil {
					state.storeCertificate(cert)
					continue
				}
			}
			if err := renewPDPIdentityIfNeeded(ctx, cfg, vaultCfg, privKey, runtimeState, state); err != nil {
				log.Printf("[PDP-SELF-ENROLL] Certificate maintenance failed: %v", err)
			}
		}
	}
}

func renewPDPIdentityIfNeeded(ctx context.Context, cfg *config.Config, vaultCfg pki.VaultConfig, privKey *ecdsa.PrivateKey, runtimeState *redisstate.Client, state *pdpIdentityState) error {
	return runtimeState.WithLock(ctx, "pdp-identity", distributedLockTTL, distributedLockWait, func() error {
		if pdpCertificateReady(cfg) {
			cert, err := pki.LoadCertificateWithKey(cfg.TLSCert, privKey)
			if err == nil {
				state.storeCertificate(cert)
				return nil
			}
			log.Printf("[PDP-SELF-ENROLL] PDP certificate reload failed before renewal: %v", err)
		}
		enrollResult, err := pki.SelfEnroll(ctx, vaultCfg, cfg.PDPFQDN, cfg.PKIRolePDP, cfg.CertificateDNSNames(), privKey)
		if err != nil {
			return fmt.Errorf("renew PDP certificate: %w", err)
		}
		if err := pki.SaveEnrolledCert(enrollResult, cfg.TLSCert, cfg.MTLSCA, cfg.DataDir); err != nil {
			return fmt.Errorf("save renewed PDP certificate: %w", err)
		}
		state.storeCertificate(enrollResult.Certificate)
		log.Printf("[PDP-SELF-ENROLL] Certificate renewed (expires=%s)", enrollResult.ExpiresAt.Format(time.RFC3339))
		return nil
	})
}

func (s *pdpIdentityState) storeCertificate(cert *tls.Certificate) {
	if cert != nil {
		s.active.Store(cert)
	}
}

func (s *pdpIdentityState) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := s.active.Load()
	if cert == nil {
		return nil, fmt.Errorf("PDP TLS certificate is not initialized")
	}
	return cert, nil
}
