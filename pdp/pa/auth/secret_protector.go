package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"pdp/config"
	"pdp/pki"
)

const protectedSecretPrefix = "enc:v1:"

// SecretProtector encrypts MFA-related values before they are written to the
// local database. Values without the enc:v1 prefix are treated as legacy
// plaintext so existing deployments can migrate lazily on the next update.
type SecretProtector struct {
	aead       cipher.AEAD
	persistent bool
}

func NewSecretProtector(cfg *config.Config) (*SecretProtector, error) {
	key, persistent, err := loadOrCreateSecretKey(cfg)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create MFA secret cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create MFA secret protector: %w", err)
	}
	return &SecretProtector{aead: aead, persistent: persistent}, nil
}

func (p *SecretProtector) Protect(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || p == nil || p.aead == nil {
		return value, nil
	}
	if strings.HasPrefix(value, protectedSecretPrefix) {
		return value, nil
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate MFA secret nonce: %w", err)
	}
	ciphertext := p.aead.Seal(nil, nonce, []byte(value), nil)
	payload := append(nonce, ciphertext...)
	return protectedSecretPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (p *SecretProtector) Unprotect(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || p == nil || p.aead == nil || !strings.HasPrefix(value, protectedSecretPrefix) {
		return value, nil
	}
	encoded := strings.TrimPrefix(value, protectedSecretPrefix)
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode protected MFA secret: %w", err)
	}
	if len(payload) <= p.aead.NonceSize() {
		return "", fmt.Errorf("protected MFA secret is truncated")
	}
	nonce := payload[:p.aead.NonceSize()]
	ciphertext := payload[p.aead.NonceSize():]
	plaintext, err := p.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt protected MFA secret: %w", err)
	}
	return string(plaintext), nil
}

func (p *SecretProtector) Persistent() bool {
	return p != nil && p.persistent
}

func loadOrCreateSecretKey(cfg *config.Config) ([]byte, bool, error) {
	dataDir := ""
	if cfg != nil {
		dataDir = strings.TrimSpace(cfg.DataDir)
	}
	if vaultTransitAvailable(cfg) {
		key, err := loadOrCreateVaultWrappedSecretKey(cfg)
		return key, true, err
	}
	if dataDir == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, false, fmt.Errorf("generate in-memory MFA secret key: %w", err)
		}
		return key, false, nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, false, fmt.Errorf("create data directory for MFA secret key: %w", err)
	}
	path := filepath.Join(dataDir, "mfa_secret.key")
	if data, err := os.ReadFile(path); err == nil {
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, false, fmt.Errorf("decode MFA secret key file: %w", err)
		}
		if len(key) != 32 {
			return nil, false, fmt.Errorf("MFA secret key must be 32 bytes")
		}
		return key, true, nil
	} else if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("read MFA secret key file: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, false, fmt.Errorf("generate MFA secret key: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return nil, false, fmt.Errorf("write MFA secret key file: %w", err)
	}
	return key, true, nil
}

func vaultTransitAvailable(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	return strings.TrimSpace(cfg.PKIURL) != "" &&
		strings.TrimSpace(cfg.PKIToken) != "" &&
		strings.TrimSpace(cfg.MFATransitKey) != "" &&
		strings.TrimSpace(cfg.MFASecretKeyEncryptedPath) != ""
}

func loadOrCreateVaultWrappedSecretKey(cfg *config.Config) ([]byte, error) {
	path := strings.TrimSpace(cfg.MFASecretKeyEncryptedPath)
	vaultCfg := pki.VaultConfig{
		URL:            cfg.PKIURL,
		Token:          cfg.PKIToken,
		PKIPath:        cfg.PKIPath,
		TransitKeyName: cfg.MFATransitKey,
		CAFile:         cfg.PKICAFile,
		ServerName:     cfg.PKIServerName,
		Timeout:        cfg.PKITimeout,
	}
	ctx := context.Background()
	if data, err := os.ReadFile(path); err == nil {
		plaintext, err := pki.TransitDecryptKey(ctx, vaultCfg, data)
		if err != nil {
			return nil, fmt.Errorf("decrypt MFA data key via Vault Transit: %w", err)
		}
		return parseMFASecretKeyBytes(plaintext)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read encrypted MFA data key: %w", err)
	}

	legacyPath := filepath.Join(strings.TrimSpace(cfg.DataDir), "mfa_secret.key")
	if legacyKey, err := readLocalMFASecretKey(legacyPath); err == nil {
		if err := writeVaultWrappedMFASecretKey(ctx, vaultCfg, path, legacyKey); err != nil {
			return nil, err
		}
		if err := os.Remove(legacyPath); err != nil && !os.IsNotExist(err) {
			log.Printf("[AUTH] Could not remove legacy plaintext MFA key %s after Vault wrapping: %v", legacyPath, err)
		}
		log.Printf("[AUTH] Migrated MFA secret key from plaintext local file to Vault Transit wrapped file")
		return legacyKey, nil
	} else if !os.IsNotExist(err) && strings.TrimSpace(cfg.DataDir) != "" {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate MFA data key: %w", err)
	}
	if err := writeVaultWrappedMFASecretKey(ctx, vaultCfg, path, key); err != nil {
		return nil, err
	}
	return key, nil
}

func writeVaultWrappedMFASecretKey(ctx context.Context, vaultCfg pki.VaultConfig, path string, key []byte) error {
	ciphertext, err := pki.TransitEncryptKey(ctx, vaultCfg, key)
	if err != nil {
		return fmt.Errorf("encrypt MFA data key via Vault Transit: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create MFA encrypted key directory: %w", err)
	}
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write encrypted MFA data key: %w", err)
	}
	return nil
}

func readLocalMFASecretKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, os.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseMFASecretKeyBytes([]byte(strings.TrimSpace(string(data))))
}

func parseMFASecretKeyBytes(data []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(data))
	if decoded, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(data) == 32 {
		return append([]byte(nil), data...), nil
	}
	return nil, fmt.Errorf("MFA secret key must be 32 bytes")
}
