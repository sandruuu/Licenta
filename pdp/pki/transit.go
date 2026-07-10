package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func transitKeyName(cfg VaultConfig) (string, error) {
	name := strings.Trim(strings.TrimSpace(cfg.TransitKeyName), "/")
	if name == "" {
		return "", fmt.Errorf("vault transit key name is required")
	}
	return name, nil
}

// TransitEncryptKey encrypts a PEM-encoded private key using Vault Transit.
func TransitEncryptKey(ctx context.Context, cfg VaultConfig, keyPEM []byte) ([]byte, error) {
	client, err := NewVaultClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Vault client: %w", err)
	}
	keyName, err := transitKeyName(cfg)
	if err != nil {
		return nil, err
	}

	plaintextB64 := base64.StdEncoding.EncodeToString(keyPEM)
	reqBody := map[string]interface{}{
		"plaintext": plaintextB64,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal transit encrypt request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/transit/encrypt/%s", client.baseURL, keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create transit encrypt request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("X-Vault-Token", client.token)
	}

	resp, err := client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault transit encrypt failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read transit encrypt response: %w", err)
	}

	var payload struct {
		Errors []string `json:"errors"`
		Data   struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, fmt.Errorf("parse transit encrypt response: %w", err)
	}

	if resp.StatusCode >= 400 {
		if len(payload.Errors) > 0 {
			return nil, fmt.Errorf("vault transit encrypt failed: %s", strings.Join(payload.Errors, "; "))
		}
		return nil, fmt.Errorf("vault transit encrypt failed with HTTP %d", resp.StatusCode)
	}

	ciphertext := strings.TrimSpace(payload.Data.Ciphertext)
	if ciphertext == "" {
		return nil, fmt.Errorf("vault transit returned empty ciphertext")
	}

	return []byte(ciphertext), nil
}

// TransitDecryptKey decrypts a ciphertext obtained from TransitEncryptKey
// and returns the original PEM-encoded private key.
func TransitDecryptKey(ctx context.Context, cfg VaultConfig, ciphertext []byte) ([]byte, error) {
	client, err := NewVaultClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Vault client: %w", err)
	}
	keyName, err := transitKeyName(cfg)
	if err != nil {
		return nil, err
	}

	reqBody := map[string]interface{}{
		"ciphertext": string(ciphertext),
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal transit decrypt request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/transit/decrypt/%s", client.baseURL, keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create transit decrypt request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		req.Header.Set("X-Vault-Token", client.token)
	}

	resp, err := client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read transit decrypt response: %w", err)
	}

	var payload struct {
		Errors []string `json:"errors"`
		Data   struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, fmt.Errorf("parse transit decrypt response: %w", err)
	}

	if resp.StatusCode >= 400 {
		if len(payload.Errors) > 0 {
			return nil, fmt.Errorf("vault transit decrypt failed: %s", strings.Join(payload.Errors, "; "))
		}
		return nil, fmt.Errorf("vault transit decrypt failed with HTTP %d", resp.StatusCode)
	}

	plaintextB64 := strings.TrimSpace(payload.Data.Plaintext)
	if plaintextB64 == "" {
		return nil, fmt.Errorf("vault transit returned empty plaintext")
	}

	keyPEM, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("decode transit plaintext: %w", err)
	}

	return keyPEM, nil
}

// RestoreOrCreateKey restores or creates the PDP private key.
func RestoreOrCreateKey(ctx context.Context, cfg VaultConfig, encryptedKeyPath string) (*ecdsa.PrivateKey, error) {
	return RestoreOrCreateNamedKey(ctx, cfg, encryptedKeyPath, "PDP")
}

// RestoreOrCreateNamedKey restores or creates a named ECDSA private key.
func RestoreOrCreateNamedKey(ctx context.Context, cfg VaultConfig, encryptedKeyPath, keyLabel string) (*ecdsa.PrivateKey, error) {
	label := strings.TrimSpace(keyLabel)
	if label == "" {
		label = "ECDSA"
	}

	// Try to restore from Vault Transit.
	data, err := os.ReadFile(encryptedKeyPath)
	if err == nil {
		log.Printf("[TRANSIT] Found encrypted %s key at %s, decrypting via Vault Transit...", label, encryptedKeyPath)
		keyPEM, err := TransitDecryptKey(ctx, cfg, data)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s key via Vault Transit: %w", label, err)
		}
		privKey, err := parseECDSAPrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse decrypted %s key: %w", label, err)
		}
		log.Printf("[TRANSIT] %s key restored successfully from Vault Transit", label)
		return privKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read encrypted %s key from %s: %w", label, encryptedKeyPath, err)
	}

	// No saved key - generate new one
	log.Printf("[TRANSIT] No encrypted %s key found, generating new ECDSA P-256 key...", label)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate %s key: %w", label, err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal %s key: %w", label, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Encrypt via Vault Transit and save
	log.Printf("[TRANSIT] Encrypting %s key via Vault Transit...", label)
	if err := encryptAndSaveKey(ctx, cfg, encryptedKeyPath, keyPEM, label); err != nil {
		return nil, err
	}

	log.Printf("[TRANSIT] New %s key generated, encrypted, and saved to %s", label, encryptedKeyPath)
	return key, nil
}

func encryptAndSaveKey(ctx context.Context, cfg VaultConfig, encryptedKeyPath string, keyPEM []byte, keyLabel string) error {
	ciphertext, err := TransitEncryptKey(ctx, cfg, keyPEM)
	if err != nil {
		return fmt.Errorf("encrypt %s key via Vault Transit: %w", keyLabel, err)
	}

	if err := os.MkdirAll(filepath.Dir(encryptedKeyPath), 0o700); err != nil {
		return fmt.Errorf("create encrypted key directory: %w", err)
	}
	if err := WriteFileAtomic(encryptedKeyPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write encrypted PDP key: %w", err)
	}
	return nil
}

// parseECDSAPrivateKey decodes a PEM-encoded ECDSA private key.
func parseECDSAPrivateKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse EC private key (SEC1: %v, PKCS8: %v)", err, err2)
		}
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ECDSA")
		}
		return ecKey, nil
	}
	return key, nil
}
