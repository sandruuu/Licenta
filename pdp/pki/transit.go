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
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// TransitEncryptKey encrypts a PEM-encoded private key using Vault Transit
// and returns the ciphertext to be stored on disk.
//
// Vault Transit key must be pre-created:
//
//	vault write -f transit/keys/ztna-pdp-key
func TransitEncryptKey(ctx context.Context, cfg VaultConfig, keyPEM []byte) ([]byte, error) {
	client, err := NewVaultClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Vault client: %w", err)
	}

	// Encode plaintext as base64 (Vault Transit requirement)
	plaintextB64 := base64.StdEncoding.EncodeToString(keyPEM)
	reqBody := map[string]interface{}{
		"plaintext": plaintextB64,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal transit encrypt request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/transit/encrypt/ztna-pdp-key", client.baseURL)
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

	reqBody := map[string]interface{}{
		"ciphertext": string(ciphertext),
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal transit decrypt request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/transit/decrypt/ztna-pdp-key", client.baseURL)
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

// RestoreOrCreateKey attempts to restore the PDP private key from Vault Transit,
// or generates a new one and encrypts it if no saved key exists.
//
// Returns the ECDSA private key (for TLS config) and the PEM-encoded key.
func RestoreOrCreateKey(ctx context.Context, cfg VaultConfig, keyPath, encryptedKeyPath string) (*ecdsa.PrivateKey, []byte, error) {
	// Try to restore from Vault Transit
	if data, err := os.ReadFile(encryptedKeyPath); err == nil {
		log.Printf("[PDP-TRANSIT] Found encrypted key at %s, decrypting via Vault Transit...", encryptedKeyPath)
		keyPEM, err := TransitDecryptKey(ctx, cfg, data)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt PDP key via Vault Transit: %w", err)
		}
		privKey, err := parseECDSAPrivateKey(keyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("parse decrypted PDP key: %w", err)
		}
		log.Printf("[PDP-TRANSIT] Key restored successfully from Vault Transit")
		return privKey, keyPEM, nil
	}

	// No saved key — generate new one
	log.Printf("[PDP-TRANSIT] No encrypted key found, generating new ECDSA P-256 key...")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate PDP key: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal PDP key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Encrypt via Vault Transit and save
	log.Printf("[PDP-TRANSIT] Encrypting key via Vault Transit...")
	ciphertext, err := TransitEncryptKey(ctx, cfg, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt PDP key via Vault Transit: %w", err)
	}

	if err := os.MkdirAll(strings.TrimSuffix(encryptedKeyPath, "/pdp_key.enc"), 0o700); err != nil {
		// If encryptedKeyPath is like "data/pdp_key.enc", MkdirAll "data"
		dir := "."
		for i := len(encryptedKeyPath) - 1; i >= 0; i-- {
			if encryptedKeyPath[i] == '/' || encryptedKeyPath[i] == '\\' {
				dir = encryptedKeyPath[:i]
				break
			}
		}
		_ = os.MkdirAll(dir, 0o700)
	}
	if err := os.WriteFile(encryptedKeyPath, ciphertext, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write encrypted PDP key: %w", err)
	}

	log.Printf("[PDP-TRANSIT] New key generated, encrypted, and saved to %s", encryptedKeyPath)
	return key, keyPEM, nil
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
