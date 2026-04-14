package tpmauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// KeyManager provides a crypto.Signer backed by TPM when available,
// falling back to a software ECDSA key stored on disk.
type KeyManager struct {
	signer crypto.Signer
	isTPM  bool
}

// NewKeyManager creates a key manager. It tries to use the platform TPM first;
// if the TPM is not available it falls back to a software key in dataDir.
func NewKeyManager(dataDir string) (*KeyManager, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// Try TPM-backed key first
	signer, err := loadOrCreateTPMKey(dataDir)
	if err == nil {
		slog.Info("Using TPM-backed key for mTLS", "dataDir", dataDir)
		return &KeyManager{signer: signer, isTPM: true}, nil
	}
	slog.Warn("TPM not available, using software key", "reason", err)

	// Fallback: software ECDSA key on disk
	signer, err = loadOrCreateSoftwareKey(dataDir)
	if err != nil {
		return nil, fmt.Errorf("software key fallback: %w", err)
	}
	slog.Info("Using software key for mTLS (no TPM)", "dataDir", dataDir)
	return &KeyManager{signer: signer, isTPM: false}, nil
}

// Signer returns the underlying crypto.Signer (TPM or software).
func (km *KeyManager) Signer() crypto.Signer { return km.signer }

// IsTPM returns true if the key is TPM-backed.
func (km *KeyManager) IsTPM() bool { return km.isTPM }

// Public returns the public key.
func (km *KeyManager) Public() crypto.PublicKey { return km.signer.Public() }

// Sign delegates to the underlying signer.
func (km *KeyManager) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return km.signer.Sign(rand, digest, opts)
}

// DeviceFingerprint returns a stable device identity string.
// With TPM: "ek-" + SHA256(EKPub PKIX DER) — hardware-anchored, same across all apps.
// Without TPM: "sw-" + SHA256(Windows MachineGuid) — best-effort software fallback.
func (km *KeyManager) DeviceFingerprint() (string, error) {
	if km.isTPM {
		ekPub, err := ReadEKPub()
		if err != nil {
			return "", fmt.Errorf("read EK public key: %w", err)
		}
		der, err := x509.MarshalPKIXPublicKey(ekPub)
		if err != nil {
			return "", fmt.Errorf("marshal EK public key: %w", err)
		}
		h := sha256.Sum256(der)
		return "ek-" + hex.EncodeToString(h[:]), nil
	}

	// Software fallback: use Windows MachineGuid
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.READ)
	if err != nil {
		return "", fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("read MachineGuid: %w", err)
	}
	h := sha256.Sum256([]byte(guid))
	return "sw-" + hex.EncodeToString(h[:]), nil
}

// ── Software key management ──────────────────────────────────────────

func loadOrCreateSoftwareKey(dataDir string) (crypto.Signer, error) {
	keyPath := filepath.Join(dataDir, "client.key")

	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				slog.Debug("Loaded existing software key", "path", keyPath)
				return key, nil
			}
		}
	}

	// Generate new ECDSA P-256 key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	// Save to disk
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}

	slog.Info("Generated new software ECDSA P-256 key", "path", keyPath)
	return key, nil
}
