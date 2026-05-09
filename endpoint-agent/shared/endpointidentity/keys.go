package endpointidentity

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
	"runtime"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	defaultWindowsBaseDir = "ztna"
	defaultEndpointSubdir = "endpoint"
	legacyKeySubdir       = "tpm"
)

// KeyManager provides a crypto.Signer backed by TPM when available,
// falling back to a software ECDSA P-256 key stored in the shared endpoint
// identity directory.
type KeyManager struct {
	signer crypto.Signer
	isTPM  bool
}

// NewKeyManager creates a key manager. It tries to use the platform TPM first;
// if the TPM is not available it falls back to a software key in the shared
// machine-wide identity directory.
func NewKeyManager(dataDir string) (*KeyManager, error) {
	fallback := cleanFallbackDir(dataDir)
	if err := os.MkdirAll(fallback, 0700); err != nil {
		return nil, fmt.Errorf("create fallback data dir: %w", err)
	}

	keyDir := SharedKeyDir(fallback)

	signer, err := loadOrCreateTPMKey(keyDir)
	if err == nil {
		slog.Info("Using TPM-backed endpoint key", "dataDir", keyDir)
		return &KeyManager{signer: signer, isTPM: true}, nil
	}
	slog.Warn("TPM not available, using software endpoint key", "reason", err)

	signer, err = loadOrCreateSoftwareKey(keyDir)
	if err != nil {
		return nil, fmt.Errorf("software key fallback: %w", err)
	}
	slog.Info("Using software endpoint key", "dataDir", keyDir)
	return &KeyManager{signer: signer, isTPM: false}, nil
}

// SharedEndpointDir resolves the single machine-wide endpoint identity folder.
// It contains TPM/software key material, the endpoint certificate cache, and
// enrollment coordination state. ZTNA_TPM_DIR is retained as a legacy alias
// when ZTNA_ENDPOINT_DIR is not set so existing deployments can move without
// losing their endpoint identity.
func SharedEndpointDir(fallback string) string {
	if override := strings.TrimSpace(os.Getenv("ZTNA_ENDPOINT_DIR")); override != "" {
		if err := os.MkdirAll(override, 0700); err == nil {
			return filepath.Clean(override)
		}
	}

	if legacyOverride := strings.TrimSpace(os.Getenv("ZTNA_TPM_DIR")); legacyOverride != "" {
		if err := os.MkdirAll(legacyOverride, 0700); err == nil {
			return filepath.Clean(legacyOverride)
		}
	}

	return sharedDir(defaultEndpointSubdir, fallback)
}

// SharedKeyDir resolves the TPM/software key directory. New deployments use
// the same endpoint folder as certificate state; legacy tpm directories are
// copied from on first use to avoid forcing re-enrollment.
func SharedKeyDir(fallback string) string {
	endpointDir := SharedEndpointDir(fallback)
	migrateLegacyKeyMaterial(endpointDir, fallback)
	return endpointDir
}

// SharedStateDir resolves the machine-wide endpoint certificate/state cache.
func SharedStateDir(fallback string) string {
	return SharedEndpointDir(fallback)
}

func sharedDir(subdir, fallback string) string {
	var candidate string
	if pd := os.Getenv("PROGRAMDATA"); pd != "" {
		candidate = filepath.Join(pd, defaultWindowsBaseDir, subdir)
	} else {
		candidate = filepath.Join(string(filepath.Separator), "var", "lib", defaultWindowsBaseDir, subdir)
	}
	if err := os.MkdirAll(candidate, 0700); err == nil {
		return candidate
	}
	return cleanFallbackDir(fallback)
}

func legacyMachineKeyDir(fallback string) string {
	if override := strings.TrimSpace(os.Getenv("ZTNA_TPM_DIR")); override != "" {
		return filepath.Clean(override)
	}
	if pd := os.Getenv("PROGRAMDATA"); pd != "" {
		return filepath.Join(pd, defaultWindowsBaseDir, legacyKeySubdir)
	}
	return filepath.Join(string(filepath.Separator), "var", "lib", defaultWindowsBaseDir, legacyKeySubdir)
}

func migrateLegacyKeyMaterial(endpointDir, fallback string) {
	sources := []string{legacyMachineKeyDir(fallback), cleanFallbackDir(fallback)}
	for _, source := range sources {
		if source == "" || samePath(source, endpointDir) {
			continue
		}
		for _, name := range []string{"tpm-key.json", "client.key"} {
			copyFileIfMissing(filepath.Join(source, name), filepath.Join(endpointDir, name), 0600)
		}
	}
}

func copyFileIfMissing(src, dst string, perm os.FileMode) {
	if _, err := os.Stat(dst); err == nil {
		return
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		slog.Warn("Failed to create endpoint identity directory for legacy key migration", "path", filepath.Dir(dst), "error", err)
		return
	}
	if err := os.WriteFile(dst, data, perm); err != nil {
		slog.Warn("Failed to migrate legacy endpoint key material", "source", src, "target", dst, "error", err)
		return
	}
	slog.Info("Migrated legacy endpoint key material into unified endpoint folder", "source", src, "target", dst)
}

func samePath(a, b string) bool {
	aAbs, aErr := filepath.Abs(filepath.Clean(a))
	bAbs, bErr := filepath.Abs(filepath.Clean(b))
	if aErr != nil || bErr != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(aAbs, bAbs)
	}
	return aAbs == bAbs
}

func cleanFallbackDir(dataDir string) string {
	if dataDir == "" {
		return "./data"
	}
	return dataDir
}

// Signer returns the underlying crypto.Signer.
func (km *KeyManager) Signer() crypto.Signer { return km.signer }

// IsTPM returns true if the endpoint key is TPM-backed.
func (km *KeyManager) IsTPM() bool { return km.isTPM }

// Public returns the public key.
func (km *KeyManager) Public() crypto.PublicKey { return km.signer.Public() }

// Sign delegates to the underlying signer.
func (km *KeyManager) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return km.signer.Sign(rand, digest, opts)
}

// DeviceFingerprint returns a stable device identity string.
// With TPM: "ek-" + SHA256(EK public key PKIX DER).
// Without TPM: "sw-" + SHA256(Windows MachineGuid).
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

func loadOrCreateSoftwareKey(dataDir string) (crypto.Signer, error) {
	keyPath := filepath.Join(dataDir, "client.key")

	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				slog.Debug("Loaded existing software endpoint key", "path", keyPath)
				return key, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("save key: %w", err)
	}

	slog.Info("Generated new software endpoint ECDSA P-256 key", "path", keyPath)
	return key, nil
}
