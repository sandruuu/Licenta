package endpointidentity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSharedEndpointDirUnifiesKeyAndStateDirs(t *testing.T) {
	endpointDir := filepath.Join(t.TempDir(), "endpoint")
	fallback := filepath.Join(t.TempDir(), "fallback")

	t.Setenv("ZTNA_ENDPOINT_DIR", endpointDir)
	t.Setenv("ZTNA_TPM_DIR", "")
	t.Setenv("PROGRAMDATA", filepath.Join(t.TempDir(), "programdata"))

	keyDir := SharedKeyDir(fallback)
	stateDir := SharedStateDir(fallback)

	want := filepath.Clean(endpointDir)
	if keyDir != want {
		t.Fatalf("SharedKeyDir() = %q, want %q", keyDir, want)
	}
	if stateDir != want {
		t.Fatalf("SharedStateDir() = %q, want %q", stateDir, want)
	}
}

func TestSharedEndpointDirUsesLegacyTPMOverrideAsAlias(t *testing.T) {
	legacyDir := filepath.Join(t.TempDir(), "legacy-tpm")
	fallback := filepath.Join(t.TempDir(), "fallback")

	t.Setenv("ZTNA_ENDPOINT_DIR", "")
	t.Setenv("ZTNA_TPM_DIR", legacyDir)
	t.Setenv("PROGRAMDATA", filepath.Join(t.TempDir(), "programdata"))

	keyDir := SharedKeyDir(fallback)
	stateDir := SharedStateDir(fallback)

	want := filepath.Clean(legacyDir)
	if keyDir != want || stateDir != want {
		t.Fatalf("keyDir/stateDir = %q/%q, want both %q", keyDir, stateDir, want)
	}
}

func TestSharedKeyDirMigratesLegacyMachineKeyMaterial(t *testing.T) {
	programData := t.TempDir()
	fallback := filepath.Join(t.TempDir(), "fallback")
	legacyDir := filepath.Join(programData, defaultWindowsBaseDir, legacyKeySubdir)
	endpointDir := filepath.Join(programData, defaultWindowsBaseDir, defaultEndpointSubdir)

	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatalf("create legacy dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "client.key"), []byte("legacy software key"), 0600); err != nil {
		t.Fatalf("write legacy client key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "tpm-key.json"), []byte(`{"public":"old","private":"old"}`), 0600); err != nil {
		t.Fatalf("write legacy tpm key: %v", err)
	}

	t.Setenv("ZTNA_ENDPOINT_DIR", "")
	t.Setenv("ZTNA_TPM_DIR", "")
	t.Setenv("PROGRAMDATA", programData)

	keyDir := SharedKeyDir(fallback)
	if keyDir != endpointDir {
		t.Fatalf("SharedKeyDir() = %q, want %q", keyDir, endpointDir)
	}

	for _, name := range []string{"client.key", "tpm-key.json"} {
		if _, err := os.Stat(filepath.Join(endpointDir, name)); err != nil {
			t.Fatalf("expected migrated %s: %v", name, err)
		}
	}
}
