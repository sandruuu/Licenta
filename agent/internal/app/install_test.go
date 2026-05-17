package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceExecutablePathForInstaller(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ztna-agent.exe")
	if err := os.WriteFile(target, []byte("agent"), 0600); err != nil {
		t.Fatalf("write target executable: %v", err)
	}
	path, err := serviceExecutablePath(filepath.Join(dir, "ztna-agent-installer.exe"))
	if err != nil {
		t.Fatalf("serviceExecutablePath returned error: %v", err)
	}
	if path != target {
		t.Fatalf("path = %q, want %q", path, target)
	}
}

func TestServiceExecutablePathForRenamedInstaller(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ztna-agent.exe")
	if err := os.WriteFile(target, []byte("agent"), 0600); err != nil {
		t.Fatalf("write target executable: %v", err)
	}
	path, err := serviceExecutablePath(filepath.Join(dir, "ZTNAAgentSetup.exe"))
	if err != nil {
		t.Fatalf("serviceExecutablePath returned error: %v", err)
	}
	if path != target {
		t.Fatalf("path = %q, want %q", path, target)
	}
}

func TestServiceExecutablePathForAgent(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "ztna-agent.exe")
	path, err := serviceExecutablePath(current)
	if err != nil {
		t.Fatalf("serviceExecutablePath returned error: %v", err)
	}
	if path != current {
		t.Fatalf("path = %q, want %q", path, current)
	}
}
