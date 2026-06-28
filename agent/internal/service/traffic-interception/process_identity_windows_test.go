//go:build windows

package trafficinterception

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestFileSHA256CachedUsesValidCacheEntry(t *testing.T) {
	path := writeTempExecutableFile(t, []byte("process-image"))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat temp file: %v", err)
	}
	key := strings.ToLower(path)
	processFileHashMu.Lock()
	processFileHashCache[key] = cachedProcessFileHash{
		hash:      "cached-hash",
		size:      info.Size(),
		modTime:   info.ModTime(),
		expiresAt: time.Now().Add(time.Hour),
	}
	processFileHashMu.Unlock()

	hash, err := fileSHA256Cached(path)
	if err != nil {
		t.Fatalf("fileSHA256Cached returned error: %v", err)
	}
	if hash != "cached-hash" {
		t.Fatalf("hash = %q, want cached-hash", hash)
	}
}

func TestFileSHA256CachedInvalidatesChangedFile(t *testing.T) {
	path := writeTempExecutableFile(t, []byte("process-image"))
	first, err := fileSHA256Cached(path)
	if err != nil {
		t.Fatalf("first fileSHA256Cached returned error: %v", err)
	}
	if err := os.WriteFile(path, []byte("changed-process-image"), 0o600); err != nil {
		t.Fatalf("rewrite temp file: %v", err)
	}
	changedTime := time.Now().Add(time.Second)
	if err := os.Chtimes(path, changedTime, changedTime); err != nil {
		t.Fatalf("change temp file timestamp: %v", err)
	}

	second, err := fileSHA256Cached(path)
	if err != nil {
		t.Fatalf("second fileSHA256Cached returned error: %v", err)
	}
	if second == first {
		t.Fatalf("hash was not refreshed after file content changed")
	}
}

func writeTempExecutableFile(t *testing.T, content []byte) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "process-*.exe")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		t.Fatalf("write temp file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return file.Name()
}
