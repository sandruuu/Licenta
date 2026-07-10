//go:build windows

package trafficinterception

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const processFileHashCacheTTL = 10 * time.Minute

type cachedProcessFileHash struct {
	hash      string
	size      int64
	modTime   time.Time
	expiresAt time.Time
}

var (
	processFileHashMu    sync.Mutex
	processFileHashCache = map[string]cachedProcessFileHash{}
)

func resolveProcessIdentity(ctx context.Context, pid uint32) (*ProcessIdentity, error) {
	if pid == 0 {
		return nil, nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	identity := &ProcessIdentity{PID: int(pid)}
	path, err := processImagePath(pid)
	if err != nil {
		return identity, err
	}
	identity.Path = path
	identity.Name = filepath.Base(path)
	if hash, err := fileSHA256Cached(path); err == nil {
		identity.SHA256 = hash
	}
	identity.Signer = fileSigner(path)
	return identity, nil
}

func processImagePath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	size := uint32(windows.MAX_LONG_PATH)
	for {
		buffer := make([]uint16, size)
		actual := size
		err = windows.QueryFullProcessImageName(handle, 0, &buffer[0], &actual)
		if err == nil {
			return strings.TrimSpace(windows.UTF16ToString(buffer[:actual])), nil
		}
		if size >= 32768 {
			return "", fmt.Errorf("query process image name for %d: %w", pid, err)
		}
		size *= 2
	}
}

func fileSHA256Cached(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", os.ErrInvalid
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	key := strings.ToLower(path)
	now := time.Now()

	processFileHashMu.Lock()
	if cached, ok := processFileHashCache[key]; ok &&
		cached.size == info.Size() &&
		cached.modTime.Equal(info.ModTime()) &&
		cached.expiresAt.After(now) {
		processFileHashMu.Unlock()
		return cached.hash, nil
	}
	processFileHashMu.Unlock()

	hash, err := fileSHA256(path)
	if err != nil {
		return "", err
	}

	processFileHashMu.Lock()
	processFileHashCache[key] = cachedProcessFileHash{
		hash:      hash,
		size:      info.Size(),
		modTime:   info.ModTime(),
		expiresAt: now.Add(processFileHashCacheTTL),
	}
	processFileHashMu.Unlock()
	return hash, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func fileSigner(_ string) string {
	return ""
}
