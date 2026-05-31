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

	"golang.org/x/sys/windows"
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
	if hash, err := fileSHA256(path); err == nil {
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
	// Signature validation is intentionally left for a dedicated Authenticode
	// verifier. PID/path/hash are collected synchronously on the flow path.
	return ""
}
