package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

func (gateway *Gateway) terminateRelays(match func(*activeRelay) bool, reason string) {
	count := 0
	gateway.activeRelays.Range(func(_, value any) bool {
		active, ok := value.(*activeRelay)
		if !ok || active == nil {
			return true
		}
		if match(active) {
			active.cancel(reason)
			count++
		}
		return true
	})
	if count > 0 {
		log.Printf("[GATEWAY] terminated %d active relay(s) due to %s", count, reason)
	}
}

func (gateway *Gateway) renewActiveRelays(sessionID string, expiresAt time.Time) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || expiresAt.IsZero() {
		return
	}
	count := 0
	gateway.activeRelays.Range(func(_, value any) bool {
		active, ok := value.(*activeRelay)
		if !ok || active == nil || active.sessionID != sessionID || active.renew == nil {
			return true
		}
		select {
		case active.renew <- expiresAt:
		default:
			select {
			case <-active.renew:
			default:
			}
			select {
			case active.renew <- expiresAt:
			default:
			}
		}
		count++
		return true
	})
	if count > 0 {
		log.Printf("[GATEWAY] renewed %d active relay(s) for session=%s expires=%s", count, sessionID, expiresAt.Format(time.RFC3339))
	}
}

func watchRelayExpiry(ctx context.Context, expiresAt time.Time, renew <-chan time.Time, closeRelay func(reason string)) {
	if closeRelay == nil || expiresAt.IsZero() {
		return
	}
	wait := time.Until(expiresAt)
	if wait <= 0 {
		closeRelay("session.expired")
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			closeRelay("session.expired")
			return
		case nextExpiry := <-renew:
			if nextExpiry.IsZero() {
				continue
			}
			wait = time.Until(nextExpiry)
			if wait <= 0 {
				closeRelay("session.expired")
				return
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(wait)
		case <-ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) incIP(ip string) int64 {
	value, _ := gateway.perIPConns.LoadOrStore(ip, &atomic.Int64{})
	return value.(*atomic.Int64).Add(1)
}

func (gateway *Gateway) decIP(ip string) {
	value, ok := gateway.perIPConns.Load(ip)
	if !ok {
		return
	}
	counter := value.(*atomic.Int64)
	if counter.Add(-1) <= 0 {
		gateway.perIPConns.Delete(ip)
	}
}

func relayLimitBytesPerSecond(sessionMbps, globalMbps int) int {
	if sessionMbps > 0 {
		return sessionMbps * 1024 * 1024 / 8
	}
	if globalMbps > 0 {
		return globalMbps * 1024 * 1024 / 8
	}
	return 0
}

func processLogName(process *ProcessIdentity) string {
	if process == nil {
		return "unknown"
	}
	if strings.TrimSpace(process.Name) != "" {
		return strings.TrimSpace(process.Name)
	}
	if strings.TrimSpace(process.Path) != "" {
		return strings.TrimSpace(process.Path)
	}
	if process.PID > 0 {
		return fmt.Sprintf("pid:%d", process.PID)
	}
	return "unknown"
}

func remoteIPOnly(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && host != "" {
		return host
	}
	return addr.String()
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func newRelayID() string {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("relay-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes[:])
}

func serialLookupKeys(serial *big.Int) []string {
	if serial == nil {
		return nil
	}
	return normalizedSerialKeys(serial.String())
}

func normalizedSerialKeys(serial string) []string {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return nil
	}
	keys := map[string]struct{}{
		strings.ToLower(serial): {},
	}
	if decimal, ok := new(big.Int).SetString(serial, 10); ok {
		keys[decimal.String()] = struct{}{}
		keys[strings.ToLower(decimal.Text(16))] = struct{}{}
	}
	if hexValue, ok := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(serial), "0x"), 16); ok {
		keys[hexValue.String()] = struct{}{}
		keys[strings.ToLower(hexValue.Text(16))] = struct{}{}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	return result
}

func rateLimitedCopy(dst io.Writer, src io.Reader, bytesPerSecond, bufferSize int) (int64, error) {
	if bufferSize <= 0 {
		return 0, fmt.Errorf("relay_buffer_size_bytes must be configured")
	}
	buffer := make([]byte, bufferSize)
	var total int64
	windowStart := time.Now()
	var windowBytes int64
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			total += int64(written)
			windowBytes += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if bytesPerSecond > 0 && windowBytes >= int64(bytesPerSecond) {
				elapsed := time.Since(windowStart)
				if elapsed < time.Second {
					time.Sleep(time.Second - elapsed)
				}
				windowStart = time.Now()
				windowBytes = 0
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return total, nil
			}
			return total, readErr
		}
	}
}
