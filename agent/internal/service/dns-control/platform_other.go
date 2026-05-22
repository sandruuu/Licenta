//go:build !windows

package dnscontrol

import (
	"context"
	"errors"
)

func applyPlatform(ctx context.Context, config Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if len(config.DNSNames) > 0 {
		return errors.New("NRPT is available only on Windows")
	}
	return nil
}
