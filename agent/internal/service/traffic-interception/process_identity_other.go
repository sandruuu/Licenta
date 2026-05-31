//go:build !windows

package trafficinterception

import (
	"context"
	"fmt"
)

func resolveProcessIdentity(ctx context.Context, pid uint32) (*ProcessIdentity, error) {
	if pid == 0 {
		return nil, nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &ProcessIdentity{PID: int(pid)}, fmt.Errorf("process identity enrichment is supported only on Windows")
}
