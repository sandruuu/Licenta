package trafficinterception

import (
	"context"
	"sync"
	"time"
)

const processIdentityCacheTTL = 30 * time.Second

type processIdentityResolver func(context.Context, uint32) (*ProcessIdentity, error)

type cachedProcessIdentity struct {
	identity  *ProcessIdentity
	expiresAt time.Time
}

var (
	processIdentityMu    sync.Mutex
	processIdentityCache = map[uint32]cachedProcessIdentity{}
)

func resolveProcessIdentityCached(ctx context.Context, pid uint32) (*ProcessIdentity, error) {
	if pid == 0 {
		return nil, nil
	}
	now := time.Now()
	processIdentityMu.Lock()
	if cached, ok := processIdentityCache[pid]; ok && cached.expiresAt.After(now) {
		identity := cloneProcessIdentity(cached.identity)
		processIdentityMu.Unlock()
		return identity, nil
	}
	processIdentityMu.Unlock()

	identity, err := resolveProcessIdentity(ctx, pid)
	if identity == nil && pid != 0 {
		identity = &ProcessIdentity{PID: int(pid)}
	}

	processIdentityMu.Lock()
	processIdentityCache[pid] = cachedProcessIdentity{
		identity:  cloneProcessIdentity(identity),
		expiresAt: now.Add(processIdentityCacheTTL),
	}
	processIdentityMu.Unlock()
	return identity, err
}

func cloneProcessIdentity(identity *ProcessIdentity) *ProcessIdentity {
	if identity == nil {
		return nil
	}
	copy := *identity
	return &copy
}
