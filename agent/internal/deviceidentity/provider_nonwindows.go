//go:build !windows

package deviceidentity

import (
	"context"
	"strings"
	"time"
)

type platformProvider struct {
	fallbackUserSID string
	clock           func() time.Time
}

func newPlatformProvider(options Options) Provider {
	return &platformProvider{
		fallbackUserSID: strings.TrimSpace(options.AuthorizedUserSID),
		clock:           clockOrNow(options.Clock),
	}
}

func (provider *platformProvider) Snapshot(ctx context.Context) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
	}
	userSID := provider.fallbackUserSID
	return Snapshot{
		ActiveUserSID: userSID,
		KeyName:       KeyNameForSID(userSID),
		KeyProvider:   "unsupported",
		CollectedAt:   provider.clock().UTC(),
	}, nil
}
