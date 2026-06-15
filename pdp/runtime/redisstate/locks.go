package redisstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"pdp/util"
)

var ErrLockNotAcquired = errors.New("redis lock was not acquired")

type Lock struct {
	client *Client
	key    string
	token  string
}

func (c *Client) AcquireLock(ctx context.Context, name string, ttl, wait time.Duration) (*Lock, error) {
	if c == nil || c.rdb == nil {
		return nil, ErrUnavailable
	}
	name = normalizePart(strings.TrimSpace(name))
	if name == "" {
		return nil, fmt.Errorf("lock name is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	token, err := util.GenerateID("lock")
	if err != nil {
		return nil, fmt.Errorf("generate lock token: %w", err)
	}

	key := lockKey(name)
	deadline := time.Now().Add(wait)
	for {
		acquired, err := c.rdb.SetNX(ctx, key, token, ttl).Result()
		if err != nil {
			return nil, err
		}
		if acquired {
			return &Lock{client: c, key: key, token: token}, nil
		}
		if wait <= 0 || time.Now().After(deadline) {
			return nil, ErrLockNotAcquired
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *Lock) Release(ctx context.Context) error {
	if l == nil || l.client == nil || l.client.rdb == nil || l.key == "" || l.token == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	const releaseScript = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`
	return l.client.rdb.Eval(ctx, releaseScript, []string{l.key}, l.token).Err()
}

func (c *Client) WithLock(ctx context.Context, name string, ttl, wait time.Duration, fn func() error) error {
	lock, err := c.AcquireLock(ctx, name, ttl, wait)
	if err != nil {
		return err
	}
	defer func() {
		_ = lock.Release(context.Background())
	}()
	if fn == nil {
		return nil
	}
	return fn()
}

func lockKey(name string) string {
	return keyPrefix + ":lock:" + normalizePart(name)
}
