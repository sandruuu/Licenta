package redisstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

func (c *Client) SaveEphemeralState(kind, key string, value []byte, expiresAt time.Time) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	kind, key = normalizePart(kind), strings.TrimSpace(key)
	if kind == "" || key == "" {
		return fmt.Errorf("ephemeral state kind and key are required")
	}
	ttl := time.Until(expiresAt)
	if expiresAt.IsZero() {
		ttl = 5 * time.Minute
	}
	if ttl <= 0 {
		return c.DeleteEphemeralState(kind, key)
	}
	return c.rdb.Set(context.Background(), stateKey(kind, key), value, ttl).Err()
}

func (c *Client) GetEphemeralState(kind, key string) ([]byte, bool) {
	if c == nil || c.rdb == nil {
		return nil, false
	}
	raw, err := c.rdb.Get(context.Background(), stateKey(kind, strings.TrimSpace(key))).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	return raw, true
}

func (c *Client) TakeEphemeralState(kind, key string) ([]byte, bool, error) {
	if c == nil || c.rdb == nil {
		return nil, false, ErrUnavailable
	}
	raw, err := c.rdb.GetDel(context.Background(), stateKey(kind, strings.TrimSpace(key))).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func (c *Client) DeleteEphemeralState(kind, key string) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	return c.rdb.Del(context.Background(), stateKey(kind, strings.TrimSpace(key))).Err()
}

func (c *Client) ListEphemeralState(kind string) (map[string][]byte, error) {
	if c == nil || c.rdb == nil {
		return nil, ErrUnavailable
	}
	ctx := context.Background()
	prefix := stateKey(kind, "")
	out := make(map[string][]byte)
	var cursor uint64
	for {
		keys, next, err := c.rdb.Scan(ctx, cursor, prefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			raw, err := c.rdb.Get(ctx, key).Bytes()
			if errors.Is(err, redis.Nil) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out[strings.TrimPrefix(key, prefix)] = raw
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}

func (c *Client) CleanExpiredEphemeralState(time.Time) int {
	return 0
}

func stateKey(kind, key string) string {
	kind = normalizePart(kind)
	key = strings.TrimSpace(key)
	if key == "" {
		return keyPrefix + ":state:" + kind + ":"
	}
	return keyPrefix + ":state:" + kind + ":" + key
}
