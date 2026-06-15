package redisstate

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (c *Client) Allow(namespace, key string, window time.Duration, maxRequests int) (bool, error) {
	if c == nil || c.rdb == nil {
		return false, ErrUnavailable
	}
	if maxRequests <= 0 {
		return false, nil
	}
	if window <= 0 {
		window = time.Minute
	}
	now := time.Now().UTC()
	windowStart := now.UnixNano() / window.Nanoseconds()
	redisKey := rateKey(namespace, key, windowStart)
	ctx := context.Background()
	count, err := c.rdb.Incr(ctx, redisKey).Result()
	if err != nil {
		return false, err
	}
	if count == 1 {
		_ = c.rdb.Expire(ctx, redisKey, window*2).Err()
	}
	return count <= int64(maxRequests), nil
}

func rateKey(namespace, key string, windowStart int64) string {
	return keyPrefix + ":rate:" + normalizePart(namespace) + ":" + strings.TrimSpace(key) + ":" + fmt.Sprint(windowStart)
}
