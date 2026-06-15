package testredis

import (
	"context"
	"os"
	"strings"
	"testing"

	"pdp/runtime/redisstate"

	"github.com/redis/go-redis/v9"
)

const testRedisURLEnv = "PDP_TEST_REDIS_URL"

func NewClient(t *testing.T) *redisstate.Client {
	t.Helper()
	rawURL := strings.TrimSpace(os.Getenv(testRedisURLEnv))
	if rawURL == "" {
		t.Skip("set PDP_TEST_REDIS_URL to run Redis-backed tests")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatalf("parse Redis test URL: %v", err)
	}
	rdb := redis.NewClient(options)
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		t.Fatalf("ping Redis test database: %v", err)
	}
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		_ = rdb.Close()
		t.Fatalf("flush Redis test database: %v", err)
	}
	_ = rdb.Close()

	client, err := redisstate.Open(ctx, rawURL)
	if err != nil {
		t.Fatalf("open Redis runtime state: %v", err)
	}
	t.Cleanup(func() {
		options, err := redis.ParseURL(rawURL)
		if err == nil {
			rdb := redis.NewClient(options)
			_ = rdb.FlushDB(context.Background()).Err()
			_ = rdb.Close()
		}
		_ = client.Close()
	})
	return client
}
