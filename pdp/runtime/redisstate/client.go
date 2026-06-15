package redisstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"pdp/util"

	"github.com/redis/go-redis/v9"
)

const keyPrefix = "pdp"

var (
	ErrUnavailable                = errors.New("redis runtime state is unavailable")
	ErrGatewayControlNotConnected = errors.New("gateway control not connected")
	ErrGatewayControlOwnerChanged = errors.New("gateway control owner changed")
)

type Client struct {
	rdb        *redis.Client
	instanceID string
}

func Open(ctx context.Context, rawURL string) (*Client, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("redis_url is required")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis_url: %w", err)
	}
	rdb := redis.NewClient(options)
	if ctx == nil {
		ctx = context.Background()
	}
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	instanceID, err := util.GenerateID("pdp")
	if err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("generate PDP runtime instance id: %w", err)
	}
	return &Client{rdb: rdb, instanceID: instanceID}, nil
}

func (c *Client) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.rdb.Ping(ctx).Err()
}

func (c *Client) InstanceID() string {
	if c == nil {
		return ""
	}
	return c.instanceID
}

func (c *Client) setJSON(key string, value interface{}, ttl time.Duration) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.rdb.Set(context.Background(), key, raw, ttl).Err()
}

func normalizePart(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), " ", "_")
}
