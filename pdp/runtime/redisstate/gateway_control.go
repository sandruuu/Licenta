package redisstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type GatewayPresence struct {
	GatewayID string    `json:"gateway_id"`
	OwnerID   string    `json:"owner_id"`
	Endpoint  string    `json:"endpoint"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type GatewayCommandEnvelope struct {
	OwnerID   string          `json:"owner_id"`
	CommandID string          `json:"command_id"`
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type GatewayCommandResult struct {
	CommandID string    `json:"command_id"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (c *Client) SetGatewayPresence(ctx context.Context, presence GatewayPresence, ttl time.Duration) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	presence.GatewayID = strings.TrimSpace(presence.GatewayID)
	presence.OwnerID = strings.TrimSpace(presence.OwnerID)
	if presence.GatewayID == "" || presence.OwnerID == "" {
		return fmt.Errorf("gateway presence requires gateway_id and owner_id")
	}
	if ttl <= 0 {
		ttl = 3 * time.Second
	}
	now := time.Now().UTC()
	presence.UpdatedAt = now
	presence.ExpiresAt = now.Add(ttl)
	raw, err := json.Marshal(presence)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, gatewayPresenceKey(presence.GatewayID), raw, ttl).Err()
}

func (c *Client) GetGatewayPresence(ctx context.Context, gatewayID string) (GatewayPresence, bool, error) {
	var presence GatewayPresence
	if c == nil || c.rdb == nil {
		return presence, false, ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := c.rdb.Get(ctx, gatewayPresenceKey(gatewayID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return presence, false, nil
	}
	if err != nil {
		return presence, false, err
	}
	if err := json.Unmarshal(raw, &presence); err != nil {
		_ = c.rdb.Del(ctx, gatewayPresenceKey(gatewayID)).Err()
		return presence, false, nil
	}
	return presence, true, nil
}

func (c *Client) DeleteGatewayPresence(ctx context.Context, gatewayID, ownerID string) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	presence, ok, err := c.GetGatewayPresence(ctx, gatewayID)
	if err != nil || !ok {
		return err
	}
	if strings.TrimSpace(ownerID) != "" && presence.OwnerID != strings.TrimSpace(ownerID) {
		return nil
	}
	return c.rdb.Del(ctx, gatewayPresenceKey(gatewayID)).Err()
}

func (c *Client) ListGatewayPresence(ctx context.Context) ([]GatewayPresence, error) {
	if c == nil || c.rdb == nil {
		return nil, ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	prefix := gatewayPresenceKey("")
	var cursor uint64
	var out []GatewayPresence
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
			var presence GatewayPresence
			if err := json.Unmarshal(raw, &presence); err == nil {
				out = append(out, presence)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}

func (c *Client) EnqueueGatewayCommand(ctx context.Context, gatewayID, ownerID, commandID string, payload []byte, ttl time.Duration) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	presence, ok, err := c.GetGatewayPresence(ctx, gatewayID)
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(presence.OwnerID) == "" {
		return ErrGatewayControlNotConnected
	}
	if strings.TrimSpace(ownerID) != "" && presence.OwnerID != strings.TrimSpace(ownerID) {
		return ErrGatewayControlOwnerChanged
	}
	envelope := GatewayCommandEnvelope{
		OwnerID:   presence.OwnerID,
		CommandID: strings.TrimSpace(commandID),
		Payload:   append([]byte(nil), payload...),
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	queueKey := gatewayCommandQueueKey(gatewayID)
	pipe := c.rdb.TxPipeline()
	pipe.RPush(ctx, queueKey, raw)
	pipe.Expire(ctx, queueKey, ttl+time.Minute)
	_, err = pipe.Exec(ctx)
	return err
}

func (c *Client) PopGatewayCommand(ctx context.Context, gatewayID, ownerID string, timeout time.Duration) (*GatewayCommandEnvelope, error) {
	if c == nil || c.rdb == nil {
		return nil, ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	presence, ok, err := c.GetGatewayPresence(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	if !ok || presence.OwnerID != strings.TrimSpace(ownerID) {
		return nil, ErrGatewayControlOwnerChanged
	}
	if timeout < time.Second {
		raw, err := c.rdb.LPop(ctx, gatewayCommandQueueKey(gatewayID)).Bytes()
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return c.decodeGatewayCommand(ctx, gatewayID, ownerID, raw)
	}
	result, err := c.rdb.BLPop(ctx, timeout, gatewayCommandQueueKey(gatewayID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(result) < 2 {
		return nil, nil
	}
	return c.decodeGatewayCommand(ctx, gatewayID, ownerID, []byte(result[1]))
}

func (c *Client) decodeGatewayCommand(ctx context.Context, gatewayID, ownerID string, raw []byte) (*GatewayCommandEnvelope, error) {
	var envelope GatewayCommandEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if !envelope.ExpiresAt.IsZero() && !time.Now().UTC().Before(envelope.ExpiresAt) {
		_ = c.CompleteGatewayCommand(ctx, envelope.CommandID, "gateway control command expired", time.Minute)
		return nil, nil
	}
	if envelope.OwnerID != strings.TrimSpace(ownerID) {
		presence, ok, err := c.GetGatewayPresence(ctx, gatewayID)
		if err != nil {
			return nil, err
		}
		if ok && presence.OwnerID == envelope.OwnerID {
			_ = c.rdb.LPush(ctx, gatewayCommandQueueKey(gatewayID), raw).Err()
			return nil, nil
		}
		_ = c.CompleteGatewayCommand(ctx, envelope.CommandID, "gateway control stream was replaced", time.Minute)
		return nil, nil
	}
	return &envelope, nil
}

func (c *Client) CompleteGatewayCommand(ctx context.Context, commandID, errMessage string, ttl time.Duration) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	result := GatewayCommandResult{
		CommandID: strings.TrimSpace(commandID),
		Error:     strings.TrimSpace(errMessage),
		CreatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, gatewayCommandResultKey(commandID), raw, ttl).Err()
}

func (c *Client) GetGatewayCommandResult(ctx context.Context, commandID string) (GatewayCommandResult, bool, error) {
	var result GatewayCommandResult
	if c == nil || c.rdb == nil {
		return result, false, ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := c.rdb.Get(ctx, gatewayCommandResultKey(commandID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, false, err
	}
	return result, true, nil
}

func gatewayPresenceKey(gatewayID string) string {
	return keyPrefix + ":gateway-control:presence:" + strings.TrimSpace(gatewayID)
}

func gatewayCommandQueueKey(gatewayID string) string {
	return keyPrefix + ":gateway-control:queue:" + strings.TrimSpace(gatewayID)
}

func gatewayCommandResultKey(commandID string) string {
	return keyPrefix + ":gateway-control:result:" + strings.TrimSpace(commandID)
}
