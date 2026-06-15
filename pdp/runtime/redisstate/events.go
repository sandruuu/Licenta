package redisstate

import (
	"context"
	"fmt"
	"strings"
)

type PubSubMessage struct {
	Topic   string
	Payload []byte
}

func (c *Client) PublishEvent(topic string, payload []byte) error {
	if c == nil || c.rdb == nil {
		return ErrUnavailable
	}
	return c.rdb.Publish(context.Background(), eventChannel(topic), payload).Err()
}

func (c *Client) SubscribeEvents(ctx context.Context, topics ...string) (<-chan PubSubMessage, func() error, error) {
	if c == nil || c.rdb == nil {
		return nil, nil, ErrUnavailable
	}
	channels := make([]string, 0, len(topics))
	for _, topic := range topics {
		if trimmed := strings.TrimSpace(topic); trimmed != "" {
			channels = append(channels, eventChannel(trimmed))
		}
	}
	if len(channels) == 0 {
		return nil, nil, fmt.Errorf("at least one event topic is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pubsub := c.rdb.Subscribe(ctx, channels...)
	if err := pubsub.Ping(ctx); err != nil {
		_ = pubsub.Close()
		return nil, nil, err
	}
	out := make(chan PubSubMessage, 64)
	go func() {
		defer close(out)
		for msg := range pubsub.Channel() {
			topic := strings.TrimPrefix(msg.Channel, keyPrefix+":events:")
			out <- PubSubMessage{Topic: topic, Payload: []byte(msg.Payload)}
		}
	}()
	return out, pubsub.Close, nil
}

func eventChannel(topic string) string {
	return keyPrefix + ":events:" + strings.TrimSpace(topic)
}
