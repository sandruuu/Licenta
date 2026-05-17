package controlplane

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"google.golang.org/grpc"
)

const (
	controlReconnectMin = time.Second
	controlReconnectMax = 30 * time.Second
)

func (client *Client) RunControlStream(ctx context.Context, gatewayID string, sessionHandler SessionHandler) error {
	if ctx == nil {
		ctx = context.Background()
	}
	protocol, err := NewHandler(gatewayID, sessionHandler, nil)
	if err != nil {
		return err
	}

	backoff := controlReconnectMin
	for {
		err := client.runControlStreamOnce(ctx, protocol)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			log.Printf("[CONTROL] Gateway control stream ended with error: %v", err)
		} else {
			log.Printf("[CONTROL] Gateway control stream ended; reconnecting")
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
		if backoff > controlReconnectMax {
			backoff = controlReconnectMax
		}
	}
}

func (client *Client) runControlStreamOnce(ctx context.Context, protocol *Handler) error {
	conn, err := client.dial(ctx)
	if err != nil {
		return fmt.Errorf("dial PA gateway control service: %w", err)
	}
	defer conn.Close()

	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "ControlStream", ServerStreams: true, ClientStreams: true}, ControlStreamPath)
	if err != nil {
		return fmt.Errorf("open PA gateway control stream: %w", err)
	}
	if err := protocol.Run(ctx, stream); err != nil && err != io.EOF {
		return err
	}
	return nil
}
