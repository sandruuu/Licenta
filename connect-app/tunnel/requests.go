package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

const streamTimeout = 10 * time.Second

type ErrAuthRequired struct {
	AuthURL string
}

func (e *ErrAuthRequired) Error() string {
	return fmt.Sprintf("Gateway requires authentication: %s", e.AuthURL)
}

type RequestPayload struct {
	Type       string `json:"type"`
	Domain     string `json:"domain,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
}

type ResponsePayload struct {
	Status  string `json:"status"`
	CGNATIP string `json:"cgnat_ip,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
	AuthURL string `json:"auth_url,omitempty"`
	Message string `json:"message,omitempty"`
}

func (t *Tunnel) ResolveDomain(ctx context.Context, domain string) (cgnatIP string, ttl int, err error) {
	stream, err := t.OpenStream()
	if err != nil {
		return "", 0, fmt.Errorf("Failed to open stream for dns resolve: %w", err)
	}
	defer stream.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamTimeout)
	}
	stream.SetDeadline(deadline)

	reqPayload := RequestPayload{
		Type:   "dns_resolve",
		Domain: domain,
	}

	if err := json.NewEncoder(stream).Encode(&reqPayload); err != nil {
		return "", 0, fmt.Errorf("Failed writing dns request: %w", err)
	}

	var resp ResponsePayload
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		if err == io.EOF {
			return "", 0, fmt.Errorf("Gateway closed stream prematurely")
		}
		return "", 0, fmt.Errorf("Failed reading dns response: %w", err)
	}

	if resp.Status == "auth_required" {
		return "", 0, &ErrAuthRequired{AuthURL: resp.AuthURL}
	}
	if resp.Status != "resolved" && resp.Status != "ok" {
		return "", 0, fmt.Errorf("Gateway dns error: %s", resp.Message)
	}

	slog.Debug("DNS resolved via gateway", "domain", domain, "cgnat_ip", resp.CGNATIP, "ttl", resp.TTL)
	return resp.CGNATIP, resp.TTL, nil
}

func (t *Tunnel) OpenResourceStream(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	stream, err := t.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("Failed to open stream for proxy: %w", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamTimeout)
	}
	stream.SetDeadline(deadline)

	reqPayload := RequestPayload{
		Type:       "connect",
		RemoteAddr: targetHost,
		RemotePort: targetPort,
	}

	if err := json.NewEncoder(stream).Encode(&reqPayload); err != nil {
		stream.Close()
		return nil, fmt.Errorf("Failed writing connect request: %w", err)
	}

	var resp ResponsePayload
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		stream.Close()
		if err == io.EOF {
			return nil, fmt.Errorf("Gateway closed proxy stream prematurely")
		}
		return nil, fmt.Errorf("Failed reading connect response: %w", err)
	}

	if resp.Status == "auth_required" {
		stream.Close()
		return nil, &ErrAuthRequired{AuthURL: resp.AuthURL}
	}
	if resp.Status != "connected" {
		stream.Close()
		return nil, fmt.Errorf("Gateway proxy error: %s", resp.Message)
	}

	// Clear the deadline for the data phase — the stream will be used for long-lived forwarding
	stream.SetDeadline(time.Time{})

	return stream, nil
}
