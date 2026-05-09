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
	AuthURL   string
	Code      string
	ACRValues string
}

func (e *ErrAuthRequired) Error() string {
	return fmt.Sprintf("Gateway requires authentication: %s", e.AuthURL)
}

type RequestPayload struct {
	Type       string           `json:"type"`
	Domain     string           `json:"domain,omitempty"`
	RemoteAddr string           `json:"remote_addr,omitempty"`
	RemotePort int              `json:"remote_port,omitempty"`
	Token      string           `json:"token,omitempty"`
	DeviceID   string           `json:"device_id,omitempty"`
	Process    *ProcessIdentity `json:"process,omitempty"`
}

// ProcessIdentity describes the local application process that originated a
// TCP flow intercepted by connect-app. It is a contextual policy signal and is
// not treated as cryptographic proof of application identity.
type ProcessIdentity struct {
	PID    int    `json:"pid,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Signer string `json:"signer,omitempty"`
}

// HelloRequest is the first frame the connect-app sends after the yamux
// session is established. Mirrors gateway/internal/auth.HelloRequest.
type HelloRequest struct {
	Type          string   `json:"type"` // "hello"
	ClientVersion string   `json:"client_version"`
	ClientApp     string   `json:"client_app"`
	ClientBuild   string   `json:"client_build"`
	Features      []string `json:"features"`
}

// HelloResponse is the gateway's reply to HelloRequest.
type HelloResponse struct {
	Type             string   `json:"type"`
	Code             string   `json:"code"`
	ServerVersion    string   `json:"server_version"`
	MinClientVersion string   `json:"min_client_version"`
	MaxClientVersion string   `json:"max_client_version"`
	Features         []string `json:"features"`
	Message          string   `json:"message,omitempty"`
}

// Wire-protocol version supported by this build. Bumped on breaking changes
// to the JSON request/response shapes exchanged over yamux streams.
const ProtocolVersion = "1.0"

// ClientBuild can be overridden at link time via -ldflags
// "-X connect-app/tunnel.ClientBuild=$(git rev-parse --short HEAD)".
var ClientBuild = "dev"

type ResponsePayload struct {
	Status    string `json:"status"`
	Code      string `json:"code,omitempty"` // structured error code (see error_codes.go)
	CGNATIP   string `json:"cgnat_ip,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
	AuthURL   string `json:"auth_url,omitempty"`
	ACRValues string `json:"acr_values,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Structured error codes returned by the gateway in ResponsePayload.Code.
// Mirrors gateway/internal/auth constants. Connect-app branches on these so
// upstream UX (toast messages, retry policy) stays stable across gateway
// versions even when human-readable Message strings are reworded.
const (
	CodeOK                      = "ok"
	CodeAuthRequired            = "auth_required"
	CodeAuthInvalid             = "auth_invalid"
	CodeMFARequired             = "mfa_required"
	CodePostureDenied           = "posture_denied"
	CodePolicyDenied            = "policy_denied"
	CodeRiskDenied              = "risk_denied"
	CodeSessionExpired          = "session_expired"
	CodeSessionStoreUnavailable = "session_store_unavailable"
	CodeCloudUnreachable        = "cloud_unreachable"
	CodeRateLimited             = "rate_limited"
	CodeResourceUnknown         = "resource_unknown"
	CodeDNSNotFound             = "dns_not_found"
	CodeDNSResolveFailed        = "dns_resolve_failed"
	CodeInternalError           = "internal_error"
	CodeBadRequest              = "bad_request"
)

// IsTransientCode reports whether a given error code represents a transient
// failure that may resolve on retry, rather than a permanent denial.
func IsTransientCode(code string) bool {
	switch code {
	case CodeCloudUnreachable, CodeSessionStoreUnavailable, CodeRateLimited, CodeInternalError:
		return true
	}
	return false
}

func authRequiredError(resp ResponsePayload) *ErrAuthRequired {
	if resp.Status != "auth_required" && resp.Code != CodeAuthRequired && resp.Code != CodeMFARequired {
		return nil
	}
	code := resp.Code
	if code == "" {
		code = CodeAuthRequired
	}
	return &ErrAuthRequired{AuthURL: resp.AuthURL, Code: code, ACRValues: resp.ACRValues}
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

	if authErr := authRequiredError(resp); authErr != nil {
		return "", 0, authErr
	}
	if resp.Status != "resolved" && resp.Status != "ok" {
		if resp.Code != "" {
			return "", 0, fmt.Errorf("Gateway dns error [%s]: %s", resp.Code, resp.Message)
		}
		return "", 0, fmt.Errorf("Gateway dns error: %s", resp.Message)
	}

	slog.Debug("DNS resolved via gateway", "domain", domain, "cgnat_ip", resp.CGNATIP, "ttl", resp.TTL)
	return resp.CGNATIP, resp.TTL, nil
}

func (t *Tunnel) OpenResourceStream(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	return t.OpenResourceStreamWithProcess(ctx, targetHost, targetPort, nil)
}

func (t *Tunnel) OpenResourceStreamWithProcess(ctx context.Context, targetHost string, targetPort int, process *ProcessIdentity) (net.Conn, error) {
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
		Process:    process,
	}
	if token, deviceID := t.AuthCredentials(); token != "" {
		reqPayload.Token = token
		reqPayload.DeviceID = deviceID
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

	if authErr := authRequiredError(resp); authErr != nil {
		stream.Close()
		return nil, authErr
	}
	if resp.Status != "connected" {
		stream.Close()
		if resp.Code != "" {
			return nil, fmt.Errorf("Gateway proxy error [%s]: %s", resp.Code, resp.Message)
		}
		return nil, fmt.Errorf("Gateway proxy error: %s", resp.Message)
	}

	// Clear the deadline for the data phase — the stream will be used for long-lived forwarding
	stream.SetDeadline(time.Time{})

	return stream, nil
}
