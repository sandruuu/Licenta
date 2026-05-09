package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gateway/internal/provisioning"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ServiceName       = "ztna.gateway.v1.GatewayControlService"
	ControlStreamPath = "/ztna.gateway.v1.GatewayControlService/ControlStream"

	CommandProvisionSession = "provision_session"
	CommandRevokeSession    = "revoke_session"
	CommandHeartbeat        = "heartbeat"

	MessageGatewayHello = "gateway_hello"
	MessageAck          = "ack"

	ackStatusOK    = "ok"
	ackStatusError = "error"
)

type SessionHandler interface {
	ProvisionSession(session provisioning.Session, sessionToken string) error
	RevokeProvisionedSession(sessionID, reason string) bool
}

type Config struct {
	PAURL           string
	GatewayID       string
	GatewayEndpoint string
	ServerName      string
	CAFile          string
	CertFile        string
	KeyFile         string
	ReconnectMin    time.Duration
	ReconnectMax    time.Duration
	DialOptions     []grpc.DialOption
	Now             func() time.Time
}

type Client struct {
	config  Config
	handler SessionHandler
}

func NewClient(config Config, handler SessionHandler) (*Client, error) {
	config.PAURL = strings.TrimSpace(config.PAURL)
	config.GatewayID = strings.TrimSpace(config.GatewayID)
	config.GatewayEndpoint = strings.TrimSpace(config.GatewayEndpoint)
	config.ServerName = strings.TrimSpace(config.ServerName)
	config.CAFile = strings.TrimSpace(config.CAFile)
	config.CertFile = strings.TrimSpace(config.CertFile)
	config.KeyFile = strings.TrimSpace(config.KeyFile)
	if config.PAURL == "" {
		return nil, errors.New("PA control URL is required")
	}
	if config.GatewayID == "" {
		return nil, errors.New("gateway_id is required")
	}
	if config.CertFile == "" || config.KeyFile == "" {
		return nil, errors.New("gateway control mTLS certificate and key are required")
	}
	if handler == nil {
		return nil, errors.New("session handler is required")
	}
	if config.ReconnectMin <= 0 {
		config.ReconnectMin = time.Second
	}
	if config.ReconnectMax <= 0 {
		config.ReconnectMax = 30 * time.Second
	}
	if config.ReconnectMax < config.ReconnectMin {
		config.ReconnectMax = config.ReconnectMin
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Client{config: config, handler: handler}, nil
}

func (client *Client) Run(ctx context.Context) error {
	if client == nil {
		return errors.New("gateway control client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	backoff := client.config.ReconnectMin
	for {
		err := client.RunOnce(ctx)
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
		if backoff > client.config.ReconnectMax {
			backoff = client.config.ReconnectMax
		}
	}
}

func (client *Client) RunOnce(ctx context.Context) error {
	if client == nil {
		return errors.New("gateway control client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	target, serverName, err := targetFromURL(client.config.PAURL)
	if err != nil {
		return err
	}
	tlsConfig, err := clientTLSConfig(client.config, serverName)
	if err != nil {
		return err
	}
	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	dialOptions = append(dialOptions, client.config.DialOptions...)
	conn, err := grpc.DialContext(ctx, target, dialOptions...)
	if err != nil {
		return fmt.Errorf("dial PA gateway control service: %w", err)
	}
	defer conn.Close()

	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "ControlStream", ServerStreams: true, ClientStreams: true}, ControlStreamPath)
	if err != nil {
		return fmt.Errorf("open PA gateway control stream: %w", err)
	}
	if err := stream.SendMsg(client.helloMessage()); err != nil {
		return fmt.Errorf("send gateway control hello: %w", err)
	}
	for {
		command := &structpb.Struct{}
		err := stream.RecvMsg(command)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("receive gateway control command: %w", err)
		}
		ack := client.handleCommand(command)
		if err := stream.SendMsg(ack); err != nil {
			return fmt.Errorf("send gateway control ack: %w", err)
		}
	}
}

func (client *Client) helloMessage() *structpb.Struct {
	message, _ := structpb.NewStruct(map[string]interface{}{
		"type":             MessageGatewayHello,
		"gateway_id":       client.config.GatewayID,
		"gateway_endpoint": client.config.GatewayEndpoint,
		"sent_at":          client.config.Now().UTC().Format(time.RFC3339Nano),
	})
	return message
}

func (client *Client) handleCommand(command *structpb.Struct) *structpb.Struct {
	commandID := structFieldString(command, "command_id")
	commandType := strings.ToLower(strings.TrimSpace(structFieldString(command, "type")))
	switch commandType {
	case CommandProvisionSession:
		session, token, err := sessionFromCommand(command)
		if err != nil {
			return client.ack(commandID, ackStatusError, "invalid_argument", err.Error())
		}
		if err := client.handler.ProvisionSession(session, token); err != nil {
			return client.ack(commandID, ackStatusError, "provision_failed", err.Error())
		}
		return client.ack(commandID, ackStatusOK, "", "session provisioned")
	case CommandRevokeSession:
		sessionID := firstNonEmpty(structFieldString(command, "session_id"), nestedString(command, "session", "session_id"), nestedString(command, "session", "id"))
		reason := firstNonEmpty(structFieldString(command, "reason"), nestedString(command, "session", "reason"))
		if strings.TrimSpace(sessionID) == "" {
			return client.ack(commandID, ackStatusError, "invalid_argument", "session_id is required")
		}
		if !client.handler.RevokeProvisionedSession(sessionID, reason) {
			return client.ack(commandID, ackStatusError, provisioning.CodeSessionNotFound, "session was not provisioned")
		}
		return client.ack(commandID, ackStatusOK, "", "session revoked")
	case CommandHeartbeat:
		return client.ack(commandID, ackStatusOK, "", "heartbeat received")
	default:
		return client.ack(commandID, ackStatusError, "unsupported_command", fmt.Sprintf("unsupported command type %q", commandType))
	}
}

func (client *Client) ack(commandID, statusValue, code, message string) *structpb.Struct {
	fields := map[string]interface{}{
		"type":       MessageAck,
		"gateway_id": client.config.GatewayID,
		"command_id": strings.TrimSpace(commandID),
		"status":     statusValue,
		"message":    strings.TrimSpace(message),
		"sent_at":    client.config.Now().UTC().Format(time.RFC3339Nano),
	}
	if strings.TrimSpace(code) != "" {
		fields["code"] = strings.TrimSpace(code)
	}
	ack, _ := structpb.NewStruct(fields)
	return ack
}

func sessionFromCommand(command *structpb.Struct) (provisioning.Session, string, error) {
	sessionValue := command.GetFields()["session"]
	if sessionValue == nil || sessionValue.GetStructValue() == nil {
		return provisioning.Session{}, "", errors.New("session object is required")
	}
	sessionStruct := sessionValue.GetStructValue()
	expiresAt, err := timeField(sessionStruct, "expires_at")
	if err != nil {
		return provisioning.Session{}, "", err
	}
	internalPort, err := intField(sessionStruct, "internal_port")
	if err != nil {
		return provisioning.Session{}, "", err
	}
	maxBandwidth, err := optionalIntField(sessionStruct, "max_bandwidth_mbps")
	if err != nil {
		return provisioning.Session{}, "", err
	}
	session := provisioning.Session{
		ID:               firstNonEmpty(structFieldString(sessionStruct, "session_id"), structFieldString(sessionStruct, "id")),
		DeviceID:         structFieldString(sessionStruct, "device_id"),
		UserID:           structFieldString(sessionStruct, "user_id"),
		Username:         structFieldString(sessionStruct, "username"),
		ResourceID:       structFieldString(sessionStruct, "resource_id"),
		ResourceName:     structFieldString(sessionStruct, "resource_name"),
		InternalHost:     structFieldString(sessionStruct, "internal_host"),
		InternalPort:     internalPort,
		Protocol:         structFieldString(sessionStruct, "protocol"),
		ExpiresAt:        expiresAt,
		Constraints:      stringListField(sessionStruct, "constraints"),
		PolicyVersion:    structFieldString(sessionStruct, "policy_version"),
		MaxBandwidthMbps: maxBandwidth,
	}
	token := structFieldString(sessionStruct, "session_token")
	return session, token, nil
}

func clientTLSConfig(config Config, defaultServerName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load gateway control mTLS certificate: %w", err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	if strings.TrimSpace(config.ServerName) != "" {
		tlsConfig.ServerName = strings.TrimSpace(config.ServerName)
	} else if strings.TrimSpace(defaultServerName) != "" {
		tlsConfig.ServerName = strings.TrimSpace(defaultServerName)
	}
	if strings.TrimSpace(config.CAFile) != "" {
		pool, err := rootCAPool(config.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}

func rootCAPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read PA control CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("PA control CA file does not contain PEM certificates")
	}
	return pool, nil
}

func targetFromURL(raw string) (string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", errors.New("PA control URL host is required")
	}
	if !strings.Contains(trimmed, "://") {
		host := trimmed
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "443")
		}
		serverName := host
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			serverName = splitHost
		}
		return host, serverName, nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("parse PA control URL: %w", err)
	}
	host := parsed.Host
	if host == "" && parsed.Scheme == "" && parsed.Path != "" {
		host = parsed.Path
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", errors.New("PA control URL host is required")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			serverName = splitHost
		}
	}
	return host, serverName, nil
}

func structFieldString(value *structpb.Struct, key string) string {
	if value == nil || value.GetFields()[key] == nil {
		return ""
	}
	return strings.TrimSpace(value.GetFields()[key].GetStringValue())
}

func nestedString(value *structpb.Struct, objectKey, key string) string {
	if value == nil || value.GetFields()[objectKey] == nil || value.GetFields()[objectKey].GetStructValue() == nil {
		return ""
	}
	return structFieldString(value.GetFields()[objectKey].GetStructValue(), key)
}

func intField(value *structpb.Struct, key string) (int, error) {
	if value == nil || value.GetFields()[key] == nil {
		return 0, fmt.Errorf("%s is required", key)
	}
	number := value.GetFields()[key].GetNumberValue()
	if number <= 0 || number != float64(int(number)) {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return int(number), nil
}

func optionalIntField(value *structpb.Struct, key string) (int, error) {
	if value == nil || value.GetFields()[key] == nil {
		return 0, nil
	}
	number := value.GetFields()[key].GetNumberValue()
	if number < 0 || number != float64(int(number)) {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return int(number), nil
}

func timeField(value *structpb.Struct, key string) (time.Time, error) {
	text := structFieldString(value, key)
	if text == "" {
		return time.Time{}, fmt.Errorf("%s is required", key)
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", key)
	}
	return parsed.UTC(), nil
}

func stringListField(value *structpb.Struct, key string) []string {
	if value == nil || value.GetFields()[key] == nil || value.GetFields()[key].GetListValue() == nil {
		return nil
	}
	items := value.GetFields()[key].GetListValue().GetValues()
	stringsOut := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if text := strings.TrimSpace(item.GetStringValue()); text != "" {
			stringsOut = append(stringsOut, text)
		}
	}
	return stringsOut
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
