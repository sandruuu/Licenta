package tray

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"ztna.local/agent/internal/enrollment"
	"ztna.local/agent/internal/ipc"
	"ztna.local/agent/internal/meta"
	"ztna.local/agent/internal/oidc"
	"ztna.local/agent/internal/process"
)

type Options struct {
	GUI       bool
	Message   string
	Stay      bool
	Timeout   time.Duration
	Login     bool
	CloudURL  string
	IssuerURL string
	ClientID  string
	Scopes    string
	DeviceID  string
	Nonce     string
	UserSID   string
	KeyName   string
	Hostname  string
	CAFile    string
	ACRValues string
}

func Run(ctx context.Context, options Options, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if options.GUI {
		return runGUI(ctx, options, logger)
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	identity := process.Current()
	message := options.Message
	if message == "" {
		message = meta.DefaultDemoMessage
	}
	client := newDefaultClient()
	request := ipc.PingRequest{
		Message:     message,
		TrayPID:     identity.PID,
		TrayUser:    identity.Username,
		TrayUserSID: identity.UserSID,
		SentAt:      time.Now().UTC(),
	}
	callCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	var response ipc.PingResponse
	if err := client.Call(callCtx, ipc.OperationPing, request, &response); err != nil {
		return err
	}
	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ping response: %w", err)
	}
	fmt.Printf("ZTNA Agent tray process\n")
	fmt.Printf("Tray PID: %d\n", identity.PID)
	fmt.Printf("Tray user: %s\n", identity.Username)
	fmt.Printf("Tray SID: %s\n", identity.UserSID)
	fmt.Printf("IPC response:\n%s\n", data)
	logger.Info("ZTNA Agent tray IPC proof completed", "tray_pid", identity.PID, "service_pid", response.ServicePID)
	var login *loginSession
	if options.Login {
		var err error
		login, err = runLogin(ctx, client, options, identity, logger)
		if err != nil {
			return err
		}
	}
	if !options.Stay {
		return nil
	}
	if login != nil {
		go runAccessTokenRefreshLoop(ctx, client, login, options.Timeout, logger)
	}
	fmt.Println("Tray proof is staying resident. Press Ctrl+C to exit.")
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	select {
	case <-ctx.Done():
		return nil
	case <-signals:
		return nil
	}
}

type loginSession struct {
	authenticator *oidc.Authenticator
	deviceID      string
	userSID       string
}

func runLogin(ctx context.Context, client *ipc.Client, options Options, identity process.Identity, logger *slog.Logger) (*loginSession, error) {
	statusCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	var status ipc.AgentStatus
	if err := client.Call(statusCtx, ipc.OperationGetStatus, ipc.StatusRequest{}, &status); err != nil {
		return nil, fmt.Errorf("get service enrollment status: %w", err)
	}
	deviceID := firstNonEmpty(options.DeviceID, status.DeviceID)
	nonce := firstNonEmpty(options.Nonce, status.EnrollmentNonce)
	userSID := firstNonEmpty(options.UserSID, status.ActiveUserSID, identity.UserSID)
	keyName := firstNonEmpty(options.KeyName, status.KeyName)
	if keyName == "" && userSID != "" {
		keyName = "ZTNA_DeviceKey_" + userSID
	}
	cloudURL := strings.TrimRight(strings.TrimSpace(options.CloudURL), "/")
	issuerURL := strings.TrimRight(strings.TrimSpace(firstNonEmpty(options.IssuerURL, options.CloudURL)), "/")
	if cloudURL == "" {
		return nil, fmt.Errorf("cloud URL is required for tray login")
	}
	if issuerURL == "" {
		return nil, fmt.Errorf("issuer URL is required for tray login")
	}
	if deviceID == "" {
		return nil, fmt.Errorf("device_id is required for tray login")
	}
	if nonce == "" {
		return nil, fmt.Errorf("enrollment nonce is required for tray login")
	}
	if userSID == "" {
		return nil, fmt.Errorf("user SID is required for tray login")
	}
	if keyName == "" {
		return nil, fmt.Errorf("key name is required for tray login")
	}
	authenticator, err := oidc.NewAuthenticator(oidc.Config{
		IssuerURL:   issuerURL,
		ClientID:    options.ClientID,
		Scopes:      options.Scopes,
		DeviceID:    deviceID,
		Hostname:    options.Hostname,
		CAFile:      options.CAFile,
		OpenBrowser: newDefaultBrowserOpener(),
	})
	if err != nil {
		return nil, err
	}
	tokens, err := authenticator.Authenticate(ctx, options.ACRValues)
	if err != nil {
		return nil, err
	}
	enrollmentClient, err := enrollment.NewClient(enrollment.Config{CloudURL: cloudURL, CAFile: options.CAFile})
	if err != nil {
		return nil, err
	}
	enrollmentToken, err := enrollmentClient.RequestEnrollmentToken(ctx, enrollment.TokenRequest{
		AccessToken: tokens.AccessToken,
		DeviceID:    deviceID,
		Nonce:       nonce,
		UserSID:     userSID,
	})
	if err != nil {
		return nil, err
	}
	submitCtx, submitCancel := context.WithTimeout(ctx, options.Timeout)
	defer submitCancel()
	var submitResponse ipc.SubmitEnrollmentTokenResponse
	if err := client.Call(submitCtx, ipc.OperationSubmitEnrollmentToken, ipc.SubmitEnrollmentTokenRequest{
		Token:                enrollmentToken.EnrollmentToken,
		AccessToken:          tokens.AccessToken,
		AccessTokenExpiresAt: tokens.ExpiresAt,
		Nonce:                enrollmentToken.Nonce,
		DeviceID:             enrollmentToken.DeviceID,
		UserSID:              userSID,
		KeyName:              keyName,
		UserEmail:            enrollmentToken.UserEmail,
		ExpiresAt:            enrollmentToken.ExpiresAt,
		ExpiresInSeconds:     enrollmentToken.ExpiresIn,
		SentAt:               time.Now().UTC(),
	}, &submitResponse); err != nil {
		return nil, fmt.Errorf("submit enrollment token to service: %w", err)
	}
	if err := sendAccessTokenUpdate(ctx, client, options.Timeout, tokens.AccessToken, tokens.ExpiresAt, enrollmentToken.DeviceID, userSID); err != nil {
		return nil, err
	}
	fmt.Printf("OIDC user: %s\n", safeValue(tokens.Username))
	fmt.Printf("OIDC role: %s\n", safeValue(tokens.Role))
	fmt.Printf("Enrollment device ID: %s\n", enrollmentToken.DeviceID)
	fmt.Printf("Enrollment token expires at: %s\n", enrollmentToken.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("Service enrollment ACK: accepted=%t state=%s key=%s\n", submitResponse.Accepted, submitResponse.EnrollmentState, submitResponse.KeyName)
	logger.Info("Enrollment token submitted to service", "device_id", enrollmentToken.DeviceID, "user_sid", userSID, "key_name", keyName, "accepted", submitResponse.Accepted)
	return &loginSession{authenticator: authenticator, deviceID: enrollmentToken.DeviceID, userSID: userSID}, nil
}

func sendAccessTokenUpdate(ctx context.Context, client *ipc.Client, timeout time.Duration, accessToken string, expiresAt time.Time, deviceID, userSID string) error {
	updateCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var response ipc.UpdateAccessTokenResponse
	if err := client.Call(updateCtx, ipc.OperationUpdateAccessToken, ipc.UpdateAccessTokenRequest{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
		DeviceID:    deviceID,
		UserSID:     userSID,
		SentAt:      time.Now().UTC(),
	}, &response); err != nil {
		return fmt.Errorf("update service access token: %w", err)
	}
	return nil
}

func runAccessTokenRefreshLoop(ctx context.Context, client *ipc.Client, login *loginSession, timeout time.Duration, logger *slog.Logger) {
	if login == nil || login.authenticator == nil {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			accessToken, expiresAt := login.authenticator.CurrentAccessTokenInfo()
			if accessToken != "" && !expiresAt.IsZero() && time.Until(expiresAt) > 5*time.Minute {
				continue
			}
			refreshTimeout := timeout
			if refreshTimeout < 5*time.Minute {
				refreshTimeout = 5 * time.Minute
			}
			refreshCtx, cancel := context.WithTimeout(ctx, refreshTimeout)
			tokens, err := login.authenticator.Authenticate(refreshCtx, "")
			cancel()
			if err != nil {
				logger.Warn("OIDC access token refresh failed", "error", err)
				continue
			}
			if err := sendAccessTokenUpdate(ctx, client, timeout, tokens.AccessToken, tokens.ExpiresAt, login.deviceID, login.userSID); err != nil {
				logger.Warn("Service access token update failed", "error", err)
				continue
			}
			logger.Info("Service access token refreshed", "device_id", login.deviceID, "expires_at", tokens.ExpiresAt.Format(time.RFC3339))
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func safeValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return strings.TrimSpace(value)
}
