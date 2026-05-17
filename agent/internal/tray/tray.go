package tray

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"agent/internal/platform/process"
	sharedidentity "agent/internal/shared/identity"
	"agent/internal/shared/ipc"
	"agent/internal/tray/oidc"
)

type Options struct {
	Timeout                  time.Duration
	EnrollmentTimeout        time.Duration
	TokenRefreshInterval     time.Duration
	TokenRefreshMargin       time.Duration
	DashboardRefreshInterval time.Duration
	PAURL                    string
	IssuerURL                string
	ClientID                 string
	Scopes                   string
	DeviceID                 string
	Nonce                    string
	LocalSID                 string
	KeyName                  string
	Hostname                 string
	CAFile                   string
	ACRValues                string
}

func Run(ctx context.Context, options Options, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Timeout <= 0 {
		return fmt.Errorf("tray timeout is required")
	}
	if options.EnrollmentTimeout <= 0 {
		return fmt.Errorf("tray enrollment timeout is required")
	}
	if options.TokenRefreshInterval <= 0 {
		return fmt.Errorf("tray token refresh interval is required")
	}
	if options.TokenRefreshMargin <= 0 {
		return fmt.Errorf("tray token refresh margin is required")
	}
	if options.DashboardRefreshInterval <= 0 {
		return fmt.Errorf("tray dashboard refresh interval is required")
	}
	return runGUI(ctx, options, logger)
}

type loginSession struct {
	authenticator *oidc.Authenticator
	deviceID      string
	localSID      string
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
	localSID := firstNonEmpty(options.LocalSID, status.ActiveUserSID, identity.UserSID)
	keyName := firstNonEmpty(options.KeyName, status.KeyName)
	if keyName == "" {
		keyName = sharedidentity.KeyNameForDevice()
	}
	paURL := strings.TrimRight(strings.TrimSpace(options.PAURL), "/")
	issuerURL := strings.TrimRight(strings.TrimSpace(firstNonEmpty(options.IssuerURL, options.PAURL)), "/")
	if paURL == "" {
		return nil, fmt.Errorf("PA URL is required for tray login")
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
	if localSID == "" {
		return nil, fmt.Errorf("local user SID is required for tray login")
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
	submitCtx, submitCancel := context.WithTimeout(ctx, options.Timeout)
	defer submitCancel()
	var submitResponse ipc.StartEnrollmentResponse
	if err := client.Call(submitCtx, ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          tokens.AccessToken,
		AccessTokenExpiresAt: tokens.ExpiresAt,
		Nonce:                nonce,
		DeviceID:             deviceID,
		UserSID:              localSID,
		KeyName:              keyName,
		UserEmail:            tokens.Username,
		SentAt:               time.Now().UTC(),
	}, &submitResponse); err != nil {
		return nil, fmt.Errorf("start service enrollment: %w", err)
	}
	logger.Info("Enrollment started through service", "device_id", deviceID, "local_user_sid", localSID, "key_name", keyName, "accepted", submitResponse.Accepted)
	return &loginSession{authenticator: authenticator, deviceID: deviceID, localSID: localSID}, nil
}

func sendAccessTokenUpdate(ctx context.Context, client *ipc.Client, timeout time.Duration, accessToken string, expiresAt time.Time, deviceID, localSID string) error {
	updateCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var response ipc.UpdateAccessTokenResponse
	if err := client.Call(updateCtx, ipc.OperationUpdateAccessToken, ipc.UpdateAccessTokenRequest{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
		DeviceID:    deviceID,
		UserSID:     localSID,
		SentAt:      time.Now().UTC(),
	}, &response); err != nil {
		return fmt.Errorf("update service access token: %w", err)
	}
	return nil
}

func runAccessTokenRefreshLoop(ctx context.Context, client *ipc.Client, login *loginSession, timeout, refreshInterval, refreshMargin time.Duration, logger *slog.Logger) {
	if login == nil || login.authenticator == nil {
		return
	}
	if timeout <= 0 || refreshInterval <= 0 || refreshMargin <= 0 {
		return
	}
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			accessToken, expiresAt := login.authenticator.CurrentAccessTokenInfo()
			if accessToken != "" && !expiresAt.IsZero() && time.Until(expiresAt) > refreshMargin {
				continue
			}
			refreshCtx, cancel := context.WithTimeout(ctx, timeout)
			tokens, err := login.authenticator.Refresh(refreshCtx)
			cancel()
			if err != nil {
				if errors.Is(err, oidc.ErrRefreshTokenUnavailable) {
					logger.Warn("OIDC refresh token is unavailable; user sign-in is required")
					return
				}
				logger.Warn("OIDC access token refresh failed", "error", err)
				continue
			}
			if err := sendAccessTokenUpdate(ctx, client, timeout, tokens.AccessToken, tokens.ExpiresAt, login.deviceID, login.localSID); err != nil {
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
