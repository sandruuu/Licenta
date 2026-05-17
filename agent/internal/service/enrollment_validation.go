package service

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"agent/internal/shared/ipc"
)

func validateEnrollmentRequest(payload ipc.StartEnrollmentRequest, now time.Time) error {
	if strings.TrimSpace(payload.AccessToken) == "" {
		return errors.New("access_token is required")
	}
	if len(payload.AccessToken) > maxAccessTokenBytes {
		return fmt.Errorf("access token exceeds %d bytes", maxAccessTokenBytes)
	}
	if strings.Count(payload.AccessToken, ".") != 2 {
		return errors.New("access token must be JWT-shaped")
	}
	if payload.AccessTokenExpiresAt.IsZero() || !payload.AccessTokenExpiresAt.After(now) {
		return errors.New("access_token_expires_at must be in the future")
	}
	if strings.TrimSpace(payload.Nonce) == "" {
		return errors.New("nonce is required")
	}
	if strings.TrimSpace(payload.DeviceID) == "" {
		return errors.New("device_id is required")
	}
	if strings.TrimSpace(payload.UserSID) == "" {
		return errors.New("local user SID is required")
	}
	if strings.TrimSpace(payload.KeyName) == "" {
		return errors.New("key_name is required")
	}
	if strings.TrimSpace(payload.UserEmail) != "" {
		email := strings.TrimSpace(payload.UserEmail)
		addr, err := mail.ParseAddress(email)
		if err != nil || addr == nil || addr.Name != "" || addr.Address != email {
			return errors.New("user_email must be a plain RFC 822 mailbox")
		}
	}
	return nil
}
