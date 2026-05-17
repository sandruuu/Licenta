package deviceidentity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"agent/internal/shared/identity"
)

const (
	DefaultKeyName                  = identity.DefaultDeviceKeyName
	DeviceIDSourceTPMEKPublicSHA256 = "tpm_ek_public_sha256"
	MicrosoftPlatformCryptoProvider = "Microsoft Platform Crypto Provider"
)

type Provider interface {
	Snapshot(context.Context) (Snapshot, error)
}

type Options struct {
	AuthorizedUserSID string
	Clock             func() time.Time
}

type Snapshot struct {
	DeviceID       string
	DeviceIDSource string
	ActiveUserSID  string
	KeyName        string
	KeyExists      bool
	KeyProvider    string
	LastError      string
	CollectedAt    time.Time
}

func NewProvider(options Options) Provider {
	return newPlatformProvider(options)
}

func KeyNameForDevice() string {
	return identity.KeyNameForDevice()
}

func DeviceIDFromEKPublic(ekPublic []byte) (string, error) {
	if len(ekPublic) == 0 {
		return "", errors.New("TPM EK public bytes are required")
	}
	digest := sha256.Sum256(ekPublic)
	return hex.EncodeToString(digest[:]), nil
}

func clockOrNow(clock func() time.Time) func() time.Time {
	if clock != nil {
		return clock
	}
	return time.Now
}
