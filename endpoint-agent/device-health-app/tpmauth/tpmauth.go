package tpmauth

import (
	"context"

	endpointidentity "ztna.local/shared/endpointidentity"
)

type KeyManager = endpointidentity.KeyManager
type EnrollmentResult = endpointidentity.EnrollmentResult

func NewKeyManager(dataDir string) (*KeyManager, error) {
	return endpointidentity.NewKeyManager(dataDir)
}

func EnrollAndWait(ctx context.Context, km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir string) (*EnrollmentResult, error) {
	return endpointidentity.EnrollAndWait(ctx, km, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir)
}

func StartAutoRenewal(ctx context.Context, km *KeyManager, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir string) {
	endpointidentity.StartAutoRenewal(ctx, km, cloudURL, caFile, certSHA256, deviceID, hostname, dataDir)
}
