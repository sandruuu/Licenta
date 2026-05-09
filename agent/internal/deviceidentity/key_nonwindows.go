//go:build !windows

package deviceidentity

import (
	"context"
	"crypto"
	"fmt"
)

func (*KeyStore) EnsureSigningKey(context.Context, string) (crypto.Signer, error) {
	return nil, fmt.Errorf("machine-scope NCrypt TPM keys are only supported on Windows")
}

func (*KeyStore) OpenSigningKey(context.Context, string) (crypto.Signer, error) {
	return nil, fmt.Errorf("machine-scope NCrypt TPM keys are only supported on Windows")
}
