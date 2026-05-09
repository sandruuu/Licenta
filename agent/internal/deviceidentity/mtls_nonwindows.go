//go:build !windows

package deviceidentity

import (
	"context"
	"crypto/tls"
	"fmt"
)

func LoadMachineTLSCertificate(context.Context, MachineCertificateOptions) (tls.Certificate, error) {
	return tls.Certificate{}, fmt.Errorf("Machine Store mTLS credentials are only supported on Windows")
}
