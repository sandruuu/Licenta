package deviceposture

import (
	"context"
	"crypto/tls"

	"ztna.local/agent/internal/ipc"
)

type ClientCertificateProvider func(context.Context, ipc.DevicePostureReport) (tls.Certificate, error)
