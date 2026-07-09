package devicedata

import (
	"context"

	"agent/internal/ipc"
)

type Report = ipc.DeviceDataReport
type Check = ipc.DeviceDataCheck

const (
	StatusGood        = ipc.DeviceDataStatusGood
	StatusWarning     = ipc.DeviceDataStatusWarning
	StatusCritical    = ipc.DeviceDataStatusCritical
	StatusUnavailable = ipc.DeviceDataStatusUnavailable
)

type Collector interface {
	Collect(context.Context, string) (Report, error)
}

type Watcher interface {
	Watch(context.Context, chan<- string) error
}
