//go:build !windows

package devicedata

import (
	"context"
	"log/slog"
)

type defaultWatcher struct{}

func NewDefaultWatcher(_ *slog.Logger) Watcher {
	return defaultWatcher{}
}

func (watcher defaultWatcher) Watch(ctx context.Context, _ chan<- string) error {
	if ctx == nil {
		return nil
	}
	<-ctx.Done()
	return nil
}
