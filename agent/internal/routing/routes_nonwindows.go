//go:build !windows

package routing

import (
	"context"
	"fmt"
)

func Apply(context.Context, Config) (RouteSet, error) {
	return nil, fmt.Errorf("Windows route table management is only supported on Windows")
}

func (table *Table) Close() error {
	return nil
}
