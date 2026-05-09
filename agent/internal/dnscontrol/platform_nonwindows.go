//go:build !windows

package dnscontrol

import "context"

func applyPlatform(context.Context, Config) error {
	return nil
}
