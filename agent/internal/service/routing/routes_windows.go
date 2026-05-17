//go:build windows

package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

func Apply(ctx context.Context, config Config) (RouteSet, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := NormalizeConfig(config)
	if err != nil {
		return nil, err
	}
	destination, mask, err := RouteParts(normalized.DestinationCIDR)
	if err != nil {
		return nil, err
	}
	_ = exec.CommandContext(ctx, "route", "delete", destination).Run()
	ifIndex, err := waitForInterfaceIndex(ctx, normalized.InterfaceIP, 20, 250*time.Millisecond)
	if err != nil {
		return nil, err
	}
	route := Route{Destination: destination, Mask: mask, Gateway: "0.0.0.0", InterfaceIP: normalized.InterfaceIP, Metric: normalized.Metric}
	args := []string{"add", route.Destination, "mask", route.Mask, route.Gateway, "metric", fmt.Sprintf("%d", route.Metric), "IF", ifIndex}
	cmd := exec.CommandContext(ctx, "route", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("add route %s/%s: %s: %w", route.Destination, route.Mask, strings.TrimSpace(string(output)), err)
	}
	return &Table{routes: []Route{route}}, nil
}

func (table *Table) Close() error {
	if table == nil {
		return nil
	}
	var errs []error
	for _, route := range table.routes {
		cmd := exec.Command("route", "delete", route.Destination)
		if output, err := cmd.CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %s: %w", route.Destination, strings.TrimSpace(string(output)), err))
		}
	}
	table.routes = nil
	return errors.Join(errs...)
}

func waitForInterfaceIndex(ctx context.Context, ip string, attempts int, pause time.Duration) (string, error) {
	for i := 0; i < attempts; i++ {
		ifIndex := findInterfaceIndex(ip)
		if ifIndex != "" {
			return ifIndex, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pause):
		}
	}
	return "", fmt.Errorf("TUN interface index not found for %s", ip)
}

func findInterfaceIndex(ip string) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ipNet, ok := address.(*net.IPNet)
			if ok && ipNet.IP.To4() != nil && ipNet.IP.String() == ip {
				return fmt.Sprintf("%d", iface.Index)
			}
		}
	}
	return ""
}
