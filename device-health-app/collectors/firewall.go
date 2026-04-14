//go:build windows

package collectors

import (
	"context"
	"os/exec"
	"strings"
)

// FirewallStatus holds the state of each firewall profile
type FirewallStatus struct {
	DomainProfile  bool
	PrivateProfile bool
	PublicProfile  bool
	AllEnabled     bool
}

// CollectFirewallStatus checks Windows Firewall for all profiles
func CollectFirewallStatus() FirewallStatus {
	status := FirewallStatus{}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "netsh", "advfirewall", "show", "allprofiles", "state").Output()
	if err != nil {
		return status
	}

	output := string(out)
	lines := strings.Split(output, "\n")

	profileIndex := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "State") && strings.Contains(line, "ON") {
			switch profileIndex {
			case 0:
				status.DomainProfile = true
			case 1:
				status.PrivateProfile = true
			case 2:
				status.PublicProfile = true
			}
			profileIndex++
		} else if strings.Contains(line, "State") && strings.Contains(line, "OFF") {
			profileIndex++
		}
	}

	status.AllEnabled = status.DomainProfile && status.PrivateProfile && status.PublicProfile
	return status
}
