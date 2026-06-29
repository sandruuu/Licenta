//go:build windows

package devicedata

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

type defaultWatcher struct {
	logger *slog.Logger
}

func NewDefaultWatcher(logger *slog.Logger) Watcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &defaultWatcher{logger: logger}
}

func (watcher *defaultWatcher) Watch(ctx context.Context, triggers chan<- string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", watcherScript)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		reason := normalizeWatchReason(scanner.Text())
		if reason == "" {
			continue
		}
		select {
		case triggers <- reason:
		default:
			if watcher != nil && watcher.logger != nil {
				watcher.logger.Debug("Device data trigger dropped because sync queue is full", "reason", reason)
			}
		}
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return fmt.Errorf("%w: %s", waitErr, message)
		}
		return waitErr
	}
	return nil
}

func normalizeWatchReason(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.TrimPrefix(value, "trustagent-")
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return strings.ToLower(value)
}

const watcherScript = `
$ErrorActionPreference = 'SilentlyContinue'

function Register-TrustAgentEvent($Id, $Namespace, $Query) {
  try {
    Register-WmiEvent -Namespace $Namespace -Query $Query -SourceIdentifier $Id | Out-Null
  } catch {
    Write-Output ("trustagent-watcher_error_" + $Id)
  }
}

Register-TrustAgentEvent "trustagent-windows_updates_service" "root/cimv2" "SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'wuauserv' AND TargetInstance.State <> PreviousInstance.State"
Register-TrustAgentEvent "trustagent-firewall_service" "root/cimv2" "SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'mpssvc' AND TargetInstance.State <> PreviousInstance.State"
Register-TrustAgentEvent "trustagent-antivirus_service" "root/cimv2" "SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'WinDefend' AND TargetInstance.State <> PreviousInstance.State"
Register-TrustAgentEvent "trustagent-antivirus_product" "root/SecurityCenter2" "SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'AntiVirusProduct' AND TargetInstance.productState <> PreviousInstance.productState"
Register-TrustAgentEvent "trustagent-firewall_policy" "root/default" "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy'"
Register-TrustAgentEvent "trustagent-bitlocker_policy" "root/default" "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='SYSTEM\\CurrentControlSet\\Control\\BitLocker'"
Register-TrustAgentEvent "trustagent-antivirus_policy" "root/default" "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='SOFTWARE\\Microsoft\\Windows Defender'"
Register-TrustAgentEvent "trustagent-password_lock_policy" "root/default" "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies'"
Register-TrustAgentEvent "trustagent-windows_updates_reboot_required" "root/default" "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update'"

while ($true) {
  $event = Wait-Event -Timeout 60
  if ($null -ne $event) {
    Write-Output $event.SourceIdentifier
    Remove-Event -EventIdentifier $event.EventIdentifier
  }
}
`
