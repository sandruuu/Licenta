//go:build windows

package deviceposture

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"licenta/features/contracts"
)

const (
	commandTimeout            = 15 * time.Second
	connectivityProbeTimeout  = 4 * time.Second
	connectivityProbeEndpoint = "www.msftconnecttest.com"
)

var validUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

type firewallStatus struct {
	DomainProfile  bool
	PrivateProfile bool
	PublicProfile  bool
	AllEnabled     bool
}

type antivirusInfo struct {
	ProductName string
	Enabled     bool
	UpToDate    bool
	Found       bool
}

type diskEncryptionInfo struct {
	ProtectionStatus string
	EncryptionMethod string
	VolumeStatus     string
	IsEncrypted      bool
}

type passwordInfo struct {
	PasswordSet       bool
	ScreenLockSet     bool
	LockTimeout       string
	UnavailableReason string
}

type osInfo struct {
	Name         string
	Version      string
	Build        string
	Architecture string
	Uptime       string
}

type updateInfo struct {
	PendingUpdates  string
	LastHotFix      string
	LastInstalledOn string
	QueryError      string
}

type connectivityInfo struct {
	DNSOK       bool
	TCPOK       bool
	Target      string
	ResolvedIPs []string
	LastError   string
}

func platformCheckDefinitions() []checkDefinition {
	return []checkDefinition{
		{Name: "Operating System", Build: buildOSCheck},
		{Name: "Firewall", Build: buildFirewallCheck},
		{Name: "Antivirus", Build: buildAntivirusCheck},
		{Name: "Disk Encryption", Build: buildDiskEncryptionCheck},
		{Name: "Windows Updates", Build: buildWindowsUpdateCheck},
		{Name: "Connectivity", Build: buildConnectivityCheck},
		{Name: "Password & Lock", Build: buildPasswordCheck},
	}
}

func buildOSCheck(ctx context.Context) (contracts.DevicePostureCheck, string) {
	info := collectOSInfo(ctx)
	if strings.TrimSpace(info.Name) == "" {
		info.Name = "Windows"
	}
	return contracts.DevicePostureCheck{
		Name:        "Operating System",
		Status:      contracts.DevicePostureStatusGood,
		Description: info.Name,
		Details: map[string]string{
			"Version":      info.Version,
			"Build":        info.Build,
			"Architecture": info.Architecture,
			"Uptime":       info.Uptime,
		},
	}, info.Name
}

func buildFirewallCheck(ctx context.Context) (contracts.DevicePostureCheck, string) {
	status := collectFirewallStatus(ctx)
	check := contracts.DevicePostureCheck{
		Name: "Firewall",
		Details: map[string]string{
			"Domain Profile":  boolToOnOff(status.DomainProfile),
			"Private Profile": boolToOnOff(status.PrivateProfile),
			"Public Profile":  boolToOnOff(status.PublicProfile),
		},
	}
	if status.AllEnabled {
		check.Status = contracts.DevicePostureStatusGood
		check.Description = "All firewall profiles are active"
	} else if status.DomainProfile || status.PrivateProfile || status.PublicProfile {
		check.Status = contracts.DevicePostureStatusWarning
		check.Description = "Some firewall profiles are disabled"
	} else {
		check.Status = contracts.DevicePostureStatusCritical
		check.Description = "Firewall is completely disabled"
	}
	return check, ""
}

func buildAntivirusCheck(ctx context.Context) (contracts.DevicePostureCheck, string) {
	info := collectAntivirusInfo(ctx)
	check := contracts.DevicePostureCheck{Name: "Antivirus", Details: map[string]string{}}
	if !info.Found {
		check.Status = contracts.DevicePostureStatusCritical
		check.Description = "No antivirus product detected"
		return check, ""
	}
	check.Details["Product"] = info.ProductName
	check.Details["Real-time Protection"] = boolToOnOff(info.Enabled)
	check.Details["Definitions"] = boolToStatus(info.UpToDate, "Up to date", "Out of date")
	if info.Enabled && info.UpToDate {
		check.Status = contracts.DevicePostureStatusGood
		check.Description = info.ProductName + " is active and up to date"
	} else if info.Enabled {
		check.Status = contracts.DevicePostureStatusWarning
		check.Description = info.ProductName + " definitions may be outdated"
	} else {
		check.Status = contracts.DevicePostureStatusCritical
		check.Description = info.ProductName + " real-time protection is disabled"
	}
	return check, ""
}

func buildDiskEncryptionCheck(ctx context.Context) (contracts.DevicePostureCheck, string) {
	info := collectDiskEncryption(ctx)
	check := contracts.DevicePostureCheck{
		Name: "Disk Encryption",
		Details: map[string]string{
			"Protection":        info.ProtectionStatus,
			"Encryption Method": info.EncryptionMethod,
			"Volume Status":     info.VolumeStatus,
		},
	}
	if info.IsEncrypted {
		check.Status = contracts.DevicePostureStatusGood
		check.Description = "BitLocker protection is active on C:"
	} else if info.ProtectionStatus == "Unknown" {
		check.Status = contracts.DevicePostureStatusUnavailable
		check.Description = "Unable to determine encryption status"
	} else {
		check.Status = contracts.DevicePostureStatusCritical
		check.Description = "System drive is not encrypted"
	}
	return check, ""
}

func buildPasswordCheck(ctx context.Context) (contracts.DevicePostureCheck, string) {
	info := collectPasswordInfo(ctx)
	check := contracts.DevicePostureCheck{
		Name: "Password & Lock",
		Details: map[string]string{
			"Password Set": boolToYesNo(info.PasswordSet),
			"Screen Lock":  boolToYesNo(info.ScreenLockSet),
			"Lock Timeout": info.LockTimeout,
		},
	}
	if info.UnavailableReason != "" {
		check.Status = contracts.DevicePostureStatusUnavailable
		check.Description = "User password and screen-lock posture is unavailable from the current service context"
		check.Details["Reason"] = info.UnavailableReason
		return check, ""
	}
	if info.PasswordSet && info.ScreenLockSet {
		check.Status = contracts.DevicePostureStatusGood
		check.Description = "Password is set and screen lock is enabled"
	} else if info.PasswordSet {
		check.Status = contracts.DevicePostureStatusWarning
		check.Description = "Password is set but screen lock may not be configured"
	} else {
		check.Status = contracts.DevicePostureStatusCritical
		check.Description = "No password set for this account"
	}
	return check, ""
}

func buildWindowsUpdateCheck(ctx context.Context) (contracts.DevicePostureCheck, string) {
	info := collectWindowsUpdateInfo(ctx)
	check := contracts.DevicePostureCheck{
		Name: "Windows Updates",
		Details: map[string]string{
			"Pending Updates":   info.PendingUpdates,
			"Last HotFix":       info.LastHotFix,
			"Last Installed On": info.LastInstalledOn,
		},
	}
	if info.QueryError != "" {
		check.Status = contracts.DevicePostureStatusUnavailable
		check.Description = "Windows Update state could not be queried from the service context"
		check.Details["Reason"] = info.QueryError
		return check, ""
	}
	pending, err := strconv.Atoi(strings.TrimSpace(info.PendingUpdates))
	if err != nil {
		check.Status = contracts.DevicePostureStatusUnavailable
		check.Description = "Windows Update pending count is unavailable"
		return check, ""
	}
	if pending == 0 {
		check.Status = contracts.DevicePostureStatusGood
		check.Description = "No pending software updates were reported"
		return check, ""
	}
	check.Status = contracts.DevicePostureStatusWarning
	check.Description = fmt.Sprintf("%d pending software updates reported", pending)
	return check, ""
}

func buildConnectivityCheck(ctx context.Context) (contracts.DevicePostureCheck, string) {
	info := collectConnectivityInfo(ctx)
	check := contracts.DevicePostureCheck{
		Name: "Connectivity",
		Details: map[string]string{
			"Target":       info.Target,
			"DNS":          boolToStatus(info.DNSOK, "OK", "Failed"),
			"TCP":          boolToStatus(info.TCPOK, "OK", "Failed"),
			"Resolved IPs": strings.Join(info.ResolvedIPs, ", "),
		},
	}
	if info.LastError != "" {
		check.Details["Reason"] = info.LastError
	}
	if info.DNSOK && info.TCPOK {
		check.Status = contracts.DevicePostureStatusGood
		check.Description = "DNS and outbound TCP connectivity are available"
	} else if info.DNSOK {
		check.Status = contracts.DevicePostureStatusWarning
		check.Description = "DNS works but outbound TCP connectivity could not be verified"
	} else {
		check.Status = contracts.DevicePostureStatusUnavailable
		check.Description = "Connectivity check could not resolve the test endpoint"
	}
	return check, ""
}

func collectOSInfo(ctx context.Context) osInfo {
	info := osInfo{Architecture: runtime.GOARCH}
	output, err := powerShellOutput(ctx, "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List")
	if err == nil {
		values := parseKeyValueOutput(output)
		info.Name = values["Caption"]
		info.Version = values["Version"]
		info.Build = values["BuildNumber"]
	}
	switch runtime.GOARCH {
	case "amd64":
		info.Architecture = "x64 (64-bit)"
	case "386":
		info.Architecture = "x86 (32-bit)"
	case "arm64":
		info.Architecture = "ARM64"
	default:
		info.Architecture = runtime.GOARCH
	}
	uptimeOutput, err := powerShellOutput(ctx, "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime")
	if err != nil {
		return info
	}
	bootTime := strings.TrimSpace(string(uptimeOutput))
	for _, layout := range []string{"Monday, January 2, 2006 3:04:05 PM", "1/2/2006 3:04:05 PM", "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, bootTime)
		if err != nil {
			continue
		}
		uptime := time.Since(parsed)
		days := int(uptime.Hours()) / 24
		hours := int(uptime.Hours()) % 24
		minutes := int(uptime.Minutes()) % 60
		if days > 0 {
			info.Uptime = fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
		} else {
			info.Uptime = fmt.Sprintf("%dh %dm", hours, minutes)
		}
		break
	}
	if info.Uptime == "" {
		info.Uptime = "N/A"
	}
	return info
}

func collectFirewallStatus(ctx context.Context) firewallStatus {
	status := firewallStatus{}
	output, err := commandOutput(ctx, "netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		return status
	}
	profileIndex := 0
	for _, line := range strings.Split(string(output), "\n") {
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

func collectAntivirusInfo(ctx context.Context) antivirusInfo {
	info := antivirusInfo{}
	output, err := powerShellOutput(ctx, `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | Format-List`)
	if err != nil || strings.TrimSpace(string(output)) == "" {
		return info
	}
	info.Found = true
	values := parseKeyValueOutput(output)
	info.ProductName = values["displayName"]
	if productState := values["productState"]; productState != "" {
		info.Enabled, info.UpToDate = parseProductState(productState)
	}
	return info
}

func collectDiskEncryption(ctx context.Context) diskEncryptionInfo {
	info := diskEncryptionInfo{ProtectionStatus: "Unknown"}
	output, err := powerShellOutput(ctx, `Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue | Select-Object ProtectionStatus, VolumeStatus, EncryptionMethod | Format-List`)
	if err == nil && strings.TrimSpace(string(output)) != "" {
		values := parseKeyValueOutput(output)
		if value := values["ProtectionStatus"]; value != "" {
			info.ProtectionStatus = value
			info.IsEncrypted = strings.Contains(strings.ToLower(value), "on") || value == "1"
		}
		info.VolumeStatus = values["VolumeStatus"]
		info.EncryptionMethod = values["EncryptionMethod"]
		return info
	}
	output, err = commandOutput(ctx, "manage-bde", "-status", "C:")
	if err != nil {
		return info
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Protection Status") {
			value := extractAfterColon(line)
			info.ProtectionStatus = value
			info.IsEncrypted = strings.Contains(strings.ToLower(value), "on")
		} else if strings.Contains(line, "Encryption Method") {
			info.EncryptionMethod = extractAfterColon(line)
		} else if strings.Contains(line, "Conversion Status") {
			info.VolumeStatus = extractAfterColon(line)
		}
	}
	return info
}

func collectPasswordInfo(ctx context.Context) passwordInfo {
	info := passwordInfo{}
	username := strings.TrimSpace(os.Getenv("USERNAME"))
	if username == "" || strings.EqualFold(username, "SYSTEM") || !validUsername.MatchString(username) {
		info.UnavailableReason = "no interactive user profile is available to the service process"
		return info
	}
	output, err := commandOutput(ctx, "net", "user", username)
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Password last set") {
				value := extractAfterMultiSpace(line)
				if !strings.Contains(strings.ToLower(value), "never") {
					info.PasswordSet = true
				}
			}
		}
	}
	lockOutput, err := powerShellOutput(ctx, `powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 2>$null`)
	if err == nil {
		for _, line := range strings.Split(string(lockOutput), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Current AC Power Setting Index") || strings.Contains(line, "Current DC Power Setting Index") {
				value := strings.TrimSpace(extractAfterColon(line))
				if value != "" && value != "0x00000000" {
					info.ScreenLockSet = true
					info.LockTimeout = parseHexSeconds(value)
				}
			}
		}
	}
	if info.ScreenLockSet {
		return info
	}
	secureOutput, err := powerShellOutput(ctx, `Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ScreenSaverIsSecure`)
	if err != nil || strings.TrimSpace(string(secureOutput)) != "1" {
		return info
	}
	info.ScreenLockSet = true
	timeoutOutput, err := powerShellOutput(ctx, `Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ScreenSaveTimeOut`)
	if err == nil {
		info.LockTimeout = strings.TrimSpace(string(timeoutOutput)) + " seconds"
	}
	return info
}

func collectWindowsUpdateInfo(ctx context.Context) updateInfo {
	script := `$ErrorActionPreference = 'Stop';
$pending = 'Unknown';
try {
  $session = New-Object -ComObject Microsoft.Update.Session;
  $searcher = $session.CreateUpdateSearcher();
  $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0");
  $pending = [string]$result.Updates.Count;
} catch {
  $pending = 'Unknown';
}
$hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1;
Write-Output ("PendingUpdates: " + $pending);
if ($hotfix) {
  Write-Output ("LastHotFix: " + $hotfix.HotFixID);
  Write-Output ("LastInstalledOn: " + $hotfix.InstalledOn);
}`
	info := updateInfo{}
	output, err := powerShellOutput(ctx, script)
	if err != nil {
		info.QueryError = err.Error()
		return info
	}
	values := parseKeyValueOutput(output)
	info.PendingUpdates = values["PendingUpdates"]
	info.LastHotFix = values["LastHotFix"]
	info.LastInstalledOn = values["LastInstalledOn"]
	if info.PendingUpdates == "" || strings.EqualFold(info.PendingUpdates, "Unknown") {
		info.QueryError = "pending update count is unknown"
	}
	return info
}

func collectConnectivityInfo(ctx context.Context) connectivityInfo {
	info := connectivityInfo{Target: connectivityProbeEndpoint + ":80"}
	lookupCtx, cancelLookup := context.WithTimeout(ctx, connectivityProbeTimeout)
	addresses, err := net.DefaultResolver.LookupHost(lookupCtx, connectivityProbeEndpoint)
	cancelLookup()
	if err != nil {
		info.LastError = err.Error()
		return info
	}
	info.DNSOK = true
	info.ResolvedIPs = addresses
	dialCtx, cancelDial := context.WithTimeout(ctx, connectivityProbeTimeout)
	connection, err := (&net.Dialer{Timeout: connectivityProbeTimeout}).DialContext(dialCtx, "tcp", info.Target)
	cancelDial()
	if err != nil {
		info.LastError = err.Error()
		return info
	}
	_ = connection.Close()
	info.TCPOK = true
	return info
}

func commandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	commandContext, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	return exec.CommandContext(commandContext, name, args...).Output()
}

func powerShellOutput(ctx context.Context, script string) ([]byte, error) {
	return commandOutput(ctx, "powershell", "-NoProfile", "-Command", script)
}

func parseKeyValueOutput(output []byte) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		key, value := splitKeyValue(line)
		if key != "" {
			values[key] = value
		}
	}
	return values
}

func splitKeyValue(line string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func parseProductState(stateText string) (bool, bool) {
	state := 0
	for _, character := range strings.TrimSpace(stateText) {
		if character >= '0' && character <= '9' {
			state = state*10 + int(character-'0')
		}
	}
	if state == 0 {
		return false, false
	}
	return state&0x1000 != 0, state&0x10 == 0
}

func extractAfterColon(line string) string {
	_, value := splitKeyValue(line)
	if value == "" {
		return ""
	}
	return value
}

func extractAfterMultiSpace(line string) string {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return ""
	}
	return strings.Join(parts[3:], " ")
}

func parseHexSeconds(hexValue string) string {
	hexValue = strings.TrimPrefix(strings.TrimSpace(hexValue), "0x")
	seconds, err := strconv.ParseInt(hexValue, 16, 64)
	if err != nil {
		return ""
	}
	if seconds >= 3600 {
		hours := seconds / 3600
		minutes := (seconds % 3600) / 60
		if minutes > 0 {
			return fmt.Sprintf("%dh %dm", hours, minutes)
		}
		return fmt.Sprintf("%dh", hours)
	}
	if seconds >= 60 {
		minutes := seconds / 60
		if minutes == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}
	return fmt.Sprintf("%d seconds", seconds)
}
