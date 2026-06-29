//go:build windows

package devicedata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	commandTimeout          = 20 * time.Second
	stableDeviceCheckTTL    = 5 * time.Minute
	unavailableCheckGrace   = 2 * time.Minute
	deviceCheckWarningField = "LastCollectionWarning"
)

type defaultCollector struct {
	logger *slog.Logger
	mu     sync.Mutex
	cache  map[string]cachedDeviceCheck
}

type cachedDeviceCheck struct {
	check       Check
	collectedAt time.Time
}

func NewDefaultCollector(logger *slog.Logger) Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &defaultCollector{logger: logger, cache: map[string]cachedDeviceCheck{}}
}

func (collector *defaultCollector) Collect(ctx context.Context, deviceID string) (Report, error) {
	hostname, _ := os.Hostname()
	osCheck := collector.cachedCheck(ctx, "Operating System", stableDeviceCheckTTL, func(ctx context.Context) Check {
		osInfo, osErr := collectWindowsOSInfo(ctx)
		osName := strings.TrimSpace(stringFromMap(osInfo, "Caption"))
		if osName == "" {
			osName = runtime.GOOS
		}
		return operatingSystemCheck(osName, osInfo, osErr)
	})
	osName := runtime.GOOS
	if osCheck.Status != StatusUnavailable && strings.TrimSpace(osCheck.Description) != "" {
		osName = strings.TrimSpace(osCheck.Description)
	}
	report := Report{
		DeviceID:    strings.TrimSpace(deviceID),
		Hostname:    strings.TrimSpace(hostname),
		OS:          osName,
		CollectedAt: time.Now().UTC(),
	}
	report.Checks = []Check{
		osCheck,
		collector.cachedCheck(ctx, "Windows Updates", stableDeviceCheckTTL, windowsUpdatesCheck),
		collector.cachedCheck(ctx, "Password & Lock", stableDeviceCheckTTL, passwordLockCheck),
		collector.cachedCheck(ctx, "Disk Encryption", stableDeviceCheckTTL, diskEncryptionCheck),
		collector.transientAwareCheck(ctx, "Firewall", firewallCheck),
		collector.transientAwareCheck(ctx, "Antivirus", antivirusCheck),
	}
	return report, nil
}

func (collector *defaultCollector) cachedCheck(ctx context.Context, name string, ttl time.Duration, collect func(context.Context) Check) Check {
	name = strings.TrimSpace(name)
	now := time.Now().UTC()
	collector.mu.Lock()
	if cached, ok := collector.cache[name]; ok && ttl > 0 && now.Sub(cached.collectedAt) < ttl {
		collector.mu.Unlock()
		return cloneCheck(cached.check)
	}
	collector.mu.Unlock()

	check, fallback := collector.stabilizeCheck(name, collect(ctx), now)
	if !fallback {
		collector.mu.Lock()
		if collector.cache == nil {
			collector.cache = map[string]cachedDeviceCheck{}
		}
		collector.cache[name] = cachedDeviceCheck{check: cloneCheck(check), collectedAt: now}
		collector.mu.Unlock()
	}
	return check
}

func (collector *defaultCollector) transientAwareCheck(ctx context.Context, name string, collect func(context.Context) Check) Check {
	name = strings.TrimSpace(name)
	now := time.Now().UTC()
	check := collect(ctx)
	check, fallback := collector.stabilizeCheck(name, check, now)
	if !fallback {
		collector.mu.Lock()
		if collector.cache == nil {
			collector.cache = map[string]cachedDeviceCheck{}
		}
		collector.cache[name] = cachedDeviceCheck{check: cloneCheck(check), collectedAt: now}
		collector.mu.Unlock()
	}
	return check
}

func (collector *defaultCollector) stabilizeCheck(name string, check Check, now time.Time) (Check, bool) {
	if collector == nil || normalizeCheckStatus(check.Status) != StatusUnavailable {
		return check, false
	}
	collector.mu.Lock()
	cached, ok := collector.cache[name]
	collector.mu.Unlock()
	if !ok || normalizeCheckStatus(cached.check.Status) == StatusUnavailable || now.Sub(cached.collectedAt) > unavailableCheckGrace {
		return check, false
	}
	stable := cloneCheck(cached.check)
	if stable.Details == nil {
		stable.Details = map[string]string{}
	}
	warning := strings.TrimSpace(check.Description)
	if reason := strings.TrimSpace(check.Details["Reason"]); reason != "" {
		warning = firstNonEmptyString(warning, reason)
	}
	if warning != "" {
		stable.Details[deviceCheckWarningField] = warning
	}
	return stable, true
}

func cloneCheck(check Check) Check {
	clone := check
	if check.Details != nil {
		clone.Details = make(map[string]string, len(check.Details))
		for key, value := range check.Details {
			clone.Details[key] = value
		}
	}
	return clone
}

func normalizeCheckStatus(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func collectWindowsOSInfo(ctx context.Context) (map[string]any, error) {
	return runPowerShellJSONMap(ctx, `
$os = Get-CimInstance -ClassName Win32_OperatingSystem
[pscustomobject]@{
  Caption = [string]$os.Caption
  Version = [string]$os.Version
  BuildNumber = [string]$os.BuildNumber
  Architecture = [string]$os.OSArchitecture
  ProductType = [string]$os.ProductType
  InstallDate = [string]$os.InstallDate
  LastBootUpTime = [string]$os.LastBootUpTime
} | ConvertTo-Json -Compress
`)
}

func operatingSystemCheck(osName string, info map[string]any, err error) Check {
	if err != nil {
		return unavailableCheck("Operating System", "Operating system details are unavailable", err)
	}
	details := detailsFromMap(info, "Version", "BuildNumber", "Architecture", "ProductType", "InstallDate", "LastBootUpTime")
	if strings.Contains(strings.ToLower(osName), "windows") {
		return Check{
			Name:        "Operating System",
			Status:      StatusGood,
			Description: osName,
			Details:     details,
		}
	}
	return Check{
		Name:        "Operating System",
		Status:      StatusWarning,
		Description: osName,
		Details:     details,
	}
}

func windowsUpdatesCheck(ctx context.Context) Check {
	info, err := runPowerShellJSONMap(ctx, `
$service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
$missingUpdateCount = $null
$searchError = $null
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
  $missingUpdateCount = @($result.Updates).Count
} catch {
  $searchError = $_.Exception.Message
}
$rebootPending = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -or
  (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -or
  (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations")
[pscustomobject]@{
  ServiceStatus = if ($service) { [string]$service.Status } else { "" }
  MissingUpdateCount = $missingUpdateCount
  RebootPending = [bool]$rebootPending
  SearchError = $searchError
} | ConvertTo-Json -Compress
`)
	if err != nil {
		return unavailableCheck("Windows Updates", "Windows Update status is unavailable", err)
	}
	details := detailsFromMap(info, "ServiceStatus", "MissingUpdateCount", "RebootPending", "SearchError")
	serviceStatus := stringFromMap(info, "ServiceStatus")
	missingUpdates, hasMissingUpdates := intFromMap(info, "MissingUpdateCount")
	rebootPending := boolFromMap(info, "RebootPending")
	searchError := stringFromMap(info, "SearchError")

	if searchError != "" && !hasMissingUpdates {
		return Check{
			Name:        "Windows Updates",
			Status:      StatusUnavailable,
			Description: "Windows Update Agent search is unavailable",
			Details:     details,
		}
	}
	if !strings.EqualFold(serviceStatus, "Running") {
		return Check{
			Name:        "Windows Updates",
			Status:      StatusWarning,
			Description: "Windows Update service is " + serviceStatus,
			Details:     details,
		}
	}
	if rebootPending {
		return Check{
			Name:        "Windows Updates",
			Status:      StatusWarning,
			Description: "Windows updates require a reboot",
			Details:     details,
		}
	}
	if missingUpdates > 0 {
		return Check{
			Name:        "Windows Updates",
			Status:      StatusWarning,
			Description: fmt.Sprintf("%d visible Windows updates are not installed", missingUpdates),
			Details:     details,
		}
	}
	return Check{
		Name:        "Windows Updates",
		Status:      StatusGood,
		Description: "Windows Update service is running and no visible updates are pending",
		Details:     details,
	}
}

func passwordLockCheck(ctx context.Context) Check {
	info, err := runPowerShellJSONMap(ctx, `
$temp = Join-Path $env:TEMP ("trustagent-secpol-" + [guid]::NewGuid().ToString() + ".cfg")
$values = @{}
try {
  secedit /export /cfg $temp /quiet | Out-Null
  if (Test-Path $temp) {
    Get-Content $temp | ForEach-Object {
      if ($_ -match "^\s*([^=]+?)\s*=\s*(.*?)\s*$") {
        $values[$matches[1].Trim()] = $matches[2].Trim()
      }
    }
  }
} finally {
  Remove-Item $temp -Force -ErrorAction SilentlyContinue
}
$inactivity = $null
try {
  $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
  if ($policy -and $null -ne $policy.InactivityTimeoutSecs) { $inactivity = [int]$policy.InactivityTimeoutSecs }
} catch {}
[pscustomobject]@{
  MinimumPasswordLength = if ($values.ContainsKey("MinimumPasswordLength")) { [int]$values["MinimumPasswordLength"] } else { $null }
  PasswordComplexity = if ($values.ContainsKey("PasswordComplexity")) { [int]$values["PasswordComplexity"] } else { $null }
  LockoutBadCount = if ($values.ContainsKey("LockoutBadCount")) { [int]$values["LockoutBadCount"] } else { $null }
  LockoutDuration = if ($values.ContainsKey("LockoutDuration")) { [int]$values["LockoutDuration"] } else { $null }
  MaximumPasswordAge = if ($values.ContainsKey("MaximumPasswordAge")) { [int]$values["MaximumPasswordAge"] } else { $null }
  InactivityTimeoutSeconds = $inactivity
} | ConvertTo-Json -Compress
`)
	if err != nil {
		return unavailableCheck("Password & Lock", "Password and lock policy is unavailable", err)
	}
	details := detailsFromMap(info, "MinimumPasswordLength", "PasswordComplexity", "LockoutBadCount", "LockoutDuration", "MaximumPasswordAge", "InactivityTimeoutSeconds")
	minLength, hasMinLength := intFromMap(info, "MinimumPasswordLength")
	complexity, hasComplexity := intFromMap(info, "PasswordComplexity")
	lockoutBadCount, hasLockoutBadCount := intFromMap(info, "LockoutBadCount")
	inactivityTimeout, hasInactivityTimeout := intFromMap(info, "InactivityTimeoutSeconds")
	if !hasMinLength && !hasComplexity && !hasLockoutBadCount && !hasInactivityTimeout {
		return Check{
			Name:        "Password & Lock",
			Status:      StatusUnavailable,
			Description: "Password and lock policy was not reported by Windows",
			Details:     details,
		}
	}
	weakReasons := []string{}
	if !hasMinLength || minLength < 8 {
		weakReasons = append(weakReasons, "minimum password length is below 8")
	}
	if !hasComplexity || complexity != 1 {
		weakReasons = append(weakReasons, "password complexity is not enabled")
	}
	if !hasLockoutBadCount || lockoutBadCount <= 0 || lockoutBadCount > 10 {
		weakReasons = append(weakReasons, "account lockout threshold is not enforced tightly")
	}
	if hasInactivityTimeout && (inactivityTimeout <= 0 || inactivityTimeout > 900) {
		weakReasons = append(weakReasons, "machine inactivity lock is not enforced within 15 minutes")
	}
	if len(weakReasons) > 0 {
		return Check{
			Name:        "Password & Lock",
			Status:      StatusWarning,
			Description: strings.Join(weakReasons, "; "),
			Details:     details,
		}
	}
	return Check{
		Name:        "Password & Lock",
		Status:      StatusGood,
		Description: "Password complexity, account lockout and inactivity lock policies are enforced",
		Details:     details,
	}
}

func diskEncryptionCheck(ctx context.Context) Check {
	info, err := runPowerShellJSONMap(ctx, `
$mountPoint = $env:SystemDrive
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
  $volume = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
  [pscustomobject]@{
    MountPoint = [string]$volume.MountPoint
    ProtectionStatus = [string]$volume.ProtectionStatus
    VolumeStatus = [string]$volume.VolumeStatus
    EncryptionPercentage = [int]$volume.EncryptionPercentage
    EncryptionMethod = [string]$volume.EncryptionMethod
    LockStatus = [string]$volume.LockStatus
  } | ConvertTo-Json -Compress
} else {
  $volume = Get-CimInstance -Namespace "root/CIMV2/Security/MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$mountPoint'" -ErrorAction Stop
  [pscustomobject]@{
    MountPoint = [string]$volume.DriveLetter
    ProtectionStatus = [string]$volume.ProtectionStatus
    VolumeStatus = [string]$volume.ConversionStatus
    EncryptionPercentage = [int]$volume.EncryptionPercentage
    EncryptionMethod = [string]$volume.EncryptionMethod
    LockStatus = ""
  } | ConvertTo-Json -Compress
}
`)
	if err != nil {
		return unavailableCheck("Disk Encryption", "Disk encryption status is unavailable", err)
	}
	details := detailsFromMap(info, "MountPoint", "ProtectionStatus", "VolumeStatus", "EncryptionPercentage", "EncryptionMethod", "LockStatus")
	protectionStatus := strings.ToLower(stringFromMap(info, "ProtectionStatus"))
	volumeStatus := strings.ToLower(stringFromMap(info, "VolumeStatus"))
	percentage, hasPercentage := intFromMap(info, "EncryptionPercentage")
	protected := protectionStatus == "on" || protectionStatus == "1"
	fullyEncrypted := strings.Contains(volumeStatus, "fullyencrypted") || strings.Contains(volumeStatus, "fully encrypted") || (hasPercentage && percentage >= 100)
	if protected && fullyEncrypted {
		return Check{Name: "Disk Encryption", Status: StatusGood, Description: "System drive is protected by BitLocker", Details: details}
	}
	if protected {
		return Check{Name: "Disk Encryption", Status: StatusWarning, Description: "Disk encryption protection is on but encryption is not complete", Details: details}
	}
	return Check{
		Name:        "Disk Encryption",
		Status:      StatusCritical,
		Description: "System drive BitLocker protection is off",
		Details:     details,
	}
}

func firewallCheck(ctx context.Context) Check {
	profiles, err := runPowerShellJSONList(ctx, `
$profiles = @()
try {
  $policy = New-Object -ComObject HNetCfg.FwPolicy2
  foreach ($profile in @(@{Name="Domain";Value=1}, @{Name="Private";Value=2}, @{Name="Public";Value=4})) {
    $profiles += [pscustomobject]@{
      Name = $profile.Name
      Enabled = [bool]$policy.FirewallEnabled($profile.Value)
      DefaultInboundAction = [string]$policy.DefaultInboundAction($profile.Value)
      DefaultOutboundAction = [string]$policy.DefaultOutboundAction($profile.Value)
    }
  }
} catch {
  $profiles = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
}
$profiles | ConvertTo-Json -Compress
`)
	if err != nil {
		return unavailableCheck("Firewall", "Firewall status is unavailable", err)
	}
	if len(profiles) == 0 {
		return unavailableCheck("Firewall", "Firewall status is unavailable", fmt.Errorf("no firewall profiles returned"))
	}
	details := make(map[string]string, len(profiles)*3)
	allEnabled := true
	for _, profile := range profiles {
		name := firstNonEmptyString(stringFromMap(profile, "Name"), "Unknown")
		enabled := boolFromMap(profile, "Enabled")
		details[name+"Enabled"] = strconv.FormatBool(enabled)
		if inbound := stringFromMap(profile, "DefaultInboundAction"); inbound != "" {
			details[name+"DefaultInboundAction"] = inbound
		}
		if outbound := stringFromMap(profile, "DefaultOutboundAction"); outbound != "" {
			details[name+"DefaultOutboundAction"] = outbound
		}
		if !enabled {
			allEnabled = false
		}
	}
	if allEnabled {
		return Check{
			Name:        "Firewall",
			Status:      StatusGood,
			Description: "Firewall is enabled for all profiles",
			Details:     details,
		}
	}
	return Check{
		Name:        "Firewall",
		Status:      StatusCritical,
		Description: "Firewall is disabled for one or more profiles",
		Details:     details,
	}
}

func antivirusCheck(ctx context.Context) Check {
	info, err := runPowerShellJSONMap(ctx, `
$products = @()
function Convert-ProductState($value) {
  $state = 0
  try { $state = [int]$value } catch {}
  $hex = ("{0:x6}" -f $state)
  $protectionCode = $hex.Substring(2, 2)
  $signatureCode = $hex.Substring(4, 2)
  $enabled = $protectionCode -in @("10", "11")
  $protectionState = switch ($protectionCode) {
    "00" { "Off" }
    "01" { "Expired" }
    "10" { "On" }
    "11" { "On" }
    default { "Unknown" }
  }
  $signatureState = switch ($signatureCode) {
    "00" { "UpToDate" }
    "10" { "OutOfDate" }
    default { "Unknown" }
  }
  [pscustomobject]@{
    Hex = $hex
    Enabled = [bool]$enabled
    ProtectionState = $protectionState
    SignaturesUpToDate = [bool]($signatureState -eq "UpToDate")
    SignatureState = $signatureState
  }
}
try {
  $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
    $state = Convert-ProductState $_.productState
    [pscustomobject]@{
      Provider = "Windows Security Center"
      ProductName = [string]$_.displayName
      ProductState = [string]$_.productState
      ProductStateHex = [string]$state.Hex
      SecurityCenterEnabled = [bool]$state.Enabled
      SecurityCenterState = [string]$state.ProtectionState
      SignaturesUpToDate = [bool]$state.SignaturesUpToDate
      SignatureState = [string]$state.SignatureState
      ProductExe = [string]$_.pathToSignedProductExe
      ReportingExe = [string]$_.pathToSignedReportingExe
    }
  })
} catch {}
$selected = $null
$thirdParty = @($products | Where-Object { $_.ProductName -and $_.ProductName -notmatch "(?i)(microsoft|defender)" })
if ($thirdParty.Count -gt 0) {
  $selected = $thirdParty | Sort-Object -Property @{Expression = { $_.SecurityCenterEnabled }; Descending = $true}, @{Expression = { $_.SignaturesUpToDate }; Descending = $true}, ProductName | Select-Object -First 1
} elseif ($products.Count -gt 0) {
  $selected = $products | Sort-Object -Property @{Expression = { $_.SecurityCenterEnabled }; Descending = $true}, @{Expression = { $_.SignaturesUpToDate }; Descending = $true}, ProductName | Select-Object -First 1
}
if ($selected) {
  [pscustomobject]@{
    Provider = [string]$selected.Provider
    ProductName = [string]$selected.ProductName
    ProductState = [string]$selected.ProductState
    ProductStateHex = [string]$selected.ProductStateHex
    SecurityCenterEnabled = [bool]$selected.SecurityCenterEnabled
    SecurityCenterState = [string]$selected.SecurityCenterState
    SignaturesUpToDate = [bool]$selected.SignaturesUpToDate
    SignatureState = [string]$selected.SignatureState
    ProductExe = [string]$selected.ProductExe
    ReportingExe = [string]$selected.ReportingExe
    ProductCount = [int]$products.Count
    Products = [string](($products | ForEach-Object { $_.ProductName }) -join "; ")
  } | ConvertTo-Json -Compress
} elseif (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
  $mp = Get-MpComputerStatus
  [pscustomobject]@{
    Provider = "Microsoft Defender"
    ProductName = "Microsoft Defender Antivirus"
    AntivirusEnabled = [bool]$mp.AntivirusEnabled
    RealTimeProtectionEnabled = [bool]$mp.RealTimeProtectionEnabled
    AMServiceEnabled = [bool]$mp.AMServiceEnabled
    AntispywareEnabled = [bool]$mp.AntispywareEnabled
    NISEnabled = [bool]$mp.NISEnabled
    SignatureAge = [int]$mp.AntivirusSignatureAge
    SignatureLastUpdated = [string]$mp.AntivirusSignatureLastUpdated
  } | ConvertTo-Json -Compress
} else {
  [pscustomobject]@{
    Provider = "Windows Security Center"
    ProductName = ""
    ProductState = ""
  } | ConvertTo-Json -Compress
}
`)
	return antivirusCheckFromInfo(info, err)
}

func antivirusCheckFromInfo(info map[string]any, err error) Check {
	if err != nil {
		return unavailableCheck("Antivirus", "Antivirus status is unavailable", err)
	}
	details := detailsFromMap(info, "Provider", "ProductName", "AntivirusEnabled", "RealTimeProtectionEnabled", "AMServiceEnabled", "AntispywareEnabled", "NISEnabled", "SignatureAge", "SignatureLastUpdated", "ProductState", "ProductStateHex", "SecurityCenterEnabled", "SecurityCenterState", "SignaturesUpToDate", "SignatureState", "ProductCount", "Products", "ProductExe", "ReportingExe")
	productName := stringFromMap(info, "ProductName")
	if productName == "" {
		return Check{Name: "Antivirus", Status: StatusUnavailable, Description: "Antivirus product was not detected", Details: details}
	}
	if strings.EqualFold(stringFromMap(info, "Provider"), "Microsoft Defender") {
		antivirusEnabled := boolFromMap(info, "AntivirusEnabled")
		realtimeEnabled := boolFromMap(info, "RealTimeProtectionEnabled")
		serviceEnabled := boolFromMap(info, "AMServiceEnabled")
		signatureAge, hasSignatureAge := intFromMap(info, "SignatureAge")
		if antivirusEnabled && realtimeEnabled && serviceEnabled && (!hasSignatureAge || signatureAge <= 7) {
			return Check{Name: "Antivirus", Status: StatusGood, Description: "Microsoft Defender real-time protection is enabled", Details: details}
		}
		return Check{Name: "Antivirus", Status: StatusWarning, Description: "Microsoft Defender is installed but protection is not fully healthy", Details: details}
	}
	if strings.EqualFold(stringFromMap(info, "Provider"), "Windows Security Center") {
		enabled := boolFromMap(info, "SecurityCenterEnabled")
		signaturesUpToDate := boolFromMap(info, "SignaturesUpToDate")
		signatureState := stringFromMap(info, "SignatureState")
		signatureKnown := signatureState != "" && !strings.EqualFold(signatureState, "Unknown")
		if enabled && (!signatureKnown || signaturesUpToDate) {
			return Check{Name: "Antivirus", Status: StatusGood, Description: productName + " is enabled", Details: details}
		}
		if !enabled {
			return Check{Name: "Antivirus", Status: StatusCritical, Description: productName + " is installed but protection is not enabled", Details: details}
		}
		return Check{Name: "Antivirus", Status: StatusWarning, Description: productName + " is enabled but signatures are not up to date", Details: details}
	}
	return Check{Name: "Antivirus", Status: StatusGood, Description: productName, Details: details}
}

func unavailableCheck(name, description string, err error) Check {
	details := map[string]string{}
	if err != nil {
		details["Reason"] = err.Error()
	}
	return Check{
		Name:        name,
		Status:      StatusUnavailable,
		Description: description,
		Details:     details,
	}
}

func runPowerShellJSONMap(ctx context.Context, script string) (map[string]any, error) {
	output, err := runPowerShell(ctx, script)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func runPowerShellJSONList(ctx context.Context, script string) ([]map[string]any, error) {
	output, err := runPowerShell(ctx, script)
	if err != nil {
		return nil, err
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, nil
	}
	var list []map[string]any
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &list); err != nil {
			return nil, err
		}
		return list, nil
	}
	var item map[string]any
	if err := json.Unmarshal([]byte(output), &item); err != nil {
		return nil, err
	}
	return []map[string]any{item}, nil
}

func runPowerShell(ctx context.Context, script string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if commandCtx.Err() != nil {
		return "", commandCtx.Err()
	}
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return "", fmt.Errorf("%w: %s", err, message)
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func detailsFromMap(values map[string]any, keys ...string) map[string]string {
	details := map[string]string{}
	for _, key := range keys {
		value := strings.TrimSpace(valueToString(values[key]))
		if value != "" {
			details[key] = value
		}
	}
	return details
}

func stringFromMap(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	return strings.TrimSpace(valueToString(values[key]))
}

func intFromMap(values map[string]any, key string) (int, bool) {
	if values == nil {
		return 0, false
	}
	switch value := values[key].(type) {
	case float64:
		return int(value), true
	case int:
		return value, true
	case json.Number:
		parsed, err := value.Int64()
		return int(parsed), err == nil
	case string:
		if strings.TrimSpace(value) == "" {
			return 0, false
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func boolFromMap(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	switch value := values[key].(type) {
	case bool:
		return value
	case float64:
		return value != 0
	case int:
		return value != 0
	case string:
		normalized := strings.ToLower(strings.TrimSpace(value))
		return normalized == "true" || normalized == "enabled" || normalized == "on" || normalized == "1"
	default:
		return false
	}
}

func valueToString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
