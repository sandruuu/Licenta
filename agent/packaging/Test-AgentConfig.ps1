param(
    [Parameter(Mandatory = $true)]
    [string]$RuntimePath,

    [switch]$RepairPaths,
    [switch]$SkipEnvironmentChecks
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function Resolve-AgentConfigPath {
    param([Parameter(Mandatory = $true)][string]$RuntimePath)

    $runtime = (Resolve-Path -LiteralPath $RuntimePath).ProviderPath
    return Join-Path (Split-Path -Parent $runtime) "config.json"
}

function Read-AgentConfig {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "TrustAgent config is missing: $ConfigPath"
    }
    try {
        return Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
    } catch {
        throw "TrustAgent config is not valid JSON: $($_.Exception.Message)"
    }
}

function Get-JsonPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $property = $Config.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-RequiredString {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $value = [string](Get-JsonPropertyValue -Config $Config -Name $Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "TrustAgent config '$Name' is required."
    }
    return $value.Trim()
}

function Get-OptionalBool {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$Name,
        [bool]$Default = $false
    )

    $value = Get-JsonPropertyValue -Config $Config -Name $Name
    if ($null -eq $value) {
        return $Default
    }
    if ($value -isnot [bool]) {
        throw "TrustAgent config '$Name' must be a JSON boolean."
    }
    return [bool]$value
}

function Test-GoDuration {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$Name,
        [bool]$Required = $false
    )

    $value = [string](Get-JsonPropertyValue -Config $Config -Name $Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        if ($Required) {
            throw "TrustAgent config '$Name' is required."
        }
        return
    }
    if ($value.Trim() -notmatch '^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+$') {
        throw "TrustAgent config '$Name' must use Go duration syntax, for example '10s', '3m', or '1h30m'."
    }
}

function Split-AgentHostPort {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $trimmed = $Value.Trim()
    $hostName = ""
    $portText = ""
    if ($trimmed -match '^\[([^\]]+)\]:(\d+)$') {
        $hostName = $Matches[1]
        $portText = $Matches[2]
    } else {
        $lastColon = $trimmed.LastIndexOf(":")
        if ($lastColon -le 0 -or $lastColon -ne $trimmed.IndexOf(":")) {
            throw "TrustAgent config '$Name' must be host:port."
        }
        $hostName = $trimmed.Substring(0, $lastColon)
        $portText = $trimmed.Substring($lastColon + 1)
    }

    $port = 0
    if (-not [int]::TryParse($portText, [ref]$port) -or $port -le 0 -or $port -gt 65535) {
        throw "TrustAgent config '$Name' has an invalid port."
    }
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        throw "TrustAgent config '$Name' has an empty host."
    }
    return [pscustomobject]@{ Host = $hostName.Trim(); Port = $port }
}

function Parse-AgentIPAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Value.Trim(), [ref]$ip)) {
        throw "TrustAgent config '$Name' must be an IP address."
    }
    return $ip
}

function Test-AgentIPv4CIDR {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $parts = $Value.Trim().Split("/", 2)
    if ($parts.Count -ne 2) {
        throw "TrustAgent config '$Name' must be an IPv4 CIDR, for example 100.64.0.0/10."
    }
    $ip = Parse-AgentIPAddress -Value $parts[0] -Name $Name
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "TrustAgent config '$Name' must be an IPv4 CIDR."
    }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 30) {
        throw "TrustAgent config '$Name' must have an IPv4 prefix between 0 and 30."
    }
}

function Resolve-AgentReferencedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BaseDir
    )

    $trimmed = $Path.Trim()
    if ([System.IO.Path]::IsPathRooted($trimmed)) {
        return $trimmed
    }
    return Join-Path $BaseDir $trimmed
}

function Set-AgentJsonProperty {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    if ($null -eq $Config.PSObject.Properties[$Name]) {
        $Config | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    } else {
        $Config.$Name = $Value
    }
}

function Test-AgentCertificateFile {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [switch]$RepairPaths
    )

    $configDir = Split-Path -Parent $ConfigPath
    $caValue = Get-RequiredString -Config $Config -Name "pdp_ca_file"
    $resolvedCA = Resolve-AgentReferencedPath -Path $caValue -BaseDir $configDir
    if (-not (Test-Path -LiteralPath $resolvedCA)) {
        throw "TrustAgent PDP CA file does not exist: $resolvedCA"
    }
    $caText = Get-Content -Raw -LiteralPath $resolvedCA
    if ($caText -notmatch "-----BEGIN CERTIFICATE-----") {
        throw "TrustAgent PDP CA file does not look like a PEM certificate: $resolvedCA"
    }
    if ($RepairPaths -and -not [System.IO.Path]::IsPathRooted($caValue)) {
        Set-AgentJsonProperty -Config $Config -Name "pdp_ca_file" -Value ((Resolve-Path -LiteralPath $resolvedCA).ProviderPath)
        $Config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
    }
}

function Test-TcpPortAvailable {
    param(
        [Parameter(Mandatory = $true)][System.Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $listener = [System.Net.Sockets.TcpListener]::new($Address, $Port)
    try {
        $listener.Start()
    } catch {
        throw "$Name cannot listen on $($Address.ToString()):$Port/tcp: $($_.Exception.Message)"
    } finally {
        $listener.Stop()
    }
}

function Test-UdpPortAvailable {
    param(
        [Parameter(Mandatory = $true)][System.Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $udp = $null
    try {
        $endpoint = [System.Net.IPEndPoint]::new($Address, $Port)
        $udp = [System.Net.Sockets.UdpClient]::new($endpoint)
    } catch {
        throw "$Name cannot listen on $($Address.ToString()):$Port/udp: $($_.Exception.Message)"
    } finally {
        if ($null -ne $udp) {
            $udp.Close()
        }
    }
}

function Test-WfpDeviceAvailable {
    param([Parameter(Mandatory = $true)][string]$DevicePath)

    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class TrustAgentWfpProbe {
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static void Open(string devicePath) {
        IntPtr handle = CreateFileW(devicePath, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle == INVALID_HANDLE_VALUE) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not open " + devicePath);
        }
        CloseHandle(handle);
    }
}
"@

    try {
        [TrustAgentWfpProbe]::Open($DevicePath)
    } catch {
        throw "TrustAgent traffic interception is enabled, but the WFP device '$DevicePath' is not available: $($_.Exception.Message)"
    }
}

function Test-AgentInstallConfig {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimePath,
        [switch]$RepairPaths,
        [switch]$SkipEnvironmentChecks
    )

    $configPath = Resolve-AgentConfigPath -RuntimePath $RuntimePath
    $config = Read-AgentConfig -ConfigPath $configPath

    Get-RequiredString -Config $config -Name "pdp_grpc_endpoint" | Out-Null
    Get-RequiredString -Config $config -Name "pdp_tls_server_name" | Out-Null
    Test-AgentCertificateFile -Config $config -ConfigPath $configPath -RepairPaths:$RepairPaths
    Test-GoDuration -Config $config -Name "tray_timeout" -Required $true
    Test-GoDuration -Config $config -Name "dashboard_refresh_interval" -Required $true
    foreach ($durationName in @("enrollment_timeout", "device_data_sync_interval", "device_data_sync_change_scan_interval")) {
        Test-GoDuration -Config $config -Name $durationName
    }

    $dnsListen = Split-AgentHostPort -Value (Get-RequiredString -Config $config -Name "local_dns_listen_address") -Name "local_dns_listen_address"
    $dnsListenIP = Parse-AgentIPAddress -Value $dnsListen.Host -Name "local_dns_listen_address"
    if ($dnsListen.Port -ne 53) {
        throw "TrustAgent local_dns_listen_address must use port 53 because Windows NRPT cannot target a custom DNS port."
    }
    $dnsServer = Parse-AgentIPAddress -Value (Get-RequiredString -Config $config -Name "local_dns_server") -Name "local_dns_server"
    if ($dnsListenIP.ToString() -ne "0.0.0.0" -and $dnsListenIP.ToString() -ne "::" -and $dnsListenIP.ToString() -ne $dnsServer.ToString()) {
        throw "TrustAgent local_dns_server must match the IP used by local_dns_listen_address."
    }

    Test-AgentIPv4CIDR -Value (Get-RequiredString -Config $config -Name "synthetic_ip_cidr") -Name "synthetic_ip_cidr"

    $trafficEnabled = Get-OptionalBool -Config $config -Name "traffic_interception_enabled" -Default $false
    if ($trafficEnabled) {
        $proxyListen = Split-AgentHostPort -Value (Get-RequiredString -Config $config -Name "traffic_proxy_listen_address") -Name "traffic_proxy_listen_address"
        $proxyIP = Parse-AgentIPAddress -Value $proxyListen.Host -Name "traffic_proxy_listen_address"
        $wfpDevicePath = Get-RequiredString -Config $config -Name "wfp_driver_device_path"
        $wfpFailClosed = Get-OptionalBool -Config $config -Name "wfp_fail_closed" -Default $true
        if (-not $wfpFailClosed) {
            throw "TrustAgent wfp_fail_closed must be true when traffic_interception_enabled is true."
        }
        if (-not $SkipEnvironmentChecks) {
            Test-TcpPortAvailable -Address $proxyIP -Port $proxyListen.Port -Name "TrustAgent traffic proxy"
            $driverService = Get-Service -Name "trustagent_wfp" -ErrorAction SilentlyContinue
            if ($null -eq $driverService) {
                throw "TrustAgent traffic interception is enabled, but the trustagent_wfp driver service is not installed."
            }
            if ($driverService.Status -ne "Running") {
                throw "TrustAgent traffic interception is enabled, but the trustagent_wfp driver service is not running."
            }
            Test-WfpDeviceAvailable -DevicePath $wfpDevicePath
        }
    }

    if (-not $SkipEnvironmentChecks) {
        Test-UdpPortAvailable -Address $dnsListenIP -Port $dnsListen.Port -Name "TrustAgent local DNS"
        Test-TcpPortAvailable -Address $dnsListenIP -Port $dnsListen.Port -Name "TrustAgent local DNS"
    }

    Write-Host "TrustAgent config preflight passed: $configPath"
}

Test-AgentInstallConfig -RuntimePath $RuntimePath -RepairPaths:$RepairPaths -SkipEnvironmentChecks:$SkipEnvironmentChecks
