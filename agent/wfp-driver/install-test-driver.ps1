#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$SkipDriverInstall,
    [switch]$SkipTrustAgentRestart
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExitCode = 0
$LogPath = Join-Path $PSScriptRoot "install-test-driver.log"

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)

    Write-Host ""
    Write-Host "== $Message"
}

function Get-ServiceExecutableDirectory {
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($null -eq $service) {
        throw "Service '$ServiceName' was not found."
    }

    $pathName = [string]$service.PathName
    if ([string]::IsNullOrWhiteSpace($pathName)) {
        throw "Service '$ServiceName' does not expose an executable path."
    }

    if ($pathName -match '^\s*"([^"]+)"') {
        $exePath = $Matches[1]
    } else {
        $trimmedPathName = $pathName.Trim()
        $exeMarker = $trimmedPathName.IndexOf(".exe", [StringComparison]::OrdinalIgnoreCase)
        if ($exeMarker -lt 0) {
            throw "Could not parse executable path from service command line: $pathName"
        }
        $exePath = $trimmedPathName.Substring(0, $exeMarker + 4)
    }

    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "Service executable does not exist: $exePath"
    }

    return Split-Path -Parent $exePath
}

function Set-JsonProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowNull()]$Value
    )

    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class TrustAgentWfpDeviceProbe {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

function Test-DriverDevicePath {
    param([Parameter(Mandatory = $true)][string]$DevicePath)

    $invalidHandle = [IntPtr]::new(-1)
    $handle = [TrustAgentWfpDeviceProbe]::CreateFileW($DevicePath, [uint32]0, [uint32]3, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -eq $invalidHandle) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Could not open $DevicePath. Win32 error: $errorCode"
    }
    [TrustAgentWfpDeviceProbe]::CloseHandle($handle) | Out-Null
}

function Assert-DriverDeviceHealthy {
    $driverDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.Service -eq "trustagent_wfp" -or
        $_.FriendlyName -eq "TrustAgent WFP Redirect Driver" -or
        $_.InstanceId -like "ROOT\TRUSTAGENTWFP\*" -or
        ($_.InstanceId -like "ROOT\SYSTEM\*" -and $_.Service -eq "trustagent_wfp")
    })
    if ($driverDevices.Count -eq 0) {
        throw "TrustAgent WFP PnP device was not found."
    }
    $unhealthy = @($driverDevices | Where-Object { $_.Status -ne "OK" })
    if ($unhealthy.Count -gt 0) {
        $summary = ($unhealthy | ForEach-Object { "$($_.InstanceId) status=$($_.Status) problem=$($_.Problem)" }) -join "; "
        throw "TrustAgent WFP PnP device is not healthy: $summary"
    }
    Test-DriverDevicePath -DevicePath "\\.\TrustAgentWfp"
}

Start-Transcript -Path $LogPath -Force | Out-Null

try {
    $RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
    $DriverPackage = Join-Path $PSScriptRoot "x64\Release\trustagent_wfp"
    $InfPath = Join-Path $DriverPackage "trustagent_wfp.inf"
    $CertPath = Join-Path $PSScriptRoot "x64\Release\trustagent_wfp.cer"
    $DevconPath = "C:\Program Files (x86)\Windows Kits\10\Tools\10.0.26100.0\x64\devcon.exe"
    $SourceConfigPath = Join-Path $RepoRoot "agent\config.json"

    Write-Step "Checking prerequisites"
    foreach ($path in @($InfPath, $CertPath, $DevconPath, $SourceConfigPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required path is missing: $path"
        }
        Write-Host "Found: $path"
    }

    Write-Step "Checking Windows test-signing mode"
    $bcdOutput = & bcdedit.exe /enum 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "bcdedit failed: $($bcdOutput -join "`n")"
    }

    $testSigningEnabled = (($bcdOutput -join "`n") -match '(?im)^\s*testsigning\s+Yes\s*$')
    if (-not $testSigningEnabled) {
        & bcdedit.exe /set testsigning on
        if ($LASTEXITCODE -ne 0) {
            throw "Could not enable Windows test-signing mode."
        }

        Write-Warning "Windows test-signing was enabled. Reboot Windows, then run this script again."
        $ExitCode = 3010
    } else {
        Write-Host "Windows test-signing is already enabled."
    }

    if ($ExitCode -eq 0) {
        Write-Step "Trusting the test certificate"
        Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Host
        Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Host

        Write-Step "Stopping TrustAgent before driver installation"
        $agentService = Get-Service -Name TrustAgent -ErrorAction SilentlyContinue
        if ($null -ne $agentService -and $agentService.Status -eq "Running") {
            Stop-Service -Name TrustAgent -Force
        }

        $existingDriverService = Get-Service -Name trustagent_wfp -ErrorAction SilentlyContinue
        if ($null -ne $existingDriverService -and $existingDriverService.Status -eq "Running") {
            Stop-Service -Name trustagent_wfp -ErrorAction SilentlyContinue
        }

        Write-Step "Removing stale TrustAgent WFP device instances"
        $staleDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.Service -eq "trustagent_wfp" -or
            $_.FriendlyName -eq "TrustAgent WFP Redirect Driver" -or
            $_.InstanceId -like "ROOT\TRUSTAGENTWFP\*" -or
            ($_.InstanceId -like "ROOT\NETWORK\*" -and $_.Service -eq "trustagent_wfp")
        })
        foreach ($device in $staleDevices) {
            Write-Host "Removing device instance: $($device.InstanceId)"
            & pnputil.exe /remove-device "$($device.InstanceId)" | Out-Host
        }

        Write-Step "Installing TrustAgent WFP driver"
        if (-not $SkipDriverInstall) {
            $driverDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
                $_.Service -eq "trustagent_wfp" -or $_.InstanceId -like "ROOT\TRUSTAGENTWFP\*"
            })
            if ($driverDevices.Count -eq 0) {
                & $DevconPath install $InfPath Root\TrustAgentWfp
            } else {
                & $DevconPath update $InfPath Root\TrustAgentWfp
            }

            $devconExit = $LASTEXITCODE
            if ($devconExit -ne 0 -and $devconExit -ne 1) {
                throw "devcon failed with exit code $devconExit."
            }
            if ($devconExit -eq 1) {
                Write-Warning "devcon requested a reboot to complete driver installation."
            }
        } else {
            Write-Host "Driver install/update skipped."
        }

        $driverService = Get-Service -Name trustagent_wfp -ErrorAction Stop
        if ($driverService.Status -ne "Running") {
            Start-Service -Name trustagent_wfp
        }

        Write-Step "Enabling traffic interception in TrustAgent config"
        $InstallDir = Get-ServiceExecutableDirectory -ServiceName "TrustAgent"
        $InstalledConfigPath = Join-Path $InstallDir "config.json"
        $ConfigBasePath = if (Test-Path -LiteralPath $InstalledConfigPath) { $InstalledConfigPath } else { $SourceConfigPath }
        $config = Get-Content -LiteralPath $ConfigBasePath -Raw | ConvertFrom-Json

        Set-JsonProperty -Object $config -Name "traffic_interception_enabled" -Value $true
        Set-JsonProperty -Object $config -Name "traffic_proxy_listen_address" -Value "127.0.0.1:18787"
        Set-JsonProperty -Object $config -Name "wfp_driver_device_path" -Value "\\.\TrustAgentWfp"
        Set-JsonProperty -Object $config -Name "wfp_fail_closed" -Value $true

        $configJson = $config | ConvertTo-Json -Depth 16
        [System.IO.File]::WriteAllText($InstalledConfigPath, $configJson + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        Write-Host "Updated: $InstalledConfigPath"

        if (-not $SkipTrustAgentRestart) {
            Write-Step "Restarting TrustAgent service"
            Restart-Service -Name TrustAgent -Force
        }

        Write-Step "Validating TrustAgent WFP device"
        Assert-DriverDeviceHealthy

        Write-Step "Current service status"
        Get-Service -Name TrustAgent,trustagent_wfp | Format-Table Name, Status, StartType, ServiceType
    }
} catch {
    Write-Error $_
    $ExitCode = 1
} finally {
    Stop-Transcript | Out-Null
}

exit $ExitCode
