#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$ServiceName = "TrustAgent"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$LogPath = Join-Path $PSScriptRoot "install-local-build.log"

function Get-ServiceExecutableDirectory {
    param([Parameter(Mandatory = $true)][string]$Name)

    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    if ($null -eq $service) {
        throw "Service '$Name' was not found."
    }

    $pathName = [string]$service.PathName
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

    return Split-Path -Parent $exePath
}

function Copy-WithRetry {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [int]$Attempts = 10,
        [int]$DelaySeconds = 1
    )

    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            Copy-Item -LiteralPath $Source -Destination $Destination -Force
            return
        } catch {
            if ($i -eq $Attempts) {
                throw
            }
            Write-Warning "Copy attempt $i failed for '$Destination': $($_.Exception.Message)"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

Start-Transcript -Path $LogPath -Force | Out-Null

try {
    $BuildDir = Join-Path $PSScriptRoot "build"
    $BuildExe = Join-Path $BuildDir "trust-agent.exe"
    $BuildConfig = Join-Path $BuildDir "config.json"
    foreach ($path in @($BuildExe, $BuildConfig)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required build artifact is missing: $path"
        }
    }

    $InstallDir = Get-ServiceExecutableDirectory -Name $ServiceName
    $InstallExe = Join-Path $InstallDir "trust-agent.exe"
    $InstallConfig = Join-Path $InstallDir "config.json"

    Write-Host "Stopping $ServiceName"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 10; $i++) {
        $processes = @(Get-Process -Name trust-agent -ErrorAction SilentlyContinue)
        if ($processes.Count -eq 0) {
            break
        }
        $processes | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }

    Write-Host "Copying $BuildExe -> $InstallExe"
    Copy-WithRetry -Source $BuildExe -Destination $InstallExe
    Write-Host "Copying $BuildConfig -> $InstallConfig"
    Copy-WithRetry -Source $BuildConfig -Destination $InstallConfig

    if (Get-Service -Name trustagent_wfp -ErrorAction SilentlyContinue) {
        Start-Service -Name trustagent_wfp -ErrorAction SilentlyContinue
    }

    Write-Host "Starting $ServiceName"
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2

    Get-Service -Name $ServiceName,trustagent_wfp -ErrorAction SilentlyContinue |
        Format-Table Name, Status, StartType, ServiceType

    Write-Host "Installed TrustAgent hash:"
    Get-FileHash -LiteralPath $InstallExe -Algorithm SHA256 | Format-List
} finally {
    Stop-Transcript | Out-Null
}
