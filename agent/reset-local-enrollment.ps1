param(
  [string]$ServiceName = "TrustAgent",
  [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated PowerShell window."
}

function Get-ServiceExecutableDirectory {
  param([Parameter(Mandatory = $true)][string]$Name)

  $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
  if ($null -eq $service) {
    return $null
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

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$buildDir = Join-Path $PSScriptRoot "build"
$buildExe = Join-Path $buildDir "trust-agent.exe"
$buildConfig = Join-Path $buildDir "config.json"

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
  $serviceInstallDir = Get-ServiceExecutableDirectory -Name $ServiceName
  if (-not [string]::IsNullOrWhiteSpace($serviceInstallDir)) {
    $InstallDir = $serviceInstallDir
  } else {
    $InstallDir = "C:\Program Files\TrustAgent"
  }
}

$installExe = Join-Path $InstallDir "trust-agent.exe"
$installConfig = Join-Path $InstallDir "config.json"
$stateDir = "C:\ProgramData\TrustAgent"
$statePath = Join-Path $stateDir "enrollment.json"

if (-not (Test-Path -LiteralPath $buildExe)) {
  throw "Missing build executable: $buildExe"
}
if (-not (Test-Path -LiteralPath $buildConfig)) {
  throw "Missing build config: $buildConfig"
}

if (-not (Test-Path -LiteralPath $InstallDir)) {
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Get-Process -Name trust-agent -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

Copy-WithRetry -Source $buildExe -Destination $installExe
Copy-WithRetry -Source $buildConfig -Destination $installConfig

if (Test-Path -LiteralPath $statePath) {
  $backup = Join-Path $stateDir "enrollment.before-reenroll-$stamp.json"
  Copy-Item -LiteralPath $statePath -Destination $backup -Force
  Remove-Item -LiteralPath $statePath -Force
  Write-Host "Backed up enrollment state to $backup"
}

Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Subject -match "^CN=dev_" } |
  ForEach-Object {
    Write-Host "Removing device certificate $($_.Subject) [$($_.Thumbprint)]"
    Remove-Item -LiteralPath $_.PSPath -Force
  }

certutil -csp "Microsoft Platform Crypto Provider" -delkey TrustAgentDeviceKey | Out-Host
certutil -csp "Microsoft Software Key Storage Provider" -delkey TrustAgentDeviceKey | Out-Host

Get-DnsClientNrptRule |
  Where-Object { $_.Comment -eq "TRUSTAGENT" } |
  Remove-DnsClientNrptRule -Force

ipconfig /flushdns | Out-Host

Start-Service $ServiceName
Start-Sleep -Seconds 2
Start-Process -FilePath $installExe

Write-Host "Installed TrustAgent hash:"
Get-FileHash -LiteralPath $installExe -Algorithm SHA256 | Format-List
Write-Host "Local enrollment reset complete. The UI should show UNENROLLED DEVICE."
