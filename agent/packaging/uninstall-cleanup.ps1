param(
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Continue"

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($Bytes)
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha256.Dispose()
    }
}

function Get-TrustAgentState {
    param([Parameter(Mandatory = $true)][string]$StatePath)

    if (-not (Test-Path -LiteralPath $StatePath)) {
        return $null
    }
    try {
        return Get-Content -Raw -LiteralPath $StatePath | ConvertFrom-Json
    } catch {
        Write-Warning "Could not read TrustAgent enrollment state: $($_.Exception.Message)"
        return $null
    }
}

function Remove-TrustAgentCertificates {
    param(
        [string]$DeviceID,
        [string]$DeviceCertSha256
    )

    $certificates = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue)
    foreach ($certificate in $certificates) {
        $remove = $false

        if (-not [string]::IsNullOrWhiteSpace($DeviceCertSha256)) {
            $actualSha256 = Get-Sha256Hex -Bytes $certificate.RawData
            if ($actualSha256 -ieq $DeviceCertSha256.Trim()) {
                $remove = $true
            }
        }

        if (-not $remove -and -not [string]::IsNullOrWhiteSpace($DeviceID)) {
            if ($certificate.Subject -eq "CN=$DeviceID" -or $certificate.Subject -like "CN=$DeviceID,*") {
                $remove = $true
            }
        }

        if (-not $remove -and [string]::IsNullOrWhiteSpace($DeviceID) -and $certificate.Subject -match "^CN=dev_") {
            $remove = $true
        }

        if ($remove) {
            Write-Host "Removing TrustAgent device certificate $($certificate.Subject) [$($certificate.Thumbprint)]"
            Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-TrustAgentKey {
    foreach ($provider in @("Microsoft Platform Crypto Provider", "Microsoft Software Key Storage Provider")) {
        Write-Host "Removing TrustAgent private key from $provider"
        & certutil.exe -csp $provider -delkey TrustAgentDeviceKey | Out-Null
    }
}

function Stop-AndRemove-Service {
    param([Parameter(Mandatory = $true)][string]$Name)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
            try {
                (Get-Service -Name $Name -ErrorAction Stop).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
            } catch {
                Write-Warning "Service $Name did not stop cleanly: $($_.Exception.Message)"
            }
        }
    }

    & sc.exe delete $Name | Out-Null
}

function Remove-TrustAgentWfpDevices {
    $devices = @(Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FriendlyName -eq "TrustAgent WFP Redirect Driver" -or
            $_.InstanceId -like "*TrustAgentWfp*"
        })

    foreach ($device in $devices) {
        Write-Host "Removing TrustAgent WFP device $($device.InstanceId)"
        & pnputil.exe /remove-device "$($device.InstanceId)" | Out-Null
    }
}

function Get-TrustAgentDriverPackages {
    $packages = New-Object System.Collections.Generic.List[string]
    $currentPublishedName = ""
    $currentOriginalName = ""

    $lines = & pnputil.exe /enum-drivers 2>$null
    foreach ($line in $lines) {
        if ($line -match "^\s*Published Name\s*:\s*(.+)$") {
            if ($currentPublishedName -ne "" -and $currentOriginalName -ieq "trustagent_wfp.inf") {
                $packages.Add($currentPublishedName)
            }
            $currentPublishedName = $Matches[1].Trim()
            $currentOriginalName = ""
            continue
        }
        if ($line -match "^\s*Original Name\s*:\s*(.+)$") {
            $currentOriginalName = $Matches[1].Trim()
            continue
        }
    }

    if ($currentPublishedName -ne "" -and $currentOriginalName -ieq "trustagent_wfp.inf") {
        $packages.Add($currentPublishedName)
    }

    return $packages
}

function Remove-TrustAgentWfpDriverPackages {
    foreach ($package in Get-TrustAgentDriverPackages) {
        Write-Host "Removing TrustAgent WFP driver package $package"
        & pnputil.exe /delete-driver $package /uninstall /force | Out-Null
    }
}

function Remove-TrustAgentDriverCertificate {
    param([Parameter(Mandatory = $true)][string[]]$CertificatePaths)

    $seenThumbprints = @{}

    foreach ($certificatePath in $CertificatePaths) {
        if ([string]::IsNullOrWhiteSpace($certificatePath) -or -not (Test-Path -LiteralPath $certificatePath)) {
            continue
        }

        try {
            $driverCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
            if ([string]::IsNullOrWhiteSpace($driverCertificate.Thumbprint) -or $seenThumbprints.ContainsKey($driverCertificate.Thumbprint)) {
                continue
            }
            $seenThumbprints[$driverCertificate.Thumbprint] = $true

            foreach ($storePath in @("Cert:\LocalMachine\Root", "Cert:\LocalMachine\TrustedPublisher")) {
                Get-ChildItem $storePath -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint -eq $driverCertificate.Thumbprint } |
                    ForEach-Object {
                        Write-Host "Removing TrustAgent driver certificate from $storePath [$($_.Thumbprint)]"
                        Remove-Item -LiteralPath $_.PSPath -Force -ErrorAction SilentlyContinue
                    }
            }
        } catch {
            Write-Warning "Could not remove TrustAgent driver certificate from ${certificatePath}: $($_.Exception.Message)"
        }
    }
}

function Remove-TrustAgentProgramData {
    param([Parameter(Mandatory = $true)][string]$StateDir)

    $programData = [System.IO.Path]::GetFullPath($env:ProgramData)
    $resolvedStateDir = [System.IO.Path]::GetFullPath($StateDir)
    $expectedStateDir = [System.IO.Path]::GetFullPath((Join-Path $programData "TrustAgent"))

    if ($resolvedStateDir -ne $expectedStateDir) {
        throw "Refusing to remove unexpected TrustAgent state directory: $resolvedStateDir"
    }

    if (Test-Path -LiteralPath $resolvedStateDir) {
        Write-Host "Removing TrustAgent state directory $resolvedStateDir"
        Remove-Item -LiteralPath $resolvedStateDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Remove-TrustAgentNrptRules {
    try {
        Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Comment -eq "TRUSTAGENT" } |
            Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not remove TrustAgent NRPT rules: $($_.Exception.Message)"
    }
}

function Remove-TrustAgentLegacyRegistry {
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TrustAgent" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "TrustAgentResumeSetup" -Force -ErrorAction SilentlyContinue
}

try {
    Stop-AndRemove-Service -Name "TrustAgent"
    Stop-AndRemove-Service -Name "trustagent_wfp"
    Get-Process -Name "trust-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $stateDir = Join-Path $env:ProgramData "TrustAgent"
    $statePath = Join-Path $stateDir "enrollment.json"
    $state = Get-TrustAgentState -StatePath $statePath

    $deviceID = ""
    $deviceCertSha256 = ""
    if ($null -ne $state) {
        $deviceID = [string]$state.device_id
        $deviceCertSha256 = [string]$state.device_cert_thumbprint
    }

    Remove-TrustAgentCertificates -DeviceID $deviceID -DeviceCertSha256 $deviceCertSha256
    Remove-TrustAgentKey
    Remove-TrustAgentWfpDevices
    Remove-TrustAgentWfpDriverPackages
    $driverCertificatePaths = @((Join-Path $PSScriptRoot "wfp-driver\trustagent_wfp.cer"))
    if (-not [string]::IsNullOrWhiteSpace($InstallDir)) {
        $driverCertificatePaths += (Join-Path $InstallDir "wfp-driver\trustagent_wfp.cer")
    }
    Remove-TrustAgentDriverCertificate -CertificatePaths $driverCertificatePaths
    Remove-TrustAgentNrptRules
    Remove-TrustAgentProgramData -StateDir $stateDir
    Remove-TrustAgentLegacyRegistry
} catch {
    Write-Warning "TrustAgent uninstall cleanup did not complete cleanly: $($_.Exception.Message)"
}
