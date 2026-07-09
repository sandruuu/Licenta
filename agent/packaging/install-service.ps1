param(
    [Parameter(Mandatory = $true)]
    [string]$RuntimePath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$serviceName = "TrustAgent"
$displayName = "TrustAgent"
$description = "Privileged TrustAgent endpoint service."
$pipePath = "\\.\pipe\trust-agent"

function Test-TrustAgentPipe {
    try {
        return [System.IO.Directory]::GetFiles("\\.\pipe\") -contains $pipePath
    } catch {
        return Test-Path -LiteralPath $pipePath
    }
}

function Wait-TrustAgentReady {
    param(
        [int]$TimeoutSeconds = 30
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -eq "Stopped") {
            throw "TrustAgent service stopped before creating the IPC pipe."
        }
        if (Test-TrustAgentPipe) {
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "TrustAgent service did not create the IPC pipe $pipePath within $TimeoutSeconds seconds."
}

function Set-TrustAgentAutomaticStart {
    & sc.exe config $serviceName start= auto | Out-Null
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if (Test-Path -LiteralPath $serviceKey) {
        New-ItemProperty -Path $serviceKey -Name "DelayedAutoStart" -PropertyType DWord -Value 0 -Force | Out-Null
    }
}

$runtime = (Resolve-Path -LiteralPath $RuntimePath).ProviderPath
$binaryPath = '"' + $runtime + '"'

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    & sc.exe config $serviceName binPath= $binaryPath start= auto DisplayName= $displayName | Out-Null
} else {
    New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName $displayName -StartupType Automatic | Out-Null
}

$wfpService = Get-Service -Name trustagent_wfp -ErrorAction SilentlyContinue
if ($null -ne $wfpService -and $wfpService.Status -ne "Running") {
    try {
        Start-Service -Name trustagent_wfp -ErrorAction Stop
        (Get-Service -Name trustagent_wfp -ErrorAction Stop).WaitForStatus("Running", [TimeSpan]::FromSeconds(15))
    } catch {
        Write-Warning "TrustAgent WFP driver service is not running yet: $($_.Exception.Message)"
    }
}

& sc.exe description $serviceName $description | Out-Null
Set-TrustAgentAutomaticStart
& sc.exe failure $serviceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
& sc.exe failureflag $serviceName 1 | Out-Null

Start-Service -Name $serviceName
try {
    Wait-TrustAgentReady -TimeoutSeconds 30
} catch {
    Write-Warning "$($_.Exception.Message) Restarting TrustAgent once."
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Service -Name $serviceName
    Wait-TrustAgentReady -TimeoutSeconds 30
}
