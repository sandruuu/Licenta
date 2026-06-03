param(
    [Parameter(Mandatory = $true)]
    [string]$RuntimePath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$serviceName = "TrustAgent"
$displayName = "TrustAgent"
$description = "Privileged TrustAgent endpoint service."

$runtime = (Resolve-Path -LiteralPath $RuntimePath).ProviderPath
$binaryPath = '"' + $runtime + '"'
$preflightScript = Join-Path $PSScriptRoot "Test-AgentConfig.ps1"
if (-not (Test-Path -LiteralPath $preflightScript)) {
    throw "TrustAgent config preflight script is missing: $preflightScript"
}

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
    Start-Service -Name trustagent_wfp -ErrorAction SilentlyContinue
    (Get-Service -Name trustagent_wfp).WaitForStatus("Running", [TimeSpan]::FromSeconds(15))
}

& $preflightScript -RuntimePath $runtime -RepairPaths

& sc.exe description $serviceName $description | Out-Null
& sc.exe config $serviceName start= delayed-auto | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
& sc.exe failureflag $serviceName 1 | Out-Null

Start-Service -Name $serviceName
