param(
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

$service = Get-Service -Name "TrustAgent" -ErrorAction SilentlyContinue
if ($null -ne $service -and $service.Status -ne "Stopped") {
    Stop-Service -Name "TrustAgent" -Force
    try {
        (Get-Service -Name "TrustAgent" -ErrorAction Stop).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    } catch {
        throw "TrustAgent service did not stop cleanly: $($_.Exception.Message)"
    }
}

Get-Process -Name "trust-agent" -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -ne 0 } |
    Stop-Process -Force -ErrorAction SilentlyContinue
