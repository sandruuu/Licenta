# ============================================================================
# ZTNA OIDC Flow — Test Script
# ============================================================================
# This script starts all required services to test the OIDC authorization
# code flow end-to-end: Cloud (IdP), Gateway (PEP), and Connect-App.
#
# Prerequisites:
#   - Go installed and in PATH
#   - TLS certificates generated in certs/ directory
#   - Run as Administrator (required for TUN interface and DNS on port 53)
#
# Test user:  admin / admin123
#
# Flow:
#   1. Start Cloud (IdP) on :8443
#   2. Start Session Store on :6380
#   3. Start Gateway Portal on :9443 (yamux) + :9444 (OIDC callback)
#   4. Start Connect-App (TUN + Magic DNS)
#   5. Test by resolving rdp-desktop.lab.local → access triggers OIDC auth
# ============================================================================

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ZTNA OIDC Flow — Test Launcher" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[WARN] Not running as Administrator. TUN interface and DNS on port 53 may fail." -ForegroundColor Yellow
    Write-Host "       Recommend: Right-click PowerShell > Run as Administrator" -ForegroundColor Yellow
    Write-Host ""
}

# Verify certs exist
$requiredCerts = @("ca.crt", "cloud.crt", "cloud.key", "gateway.crt", "gateway.key")
foreach ($cert in $requiredCerts) {
    if (-not (Test-Path "$Root\certs\$cert")) {
        Write-Host "[ERROR] Missing certificate: certs\$cert" -ForegroundColor Red
        exit 1
    }
}
Write-Host "[OK] TLS certificates found" -ForegroundColor Green

# Build all components
Write-Host ""
Write-Host "--- Building components ---" -ForegroundColor Yellow

Write-Host "  Building Cloud..."
Push-Location "$Root\cloud"
go build -o cloud.exe . 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Cloud build failed" -ForegroundColor Red; Pop-Location; exit 1 }
Pop-Location
Write-Host "  [OK] Cloud built" -ForegroundColor Green

Write-Host "  Building Session Store..."
Push-Location "$Root\gateway"
go build -o sessionstore.exe ./cmd/sessionstore 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Session Store build failed" -ForegroundColor Red; Pop-Location; exit 1 }
Pop-Location
Write-Host "  [OK] Session Store built" -ForegroundColor Green

Write-Host "  Building Gateway Portal..."
Push-Location "$Root\gateway"
go build -o portal.exe ./cmd/portal 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Portal build failed" -ForegroundColor Red; Pop-Location; exit 1 }
Pop-Location
Write-Host "  [OK] Portal built" -ForegroundColor Green

Write-Host "  Building Connect-App..."
Push-Location "$Root\connect-app"
go build -o connect-app.exe . 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Connect-App build failed" -ForegroundColor Red; Pop-Location; exit 1 }
Pop-Location
Write-Host "  [OK] Connect-App built" -ForegroundColor Green

# Start services
Write-Host ""
Write-Host "--- Starting services ---" -ForegroundColor Yellow

# 1. Cloud (IdP)
Write-Host "  Starting Cloud (IdP) on :8443..."
$cloudProc = Start-Process -FilePath "$Root\cloud\cloud.exe" `
    -ArgumentList "--config", "cloud-config.json" `
    -WorkingDirectory "$Root\cloud" `
    -PassThru -NoNewWindow -RedirectStandardOutput "$Root\cloud\cloud.log" -RedirectStandardError "$Root\cloud\cloud-error.log"
Start-Sleep -Seconds 2
Write-Host "  [OK] Cloud started (PID: $($cloudProc.Id))" -ForegroundColor Green

# 2. Session Store
Write-Host "  Starting Session Store on :6380..."
$storeProc = Start-Process -FilePath "$Root\gateway\sessionstore.exe" `
    -ArgumentList "--addr", ":6380" `
    -WorkingDirectory "$Root\gateway" `
    -PassThru -NoNewWindow -RedirectStandardOutput "$Root\gateway\store.log" -RedirectStandardError "$Root\gateway\store-error.log"
Start-Sleep -Seconds 1
Write-Host "  [OK] Session Store started (PID: $($storeProc.Id))" -ForegroundColor Green

# 3. Gateway Portal
Write-Host "  Starting Gateway Portal on :9443 + OIDC callback on :9444..."
$portalProc = Start-Process -FilePath "$Root\gateway\portal.exe" `
    -ArgumentList "--config", "gateway-config.json", "--insecure" `
    -WorkingDirectory "$Root\gateway" `
    -PassThru -NoNewWindow -RedirectStandardOutput "$Root\gateway\portal.log" -RedirectStandardError "$Root\gateway\portal-error.log"
Start-Sleep -Seconds 2
Write-Host "  [OK] Portal started (PID: $($portalProc.Id))" -ForegroundColor Green

# 4. Connect-App (requires admin for TUN)
Write-Host "  Starting Connect-App..."
$connectProc = Start-Process -FilePath "$Root\connect-app\connect-app.exe" `
    -WorkingDirectory "$Root\connect-app" `
    -PassThru -NoNewWindow -RedirectStandardOutput "$Root\connect-app\connect.log" -RedirectStandardError "$Root\connect-app\connect-error.log"
Start-Sleep -Seconds 2
Write-Host "  [OK] Connect-App started (PID: $($connectProc.Id))" -ForegroundColor Green

# Print status
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  All services running!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Services:" -ForegroundColor White
Write-Host "    Cloud (IdP):       https://localhost:8443  (PID: $($cloudProc.Id))" -ForegroundColor Gray
Write-Host "    Session Store:     http://localhost:6380   (PID: $($storeProc.Id))" -ForegroundColor Gray
Write-Host "    Gateway Portal:    localhost:9443 (yamux)  (PID: $($portalProc.Id))" -ForegroundColor Gray
Write-Host "    OIDC Callback:     https://localhost:9444  (PID: $($portalProc.Id))" -ForegroundColor Gray
Write-Host "    Connect-App:       TUN + DNS               (PID: $($connectProc.Id))" -ForegroundColor Gray
Write-Host ""
Write-Host "  Test credentials:    admin / admin123" -ForegroundColor White
Write-Host ""
Write-Host "  Test flow:" -ForegroundColor White
Write-Host "    1. nslookup rdp-desktop.lab.local 127.0.0.1" -ForegroundColor Gray
Write-Host "       (Should return a 100.64.x.x CGNAT IP)" -ForegroundColor DarkGray
Write-Host "    2. Try to connect to the CGNAT IP (e.g., mstsc /v:100.64.x.x)" -ForegroundColor Gray
Write-Host "       (Should open browser for OIDC authentication)" -ForegroundColor DarkGray
Write-Host "    3. Login with admin / admin123 in the browser" -ForegroundColor Gray
Write-Host "    4. After auth, retry the connection" -ForegroundColor Gray
Write-Host ""
Write-Host "  Logs:" -ForegroundColor White
Write-Host "    cloud\cloud.log, gateway\portal.log, connect-app\connect.log" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press Ctrl+C to stop all services" -ForegroundColor Yellow
Write-Host ""

# Store PIDs for cleanup
$pids = @($cloudProc.Id, $storeProc.Id, $portalProc.Id, $connectProc.Id)

# Wait and cleanup on exit
try {
    # Monitor processes
    while ($true) {
        Start-Sleep -Seconds 5
        foreach ($proc in @($cloudProc, $storeProc, $portalProc, $connectProc)) {
            if ($proc.HasExited) {
                Write-Host "[WARN] Process $($proc.Id) has exited with code $($proc.ExitCode)" -ForegroundColor Yellow
            }
        }
    }
} finally {
    Write-Host ""
    Write-Host "Stopping all services..." -ForegroundColor Yellow
    foreach ($pid in $pids) {
        try { Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } catch {}
    }
    Write-Host "All services stopped." -ForegroundColor Green
}
