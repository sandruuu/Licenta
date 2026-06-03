param(
    [string]$OutputDir = "",
    [string]$ConfigPath = ""
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $PSCommandPath
$agentRoot = Resolve-Path (Join-Path $scriptDir "..")
if ($OutputDir.Trim() -eq "") {
    $OutputDir = Join-Path $agentRoot "build"
}

function Get-FirstAssetName([string]$AssetsDir, [string]$Filter) {
    if (-not (Test-Path -LiteralPath $AssetsDir)) {
        return ""
    }
    $asset = Get-ChildItem -LiteralPath $AssetsDir -Filter $Filter | Select-Object -First 1
    if ($null -eq $asset) {
        return ""
    }
    return $asset.Name
}

function Normalize-ViteAssets([string]$DistDir, [string]$JavascriptName, [string]$StylesheetName) {
    $assetsDir = Join-Path $DistDir "assets"
    $indexPath = Join-Path $DistDir "index.html"
    if ($JavascriptName.Trim() -ne "") {
        $generatedJavascript = Get-ChildItem -LiteralPath $assetsDir -Filter "index.*.js" | Select-Object -First 1
        if ($null -ne $generatedJavascript -and $generatedJavascript.Name -ne $JavascriptName) {
            Move-Item -LiteralPath $generatedJavascript.FullName -Destination (Join-Path $assetsDir $JavascriptName) -Force
        }
    }
    if ($StylesheetName.Trim() -ne "") {
        $generatedStylesheet = Get-ChildItem -LiteralPath $assetsDir -Filter "index.*.css" | Select-Object -First 1
        if ($null -ne $generatedStylesheet -and $generatedStylesheet.Name -ne $StylesheetName) {
            Move-Item -LiteralPath $generatedStylesheet.FullName -Destination (Join-Path $assetsDir $StylesheetName) -Force
        }
    }
    if (Test-Path -LiteralPath $indexPath) {
        $html = Get-Content -Raw -LiteralPath $indexPath
        if ($JavascriptName.Trim() -ne "") {
            $html = $html -replace '/assets/index\.[^"]+\.js', "/assets/$JavascriptName"
        }
        if ($StylesheetName.Trim() -ne "") {
            $html = $html -replace '/assets/index\.[^"]+\.css', "/assets/$StylesheetName"
        }
        Set-Content -LiteralPath $indexPath -Value $html -NoNewline
    }
}

function Find-InnoSetupCompiler {
    $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return ""
}

function Resolve-ConfigReferencedPath {
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

function Copy-AgentConfig {
    param(
        [Parameter(Mandatory = $true)][string]$SourceConfigPath,
        [Parameter(Mandatory = $true)][string]$DestinationDir
    )

    $destinationConfigPath = Join-Path $DestinationDir "config.json"
    $config = Get-Content -Raw -LiteralPath $SourceConfigPath | ConvertFrom-Json
    $caValue = [string]$config.pdp_ca_file
    if ($caValue.Trim() -ne "") {
        $sourceCAPath = Resolve-ConfigReferencedPath -Path $caValue -BaseDir (Split-Path -Parent $SourceConfigPath)
        if (-not (Test-Path -LiteralPath $sourceCAPath)) {
            throw "Configured pdp_ca_file does not exist: $sourceCAPath"
        }
        Copy-Item -LiteralPath $sourceCAPath -Destination (Join-Path $DestinationDir "pdp-ca.pem") -Force
        $config.pdp_ca_file = "pdp-ca.pem"
    }
    $config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $destinationConfigPath -Encoding UTF8
    return $destinationConfigPath
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$staleOutputs = @(
    "trust-agent.exe",
    "TrustAgent-Setup.exe",
    "config.json",
    "pdp-ca.pem",
    "install-service.ps1",
    "Test-AgentConfig.ps1"
)
foreach ($staleOutput in $staleOutputs) {
    $stalePath = Join-Path $OutputDir $staleOutput
    if (Test-Path -LiteralPath $stalePath) {
        Remove-Item -LiteralPath $stalePath -Force
    }
}

Push-Location $agentRoot
try {
    $distDir = Join-Path $agentRoot "internal\tray\frontend\dist"
    $assetsDir = Join-Path $distDir "assets"
    $javascriptName = Get-FirstAssetName $assetsDir "index.*.js"
    $stylesheetName = Get-FirstAssetName $assetsDir "index.*.css"

    Push-Location "internal\tray\frontend"
    try {
        npm run build
    } finally {
        Pop-Location
    }
    Normalize-ViteAssets $distDir $javascriptName $stylesheetName

    go build -tags "desktop,production" -ldflags "-H windowsgui" -o (Join-Path $OutputDir "trust-agent.exe") ./cmd/agent
} finally {
    Pop-Location
}

Copy-Item -LiteralPath (Join-Path $scriptDir "install-service.ps1") -Destination (Join-Path $OutputDir "install-service.ps1") -Force
Copy-Item -LiteralPath (Join-Path $scriptDir "Test-AgentConfig.ps1") -Destination (Join-Path $OutputDir "Test-AgentConfig.ps1") -Force

$resolvedConfigPath = $ConfigPath.Trim()
if ($resolvedConfigPath -eq "") {
    $candidateConfig = Join-Path $agentRoot "config.json"
    if (Test-Path -LiteralPath $candidateConfig) {
        $resolvedConfigPath = $candidateConfig
    }
}
if ($resolvedConfigPath -eq "") {
    throw "TrustAgent config.json is required. Pass -ConfigPath or keep config.json in the agent root."
}
$resolvedConfigPath = (Resolve-Path -LiteralPath $resolvedConfigPath).ProviderPath
Copy-AgentConfig -SourceConfigPath $resolvedConfigPath -DestinationDir $OutputDir | Out-Null
& (Join-Path $OutputDir "Test-AgentConfig.ps1") -RuntimePath (Join-Path $OutputDir "trust-agent.exe") -SkipEnvironmentChecks

$iscc = Find-InnoSetupCompiler
if ($iscc.Trim() -ne "") {
    $installerScript = Join-Path $scriptDir "trust-agent-setup.iss"
    & $iscc "/DSourceDir=$OutputDir" "/O$OutputDir" "/FTrustAgent-Setup" $installerScript
    Write-Host "Windows setup created at $(Join-Path $OutputDir 'TrustAgent-Setup.exe')"
} else {
    Write-Host "Inno Setup compiler (ISCC.exe) was not found. Skipping TrustAgent-Setup.exe."
    Write-Host "Install Inno Setup 6 to generate the custom Windows installer."
}

Write-Host "Enterprise package created at $OutputDir"
