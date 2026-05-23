param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Release",

  [ValidateSet("x64")]
  [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$project = Join-Path $PSScriptRoot "trustagent_wfp.vcxproj"

$msbuild = Get-Command msbuild.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
if (-not $msbuild) {
  $msbuild = Get-ChildItem "C:\Program Files\Microsoft Visual Studio", "C:\Program Files (x86)\Microsoft Visual Studio" `
    -Recurse `
    -Filter MSBuild.exe `
    -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName
}

if (-not $msbuild) {
  throw "MSBuild was not found. Install Visual Studio Build Tools with the Windows Driver Kit."
}

$wdkInclude = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Include" -ErrorAction SilentlyContinue |
  Sort-Object Name -Descending |
  Select-Object -First 1

if (-not $wdkInclude) {
  throw "Windows Driver Kit was not found under C:\Program Files (x86)\Windows Kits\10."
}

& $msbuild $project /m /p:Configuration=$Configuration /p:Platform=$Platform /p:SkipPackageVerification=true
if ($LASTEXITCODE -ne 0) {
  throw "MSBuild failed with exit code $LASTEXITCODE."
}
