param(
    [Parameter(Mandatory = $true)]
    [string]$DriverDir
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$serviceName = "trustagent_wfp"
$deviceHardwareId = "Root\TrustAgentWfp"
$deviceDescription = "TrustAgent WFP Redirect Driver"
$devicePath = "\\.\TrustAgentWfp"
$driverDirPath = (Resolve-Path -LiteralPath $DriverDir).ProviderPath
$infPath = Join-Path $driverDirPath "trustagent_wfp.inf"
$sysPath = Join-Path $driverDirPath "trustagent_wfp.sys"
$catPath = Join-Path $driverDirPath "trustagent_wfp.cat"
$certPath = Join-Path $driverDirPath "trustagent_wfp.cer"
$devconPath = Join-Path $driverDirPath "devcon.exe"
$rebootMarkerPath = Join-Path $driverDirPath "reboot-required.txt"
$logPath = Join-Path $driverDirPath "install-wfp-driver.log"

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[TrustAgent WFP] $Message"
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "TrustAgent WFP driver installation must run as Administrator."
    }
}

function Assert-DriverPackage {
    foreach ($path in @($infPath, $sysPath, $catPath, $certPath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "TrustAgent WFP driver package is incomplete. Missing: $path"
        }
    }
}

function Test-WindowsTestSigning {
    $bcdOutput = & bcdedit.exe /enum 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "bcdedit failed: $($bcdOutput -join "`n")"
    }
    return (($bcdOutput -join "`n") -match '(?im)^\s*testsigning\s+Yes\s*$')
}

function Test-SecureBootEnabled {
    try {
        return [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
    } catch {
        Write-Warning "Could not determine Secure Boot state: $($_.Exception.Message)"
        return $false
    }
}

function Enable-WindowsTestSigning {
    & bcdedit.exe /set testsigning on | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not enable Windows test-signing mode. If Secure Boot is enabled, Windows may reject test-signed drivers."
    }
    "Windows test-signing was enabled. Reboot Windows, then run TrustAgent.exe again to finish WFP driver installation." |
        Set-Content -LiteralPath $rebootMarkerPath -Encoding UTF8
}

function Add-TrustAgentDriverCertificate {
    Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
}

function Test-DriverPackageUsesTestCertificate {
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certPath)
    $identity = "$($certificate.Subject) $($certificate.Issuer)"
    return ($identity -match '(?i)\b(test|wdk)\b')
}

function Add-SetupApiHelper {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class TrustAgentWfpInstaller {
    private const UInt32 DICD_GENERATE_ID = 0x00000001;
    private const UInt32 SPDRP_HARDWAREID = 0x00000001;
    private const UInt32 DIF_REGISTERDEVICE = 0x00000019;
    private const UInt32 INSTALLFLAG_FORCE = 0x00000001;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA {
        public UInt32 cbSize;
        public Guid ClassGuid;
        public UInt32 DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", SetLastError=true)]
    private static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid ClassGuid, IntPtr hwndParent);

    [DllImport("setupapi.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool SetupDiCreateDeviceInfo(
        IntPtr DeviceInfoSet,
        string DeviceName,
        ref Guid ClassGuid,
        string DeviceDescription,
        IntPtr hwndParent,
        UInt32 CreationFlags,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError=true)]
    private static extern bool SetupDiSetDeviceRegistryProperty(
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData,
        UInt32 Property,
        byte[] PropertyBuffer,
        UInt32 PropertyBufferSize);

    [DllImport("setupapi.dll", SetLastError=true)]
    private static extern bool SetupDiCallClassInstaller(
        UInt32 InstallFunction,
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData);

    [DllImport("setupapi.dll", SetLastError=true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    [DllImport("newdev.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool UpdateDriverForPlugAndPlayDevices(
        IntPtr hwndParent,
        string HardwareId,
        string FullInfPath,
        UInt32 InstallFlags,
        out bool RebootRequired);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static void EnsureRootDevice(string hardwareId, string description) {
        Guid systemClassGuid = new Guid("4d36e97d-e325-11ce-bfc1-08002be10318");
        IntPtr infoSet = SetupDiCreateDeviceInfoList(ref systemClassGuid, IntPtr.Zero);
        if (infoSet == INVALID_HANDLE_VALUE) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCreateDeviceInfoList failed");
        }

        try {
            SP_DEVINFO_DATA devInfo = new SP_DEVINFO_DATA();
            devInfo.cbSize = (UInt32)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
            bool created = SetupDiCreateDeviceInfo(
                infoSet,
                hardwareId,
                ref systemClassGuid,
                description,
                IntPtr.Zero,
                DICD_GENERATE_ID,
                ref devInfo);

            if (!created) {
                int error = Marshal.GetLastWin32Error();
                if (error == 183 || error == unchecked((int)0xE000020E)) {
                    return;
                }
                throw new Win32Exception(error, "SetupDiCreateDeviceInfo failed");
            }

            byte[] hardwareIdBytes = Encoding.Unicode.GetBytes(hardwareId + "\0\0");
            if (!SetupDiSetDeviceRegistryProperty(infoSet, ref devInfo, SPDRP_HARDWAREID, hardwareIdBytes, (UInt32)hardwareIdBytes.Length)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiSetDeviceRegistryProperty(SPDRP_HARDWAREID) failed");
            }

            if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, infoSet, ref devInfo)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed");
            }
        } finally {
            SetupDiDestroyDeviceInfoList(infoSet);
        }
    }

    public static bool UpdateDriver(string hardwareId, string infPath) {
        bool rebootRequired;
        if (!UpdateDriverForPlugAndPlayDevices(IntPtr.Zero, hardwareId, infPath, INSTALLFLAG_FORCE, out rebootRequired)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateDriverForPlugAndPlayDevices failed");
        }
        return rebootRequired;
    }

    public static void ProbeDevice(string devicePath) {
        IntPtr handle = CreateFileW(devicePath, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle == INVALID_HANDLE_VALUE) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not open " + devicePath);
        }
        CloseHandle(handle);
    }
}
"@
}

function Stop-TrustAgentServices {
    foreach ($name in @("TrustAgent", $serviceName)) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne "Stopped") {
            Write-Step "Stopping service $name"
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
        }
    }
}

function Remove-StaleWfpDevices {
    $staleDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.Service -eq $serviceName -or
        $_.FriendlyName -eq $deviceDescription -or
        $_.InstanceId -like "ROOT\TRUSTAGENTWFP\*" -or
        ($_.InstanceId -like "ROOT\SYSTEM\*" -and $_.Service -eq $serviceName)
    })
    foreach ($device in $staleDevices) {
        Write-Step "Removing stale WFP device $($device.InstanceId)"
        & pnputil.exe /remove-device "$($device.InstanceId)" | Out-Host
    }
}

function Start-WfpService {
    $driverService = Get-Service -Name $serviceName -ErrorAction Stop
    if ($driverService.Status -ne "Running") {
        Write-Step "Starting service $serviceName"
        Start-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus("Running", [TimeSpan]::FromSeconds(20))
    }
}

function Install-WfpDriver {
    if (Test-Path -LiteralPath $devconPath) {
        Write-Step "Installing driver with devcon"
        $driverDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.Service -eq $serviceName -or
            $_.FriendlyName -eq $deviceDescription -or
            $_.InstanceId -like "ROOT\TRUSTAGENTWFP\*" -or
            ($_.InstanceId -like "ROOT\SYSTEM\*" -and $_.Service -eq $serviceName)
        })
        $operation = if ($driverDevices.Count -eq 0) { "install" } else { "update" }
        $output = & $devconPath $operation $infPath $deviceHardwareId 2>&1
        $exitCode = $LASTEXITCODE
        $joinedOutput = $output -join "`n"
        $joinedOutput | Write-Host
        if ($exitCode -eq 0) {
            return $false
        }
        if ($exitCode -eq 1 -and $joinedOutput -match "(?i)(reboot|restart|success|installed)") {
            return $true
        }
        if ($exitCode -ne 0) {
            throw "devcon $operation failed with exit code $exitCode. Output: $($output -join "`n")"
        }
    }

    Write-Step "Installing driver with SetupAPI"
    [TrustAgentWfpInstaller]::EnsureRootDevice($deviceHardwareId, $deviceDescription)
    return [TrustAgentWfpInstaller]::UpdateDriver($deviceHardwareId, $infPath)
}

$transcriptStarted = $false
$scriptExitCode = 0
try {
    Start-Transcript -Path $logPath -Force | Out-Null
    $transcriptStarted = $true

    Assert-Admin
    Assert-DriverPackage

    if (Test-Path -LiteralPath $rebootMarkerPath) {
        Remove-Item -LiteralPath $rebootMarkerPath -Force
    }

    $requiresTestSigning = Test-DriverPackageUsesTestCertificate
    $rebootPending = $false
    if ($requiresTestSigning -and -not (Test-WindowsTestSigning)) {
        if (Test-SecureBootEnabled) {
            throw "TrustAgent WFP uses a test-signed driver. Disable Secure Boot before enabling Windows test-signing on this test machine."
        }
        Enable-WindowsTestSigning
        Write-Warning "TrustAgent enabled Windows test-signing. Reboot Windows, then run TrustAgent.exe again."
        $rebootPending = $true
    }

    if (-not $rebootPending) {
        Write-Step "Trusting driver certificate"
        Add-TrustAgentDriverCertificate
        Add-SetupApiHelper
        Stop-TrustAgentServices
        Remove-StaleWfpDevices

        $rebootRequired = Install-WfpDriver
        if ($rebootRequired) {
            "Windows requested a reboot after TrustAgent WFP driver installation." |
                Set-Content -LiteralPath $rebootMarkerPath -Encoding UTF8
            Write-Warning "Windows requested a reboot after TrustAgent WFP driver installation."
            $rebootPending = $true
        }
    }

    if (-not $rebootPending) {
        Start-WfpService
        Write-Step "Validating $devicePath"
        [TrustAgentWfpInstaller]::ProbeDevice($devicePath)
        Write-Step "Driver installation completed"
    }
} catch {
    Write-Error $_
    $scriptExitCode = 1
} finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
}

exit $scriptExitCode
