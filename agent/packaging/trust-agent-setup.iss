#define AppName "TrustAgent"
#define AppVersion "1.0.0"
#ifndef SourceDir
#define SourceDir "..\..\build"
#endif

[Setup]
AppId={{8E3A6B0B-1F71-4C53-9E3C-7F61B8E3276D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=TrustAgent
DefaultDirName={autopf}\TrustAgent
DefaultGroupName=TrustAgent
DisableProgramGroupPage=yes
OutputBaseFilename=TrustAgent-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\trust-agent.exe
SetupLogging=yes
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "startatlogin"; Description: "Start TrustAgent when I sign in"; GroupDescription: "Startup options:"; Flags: checkedonce

[Files]
Source: "{#SourceDir}\trust-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\config.json"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\install-service.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TrustAgent"; ValueData: """{app}\trust-agent.exe"""; Tasks: startatlogin; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\TrustAgent\Agent"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\TrustAgent\Agent"; ValueType: string; ValueName: "RuntimePath"; ValueData: "{app}\trust-agent.exe"; Flags: uninsdeletekey

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{tmp}\install-service.ps1"" -RuntimePath ""{app}\trust-agent.exe"""; WorkingDir: "{app}"; StatusMsg: "Installing and starting the TrustAgent service..."; Flags: runhidden waituntilterminated
Filename: "{app}\trust-agent.exe"; WorkingDir: "{app}"; Description: "Launch TrustAgent"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C sc stop TrustAgent >nul 2>nul & sc delete TrustAgent >nul 2>nul"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTrustAgentService"
