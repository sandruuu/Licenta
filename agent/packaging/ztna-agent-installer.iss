#define AppName "ZTNA Agent"
#define AppVersion "1.0.0"
#ifndef SourceDir
#define SourceDir "..\..\build"
#endif

[Setup]
AppId={{8E3A6B0B-1F71-4C53-9E3C-7F61B8E3276D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=ZTNA
DefaultDirName={autopf}\ZTNA Agent
DefaultGroupName=ZTNA Agent
DisableProgramGroupPage=yes
OutputBaseFilename=ZTNA-Agent-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\ztna-agent.exe
SetupLogging=yes
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "startatlogin"; Description: "Start ZTNA Agent when I sign in"; GroupDescription: "Startup options:"; Flags: checkedonce

[Files]
Source: "{#SourceDir}\ztna-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\ztna-agent-installer.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\config.json"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ZTNA Agent"; ValueData: """{app}\ztna-agent.exe"""; Tasks: startatlogin; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\ZTNA\Agent"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\ZTNA\Agent"; ValueType: string; ValueName: "RuntimePath"; ValueData: "{app}\ztna-agent.exe"; Flags: uninsdeletekey

[Run]
Filename: "{app}\ztna-agent-installer.exe"; WorkingDir: "{app}"; StatusMsg: "Installing and starting the ZTNA Agent service..."; Flags: runhidden waituntilterminated
Filename: "{app}\ztna-agent.exe"; WorkingDir: "{app}"; Description: "Launch ZTNA Agent"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C sc stop ZTNAAgent >nul 2>nul & sc delete ZTNAAgent >nul 2>nul"; Flags: runhidden waituntilterminated
