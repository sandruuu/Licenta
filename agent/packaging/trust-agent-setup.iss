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
OutputBaseFilename=TrustAgent
SetupIconFile={#SourceDir}\trust-agent.ico
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
Source: "{#SourceDir}\config.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\pdp-ca.pem"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\install-service.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "{#SourceDir}\Test-AgentConfig.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "{#SourceDir}\wfp-driver\*"; DestDir: "{app}\wfp-driver"; Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TrustAgent"; ValueData: """{app}\trust-agent.exe"""; Tasks: startatlogin; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\TrustAgent\Agent"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\TrustAgent\Agent"; ValueType: string; ValueName: "RuntimePath"; ValueData: "{app}\trust-agent.exe"; Flags: uninsdeletekey

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\wfp-driver\install-wfp-driver.ps1"" -DriverDir ""{app}\wfp-driver"""; WorkingDir: "{app}"; StatusMsg: "Installing the TrustAgent WFP traffic driver..."; Flags: runhidden waituntilterminated
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{tmp}\install-service.ps1"" -RuntimePath ""{app}\trust-agent.exe"""; WorkingDir: "{app}"; StatusMsg: "Installing and starting the TrustAgent service..."; Flags: runhidden waituntilterminated; Check: CanStartTrustAgent
Filename: "{app}\trust-agent.exe"; WorkingDir: "{app}"; Description: "Launch TrustAgent"; Flags: nowait postinstall skipifsilent; Check: CanStartTrustAgent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C sc stop TrustAgent >nul 2>nul & sc delete TrustAgent >nul 2>nul"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTrustAgentService"
Filename: "{cmd}"; Parameters: "/C sc stop trustagent_wfp >nul 2>nul & sc delete trustagent_wfp >nul 2>nul"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTrustAgentWfpService"

[Code]
function WfpRebootRequired: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\wfp-driver\reboot-required.txt'));
end;

function CanStartTrustAgent: Boolean;
begin
  Result := not WfpRebootRequired;
end;

function NeedRestart(): Boolean;
begin
  Result := WfpRebootRequired;
end;

procedure RegisterTrustAgentSetupResume;
var
  ResumeCommand: String;
begin
  ResumeCommand := '"' + ExpandConstant('{srcexe}') + '" /SILENT /SUPPRESSMSGBOXES /NORESTART';
  RegWriteStringValue(
    HKLM,
    'Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'TrustAgentResumeSetup',
    ResumeCommand);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WfpRebootRequired then
  begin
    RegisterTrustAgentSetupResume;
  end;
end;
