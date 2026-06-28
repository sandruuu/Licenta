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
DisableWelcomePage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\trust-agent.exe
SetupLogging=yes
CloseApplications=no
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\trust-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\config.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\pdp-ca.pem"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\prepare-install.ps1"; Flags: dontcopy
Source: "{#SourceDir}\install-service.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "{#SourceDir}\Test-AgentConfig.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "{#SourceDir}\uninstall-cleanup.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\wfp-driver\*"; DestDir: "{app}\wfp-driver"; Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
Root: HKLM; Subkey: "Software\TrustAgent\Agent"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\TrustAgent\Agent"; ValueType: string; ValueName: "RuntimePath"; ValueData: "{app}\trust-agent.exe"; Flags: uninsdeletekey

[Icons]
Name: "{group}\TrustAgent"; Filename: "{app}\trust-agent.exe"; WorkingDir: "{app}"
Name: "{commondesktop}\TrustAgent"; Filename: "{app}\trust-agent.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\wfp-driver\install-wfp-driver.ps1"" -DriverDir ""{app}\wfp-driver"""; WorkingDir: "{app}"; StatusMsg: "Installing the TrustAgent WFP traffic driver..."; Flags: runhidden waituntilterminated
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{tmp}\install-service.ps1"" -RuntimePath ""{app}\trust-agent.exe"""; WorkingDir: "{app}"; StatusMsg: "Installing and starting the TrustAgent service..."; Flags: runhidden waituntilterminated
Filename: "{app}\trust-agent.exe"; WorkingDir: "{app}"; Description: "Launch TrustAgent"; Flags: nowait postinstall skipifsilent; Check: CanStartTrustAgent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall-cleanup.ps1"" -InstallDir ""{app}"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "CleanTrustAgentInstall"

[Code]
var
  ExistingInstallDir: String;
  MaintenancePage: TInputOptionWizardPage;
  ExitAfterMaintenanceUninstall: Boolean;

function HasSetupSwitch(SwitchName: String): Boolean;
var
  I: Integer;
  Value: String;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    Value := ParamStr(I);
    if (CompareText(Value, '/' + SwitchName) = 0) or
       (CompareText(Value, '-' + SwitchName) = 0) or
       (CompareText(Value, '--' + SwitchName) = 0) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function UseExistingInstallDir(var InstallDir: String; Candidate: String): Boolean;
begin
  Result := False;
  Candidate := RemoveBackslashUnlessRoot(Trim(Candidate));
  if (Candidate <> '') and DirExists(Candidate) then
  begin
    InstallDir := Candidate;
    Log('Detected existing TrustAgent installation directory: ' + InstallDir);
    Result := True;
  end;
end;

function QueryInstallDirValue(var InstallDir: String; RootKey: Integer; Subkey: String; ValueName: String): Boolean;
var
  Candidate: String;
begin
  Result := RegQueryStringValue(RootKey, Subkey, ValueName, Candidate) and UseExistingInstallDir(InstallDir, Candidate);
end;

function GetInstalledInstallDir(var InstallDir: String): Boolean;
begin
  Result := False;
  InstallDir := '';

  if QueryInstallDirValue(InstallDir, HKLM, 'Software\TrustAgent\Agent', 'InstallDir') then
  begin
    Result := True;
    Exit;
  end;

  if QueryInstallDirValue(InstallDir, HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8E3A6B0B-1F71-4C53-9E3C-7F61B8E3276D}_is1', 'InstallLocation') then
  begin
    Result := True;
    Exit;
  end;
end;

function RunInstalledUninstaller(SilentUninstall: Boolean): Boolean;
var
  UninstallerPath: String;
  InstallDir: String;
  Params: String;
  ExitCode: Integer;
begin
  Result := False;
  if not GetInstalledInstallDir(InstallDir) then
  begin
    if not WizardSilent then
    begin
      MsgBox('TrustAgent is not installed.', mbInformation, MB_OK);
    end;
    Exit;
  end;

  UninstallerPath := AddBackslash(InstallDir) + 'unins000.exe';
  if not FileExists(UninstallerPath) then
  begin
    if not WizardSilent then
    begin
      MsgBox('TrustAgent is installed, but its uninstaller could not be found: ' + UninstallerPath, mbError, MB_OK);
    end;
    Exit;
  end;

  Params := '';
  if HasSetupSwitch('verysilent') then
  begin
    Params := '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART';
  end
  else if SilentUninstall or WizardSilent or HasSetupSwitch('silent') then
  begin
    Params := '/SILENT /SUPPRESSMSGBOXES /NORESTART';
  end;

  if Exec(UninstallerPath, Params, '', SW_SHOWNORMAL, ewWaitUntilTerminated, ExitCode) then
  begin
    Result := ExitCode = 0;
    if (ExitCode <> 0) and (not WizardSilent) then
    begin
      MsgBox('TrustAgent uninstall finished with exit code ' + IntToStr(ExitCode) + '.', mbError, MB_OK);
    end;
  end
  else if not WizardSilent then
  begin
    MsgBox('TrustAgent uninstaller could not be started.', mbError, MB_OK);
  end;
end;

function InitializeSetup: Boolean;
begin
  Result := True;
  ExistingInstallDir := '';
  if HasSetupSwitch('uninstall') or HasSetupSwitch('remove') then
  begin
    RunInstalledUninstaller(False);
    Result := False;
    Exit;
  end;
  if not WizardSilent then
  begin
    GetInstalledInstallDir(ExistingInstallDir);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  InstallDir: String;
  ExitCode: Integer;
begin
  Result := '';
  InstallDir := '';
  GetInstalledInstallDir(InstallDir);
  if InstallDir <> '' then
  begin
    ExtractTemporaryFile('prepare-install.ps1');
    if not Exec(
      'powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\prepare-install.ps1') + '" -InstallDir "' + InstallDir + '"',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ExitCode) then
    begin
      Result := 'TrustAgent could not stop the existing installation before update.';
    end;
  end;
end;

procedure InitializeWizard;
begin
  ExistingInstallDir := '';
  GetInstalledInstallDir(ExistingInstallDir);

  if ExistingInstallDir <> '' then
  begin
    MaintenancePage := CreateInputOptionPage(
      wpWelcome,
      'Existing TrustAgent installation detected',
      'Choose how Setup should continue.',
      'TrustAgent is already installed in:' + #13#10 +
      ExistingInstallDir + #13#10#13#10 +
      'Select the action you want to perform:',
      True,
      False);
    MaintenancePage.Add('Reinstall or update TrustAgent');
    MaintenancePage.Add('Uninstall TrustAgent');
    MaintenancePage.Values[0] := True;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (MaintenancePage <> nil) and (CurPageID = MaintenancePage.ID) and MaintenancePage.Values[1] then
  begin
    if RunInstalledUninstaller(True) then
    begin
      MsgBox('TrustAgent was uninstalled.', mbInformation, MB_OK);
      ExitAfterMaintenanceUninstall := True;
      Result := False;
      WizardForm.Close;
    end
    else
    begin
      Result := False;
    end;
  end;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if ExitAfterMaintenanceUninstall then
  begin
    Confirm := False;
  end;
end;

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
    if not WizardSilent then
    begin
      MsgBox(
        'TrustAgent needs a Windows restart before the local traffic protection driver can be loaded. ' +
        'The TrustAgent service is installed now, but local traffic protection will become available after setup resumes following restart.',
        mbInformation,
        MB_OK);
    end;
  end;
end;
