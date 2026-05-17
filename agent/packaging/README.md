# Windows Enterprise Deployment

This folder packages ZTNA Agent for enterprise-style deployment with a Windows
setup wizard built with Inno Setup.

## Package Build

```powershell
.\packaging\windows\build-enterprise-package.ps1
```

The output folder contains:

```text
agent/build/
```

- `ztna-agent.exe` - runtime binary used by SCM and the user tray
- `ztna-agent-installer.exe` - service setup binary
- `config.json` - optional policy/config file when present
- `ZTNA-Agent-Setup.exe` - custom Windows setup wizard

The setup wizard lets the user choose the install folder, choose whether the
agent starts at sign-in, and choose whether to launch the UI after installation.

To generate `ZTNA-Agent-Setup.exe`, install Inno Setup 6 so `ISCC.exe` is
available on `PATH` or under `%ProgramFiles(x86)%\Inno Setup 6`.

## Setup

Run:

```powershell
.\ZTNA-Agent-Setup.exe
```

The setup requires administrator approval, copies binaries and `config.json` to
the selected install folder, installs the `ZTNAAgent` LocalSystem service,
optionally creates the HKLM Run entry, and optionally launches the Wails UI.

## Detection Rule

Recommended deployment detection:

- Registry key: `HKLM\Software\ZTNA\Agent`
- Value: `RuntimePath`
- Expected file exists: `%ProgramFiles%\ZTNA Agent\ztna-agent.exe`

The runtime agent has no public CLI. Installer/deployment owns installation;
the GUI owns user enrollment and dashboard display.
