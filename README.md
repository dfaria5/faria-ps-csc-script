## Faria Powershell Custom Setup Config Script
Simple run powershell custom config script for Windows 10 and 11 that cleans and adjusts some windows settings and apps for new installs.

## Script
Here's what the current script available will do.
### Supported Windows Versions
- Windows 11
- Windows 10

### Current Version
- Uninstall bloat windows apps. (with the exception of Microsoft Store and Xbox App)
- Disables Microsoft telemetry and optimises Windows services.
- Other custom set Windows preferences. (Desktop, File Explorer, Taskbar, Power Plan, Legacy Components)
- Installs programs.
  - Microsoft Distributions (Visual C++, .NET Core, .NET Runtime, Windows Desktop Runtime)
  - Apple QuickTime (for old apps using its api/code/features)
  - 7zip
  - Java
  - Notepad++
  - VLC Media Player

### More Versions soon.

## Usage
1. Open Powershell as admin. (if you dont, the script will relaunch as admin)
2. Paste and run the comamnd bellow or you can download the script.

Powershell command:
```
irm "https://raw.githubusercontent.com/dfaria5/faria-ps-csc-script/refs/heads/main/FARIA_PS_CSC_SCRIPT.ps1" | iex
```
