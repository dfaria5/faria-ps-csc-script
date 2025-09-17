> [!NOTE]
> This is just my own simple script i use for new installs to put my own settings on windows. And since there is a command for using it with internet, might as well make it public.

> [!WARNING]
> **The current script was worked primarily with the EU versions of Windows**

# Faria Powershell Custom Setup Config Script :large_blue_diamond::computer:
This is a simple run powershell script for Windows 10 and 11 that cleans and adjusts some windows settings and apps for new installs for better performance.

## Script
Here's what the current script available will do.
### Supported Windows Versions
- Windows 11
- Windows 10

### Current Version
- Uninstall bloat windows apps. (with the exception of Microsoft Store and Xbox App)
- Disables Microsoft telemetry and optimises Windows services.
- Other custom set Windows preferences. (Start Menu, Desktop, File Explorer, Taskbar, Power Plan)
- Installs essential apps.
  - 7zip
  - Java
  - Notepad++
  - VLC Media Player
  - MediaInfoGUI

### More Versions soon.

## :zap: Usage
1. Open Powershell as admin. (if you dont, the script will relaunch as admin)
2. Paste and run the comamnd bellow or you can download the script.

Powershell command:
```
irm "<link>" | iex
```
Manual Download:

![Download Lastest Version](https://img.shields.io/github/downloads/dfaria5/faria-ps-utilsetupconf-script/latest/total?style=for-the-badge)

**Note:** If any error ocours blocking the script, use these two commands.
```
Set-ExecutionPolicy RemoteSigned -Scope Process
```
```
Unblock-File -Path "<location of the script file downloaded>"
```
