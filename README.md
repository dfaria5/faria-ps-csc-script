## Faria Powershell Custom Setup Config Script [WIP]
Simple run powershell custom config script for Windows 10 and 11 that cleans and adjusts some windows settings and apps for new installs.

## Script
Here's what the current script available will do.
### Supported Windows Versions
- Windows 11
- Windows 10

### Versions (Only Essential available for now)
|  | Full Clean | Essential | Personal Rig |
| --- | --- | --- | --- |
| Uninstall Bloat | Yes :heavy_check_mark: | Partially :grey_exclamation: (MS Store and Xbox App remain) | Partially :grey_exclamation: (*same as Essential*) |
| Disable Microsoft Telemetry | Yes :heavy_check_mark: | Yes :heavy_check_mark: | Yes :heavy_check_mark: |
| Optimize Services | Yes :heavy_check_mark: | Partially :grey_exclamation: (Services from MS Store and Xbox App are set to Manual) | Partially :grey_exclamation: (*same as Essential*) |
| Custom Set Preferences | Yes :heavy_check_mark: | Yes :heavy_check_mark: | Yes :heavy_check_mark: |
| Installs Apps | No :x: | Yes :heavy_check_mark: (MS Distributions, QuickTime, 7zip, Java, Notepad++, VLC) | Yes :heavy_check_mark: (*same as Essential*, plus Firefox, Steam, Teamspeak, Discord) |

See full details about each version **here**.

## Usage
1. Open Powershell as admin. (if you dont, the script will relaunch as admin)
2. Paste and run the comamnd bellow or you can download the script.

**Powershell Command**
```
irm "https://dfaria5.github.io/files/scripts/FARIA_PS_CSC_SCRIPT.ps1" | iex
```
(if the command above doesnt work, try this one instead)
```
irm "https://raw.githubusercontent.com/dfaria5/faria-ps-csc-script/refs/heads/main/FARIA_PS_CSC_SCRIPT.ps1" | iex
```
