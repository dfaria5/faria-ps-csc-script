## Faria Powershell Custom Setup Config Script [WIP]
Simple run powershell custom config script for Windows 10 and 11 that cleans and adjusts some windows settings and apps for new installs.

## Script
Here's what the current script available will do.
### Supported Windows Versions
- Windows 11 (Tested Win Version: 25H2 *latest version*)
- Windows 10 (Tested Win Version: 22H2 *latest version*)

### Versions
|  | Full Clean | Essential | Personal Rig |
| --- | --- | --- | --- |
| Uninstall Bloat | Yes :heavy_check_mark: | Partially :grey_exclamation: (MS Store and Xbox App remain) | Partially :grey_exclamation: (*same as Essential*) |
| Disable Microsoft Telemetry | Yes :heavy_check_mark: | Yes :heavy_check_mark: | Yes :heavy_check_mark: |
| Optimize Services | Yes :heavy_check_mark: | Yes :heavy_check_mark: (Services from MS Store and Xbox App are set to Manual) | Yes :heavy_check_mark: (*same as Essential*) |
| Custom Set Preferences | Yes :heavy_check_mark: | Yes :heavy_check_mark: | Yes :heavy_check_mark: |
| Installs Apps | No :x: | Yes :heavy_check_mark: (see details bellow) | Yes :heavy_check_mark: (see details bellow) |

See full details about each version [**here**](script/versions.md).

## Usage
1. Open Powershell as admin. (if you dont, the script will relaunch as admin)
2. Paste and run the comamnd bellow or you can download the script.

**Essential**
```
irm "https://raw.githubusercontent.com/dfaria5/faria-ps-csc-script/refs/heads/main/script/FARIA_PS_CSC_SCRIPT_ESSENTIAL.ps1" | iex
```
