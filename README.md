## Faria Powershell Custom Setup Config Script [WIP]
Simple run powershell custom config script for Windows 10 and 11 that cleans and adjusts some windows settings and apps for new installs.

## Script
### Supported Windows Versions
- Windows 11 (Last Tested Win Version: 25H2)
- Windows 10 (Last Tested Win Version: 22H2)

### Versions
See full details about each version [**here**](script/versions.md).

## Usage
Update Windows before running this script.
1. Open Powershell as admin. (if you dont, the script will relaunch as admin)
2. Paste and run the comamnd bellow or you can download the script.

**Essential** (*Recommended for usual/personal PCs*)
```
irm "https://raw.githubusercontent.com/dfaria5/faria-ps-csc-script/refs/heads/main/script/FARIA_PS_CSC_SCRIPT_ESSENTIAL.ps1" | iex
```
**Minimal** (*Recommended for low end PCs, Services PCs, Servers*)
```
irm "https://raw.githubusercontent.com/dfaria5/faria-ps-csc-script/refs/heads/main/script/FARIA_PS_CSC_SCRIPT_MINIMAL.ps1" | iex
```

## Other Specific Usage
1. Open Powershell as admin. (if you dont, the script will relaunch as admin)
2. Paste and run the comamnd bellow or you can download the script.

**Optimise Windows Only** (*Only disables Microsoft telementry, optimises Services, Power Plan set to Ultimate Performance, disable Power Managment for Network adapters and sets Performance Preset in Advanced System Settings*)
```
irm "https://raw.githubusercontent.com/dfaria5/faria-ps-csc-script/refs/heads/main/script/other/FARIA_PS_CSC_SCRIPT_ONLYOPTIMISEPC.ps1" | iex
```
**Optimise Windows Only - 2** (*Same as the first one but doesnt disable Microsoft telementry*)
```
irm "https://raw.githubusercontent.com/dfaria5/faria-ps-csc-script/refs/heads/main/script/other/FARIA_PS_CSC_SCRIPT_ONLYOPTIMISEPC_NOMST.ps1" | iex
```
**Optimise Services Only** (*As it says only optmises Services*)
```
irm "https://raw.githubusercontent.com/dfaria5/faria-ps-csc-script/refs/heads/main/script/other/FARIA_PS_CSC_SCRIPT_ONLYOPTIMISESERVICES.ps1" | iex
```
