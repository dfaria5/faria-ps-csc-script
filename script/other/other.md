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
