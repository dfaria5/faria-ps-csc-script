> [!NOTE]
> This is just my own simple script i use for new installs to put my own settings on windows. And since there is a command for using it with internet, might as well make it public.

# Faria Powershell Utility Setup Config Script
This is a simple run powershell script for Windows 10 and 11 that cleans and adjusts some windows settings and apps for new installs for better performance. There are various versions for each porpuse intended whatever is a normal pc, server, etc.
Here lists what each version will do.
### Version 2 (Recommended)
- Uninstall bloat windows apps. (with the exception of Microsoft Store and Xbox App)
- Set Ultimate Performance power plan.
- Disables Microsoft telemetry and unnecessary services that waste cpu usage.
- Other custom set Windows preferences. (Classic Desktop Icons, File Explorer Settings, Disable News/Weather Widget)

## How to use
1. Open Powershell as admin. (if you dont, the script will relaunch as admin)
2. Paste and run the comamnd bellow or you can download the script.

Command:
```
irm "<link>" | iex
```

![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/dfaria5/faria-ps-utilsetupconf-script/latest/total?style=for-the-badge)
