## Faria Powershell Custom Setup Config Script - All Version Details [WIP]
This text file includes all the details and configurations about each version of the script.

### All Versions
- Uninstall bloat windows apps. (Note: does not uninstall Microsoft Store and Xbox App)
  - Media Player.
  - Copilot.
  - Bing.
  - Clipchamp.
  - Teams.
  - News.
  - Weather.
  - Outlook.
  - OneDrive.
  - Solitaire.
  - Sticky Notes.
  - Power Automate.
  - Cortana.
  - To Do.
  - Phone Link.
- Disables Microsoft telemetry and optimises Windows services.
- Other custom set Windows preferences.
  - Desktop preferences.
    - Show classic desktop icons.
    - Show Windows Build/Version at the bottom right corner. (Optional, will ask User)
  - File Explorer preferences.
    - Show hidden files.
    - Show file extension.
  - Taskbar preferences.
    - Search Bar to Icon.
    - Aligment to the left. (Windows 11 only)
  - Power options.
    - Power plan set to Ultimate Performance.
    - Timeouts set to never.
    - Disable hard disk turning off by setting the value to 0.
  - Enables legacy component DirectPlay.
  - Show Verbose Status (Optional, will ask User - Display more additional information when booting or shutting down and logging in or logging out Windows)


### Essential Version (Specific changes)
- Other custom set Windows preferences.
  - Desktop preferences.
    - Set wallpaper mode to Picture.
    - Set default Windows wallpaper.
  - Advanced system settings, Performance Settings.
    - Show thumbnails instead of icons.
    - Show translucent selection rectangle.
    - Show window contents while dragging.
    - Smooth edges of screen fonts.
    - Use drop shadows for icon labels on the desktop.
- Installs programs. (Optional, will ask User)
  - Microsoft Distributions (Visual C++, .NET Core, .NET Runtime, Windows Desktop Runtime)
  - Powershell 7
  - Apple QuickTime (for old apps using its api/code/features)
  - 7zip
  - Java
  - Notepad++
  - VLC Media Player

### Minimal Version (Specific changes)
- Uninstall Microsft Store and Xbox App (Optional, will ask User - **WARNING**: After you uninstall this they cannot be installed again. This option should be used for servers and other such as pc services, or you really dont plan to use MS Store and Xbox App)
- Other custom set Windows preferences.
  - Desktop preferences.
    - Set wallpaper mode to Solid Color.
    - Set Solid Color to Dark Gray (Color RBG value: 15, 15, 15).
  - Advanced system settings, Performance Settings.
    - None selected/checked.
