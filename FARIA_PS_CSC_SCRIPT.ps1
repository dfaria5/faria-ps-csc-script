<#
    Faria Powershell Custom Setup Config Script Win 10/11
    Created by FARIA (github.com/dfaria5)
#>

# Relaunch as Admin if not already
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $IsAdmin) {
    Write-Host "Script not running as Administrator. Relaunching with elevated privileges..." -ForegroundColor Yellow

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Verb = "runas"

    if ($PSCommandPath) {
        # Normal script file
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    } else {
        # Likely running via `irm ... | iex`
        $scriptContent = $MyInvocation.MyCommand.Definition
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptContent))
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
    }

    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } catch {
        Write-Host "User declined the UAC prompt. Exiting..." -ForegroundColor Red
    }
    exit
}

# ========================
# CONFIGURATION
# ========================
$removeApps						= $true
$disableTelemetry				= $true
$manageServices  				= $true
$setPowerPlanUltimate     		= $true
$tweakGeneralExplorerAndOther	= $true
$installapps					= $false	# Disabled for now, testing other stuff.

Write-Host "`n# ============================================================" -ForegroundColor Green
Write-Host "# Faria Powershell Custom Setup Config Script Win 10/11" -ForegroundColor Green
Write-Host "# Created by FARIA (https://github.com/dfaria5)" -ForegroundColor Green
Write-Host "# ============================================================`n" -ForegroundColor Green
Write-Host "Status: Script excuted and started. Recommended not to use your desktop while the script is running." -ForegroundColor Green
$ErrorActionPreference = "SilentlyContinue"

# ========================
# 1. REMOVE UNWANTED/BLOAT APPS
# ========================
if ($removeApps) {
    Write-Host "Status: Uninstalling unwanted/bloat apps..." -ForegroundColor Cyan

    $apps = @(
        "Microsoft.3DBuilder",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.MicrosoftSolitaireCollection",
		"Microsoft.BingSearch"
		"Microsoft.549981C3F5F10",		# Part of Cortana
        "Microsoft.Windows.Cortana",
		"Microsoft.Copilot",
        "Microsoft.BingNews",
		"Microsoft.BingWeather",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.MicrosoftOfficeHub",
		"Microsoft.Tips",
		"QuickAssist",
		"MicrosoftCorporationII.QuickAssist",
		"Microsoft.PowerAutomateDesktop",
        "Microsoft.OneConnect",
        "Microsoft.People",
        "Microsoft.MicrosoftTeams",
		"MicrosoftTeams"
        "Microsoft.MicrosoftTeamsForSurfaceHub",
		"Microsoft.LinkedIn",
		"7EE7776C.LinkedInforWindows",
        "Microsoft.SkypeApp",
        "Microsoft.Todos",
        "Microsoft.WindowsMaps",
        "Microsoft.YourPhone",
		"Microsoft.Windows.DevHome",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.MicrosoftWhiteboard",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.ClipChamp",
        "Microsoft.Office.OneNote",
        "Microsoft.Office.Desktop",
        "Microsoft.MSPaint",              # Not to be confused with the normal Paint app, this is Paint 3D
        "Microsoft.MixedReality.Portal",
        "microsoft.windowscommunicationsapps",
		"Microsoft.OutlookForWindows",
		"Clipchamp.Clipchamp"
    )

    foreach ($app in $apps) {
        Write-Host "Status: Removing $app..." -ForegroundColor Yellow

        # Remove provisioned (for new users)
		Get-AppxProvisionedPackage -Online |
			Where-Object { $_.DisplayName -eq $app } |
			Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null

		# Remove for current user
		Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    }

	# Remove any leftovers.
	Write-Host "Status: Removing any leftovers from bloat apps..." -ForegroundColor Yellow
	# Microsoft Teams
    Get-AppxPackage -AllUsers -Name "MSTeams" -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers -Name "MicrosoftTeams" -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers -Name "MicrosoftTeamsIntegration" -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Teams*" } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    $teamsMachine = "$env:ProgramFiles (x86)\Teams Installer"
    if (Test-Path $teamsMachine) {
        Remove-Item $teamsMachine -Recurse -Force -ErrorAction SilentlyContinue
    }
	# Linkedin
	Get-AppxPackage -AllUsers -Name "LinkedInforWindows" -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*LinkedIn*" } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

	# OneDrive
	Write-Host "Status: Checking for OneDrive installation..." -ForegroundColor Yellow
	function Get-OneDriveUninstallInfo {
		$keys = @(
			"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
			"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
		)
		foreach ($k in $keys) {
			$entry = Get-ItemProperty $k -ErrorAction SilentlyContinue |
					 Where-Object { $_.DisplayName -eq "Microsoft OneDrive" } |
					 Select-Object -First 1
			if ($entry) { return $entry }
		}
		return $null
	}

	function Test-OneDriveInstalled {
		$reg = Get-OneDriveUninstallInfo
		if ($reg) { return $true }

		$appx = Get-AppxPackage -AllUsers -Name "Microsoft.OneDrive" -ErrorAction SilentlyContinue
		if (-not $appx) {
			$appx = Get-AppxPackage -AllUsers -Name "Microsoft.OneDriveSync" -ErrorAction SilentlyContinue
		}
		return [bool]$appx
	}

	function Invoke-OneDriveUninstall {
		$entry = Get-OneDriveUninstallInfo
		if ($entry -and $entry.UninstallString) {
			Write-Host "Status: Uninstalling OneDrive..." -ForegroundColor Yellow

			$cmdLine = $entry.UninstallString
			if ($cmdLine -match 'msiexec') {
				Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmdLine" -Wait -NoNewWindow
			} else {
				$exe  = $cmdLine
				$args = ""
				if ($cmdLine -match '^\s*\"([^"]+)\"\s*(.*)$') { $exe=$matches[1]; $args=$matches[2] }
				elseif ($cmdLine -match '^\s*(\S+)\s+(.*)$')    { $exe=$matches[1]; $args=$matches[2] }
				Start-Process -FilePath $exe -ArgumentList $args -Wait -NoNewWindow
			}
			return
		}

		$oneDriveSetup = @(
			"$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
			"$env:SystemRoot\System32\OneDriveSetup.exe"
		) | Where-Object { Test-Path $_ -PathType Leaf }

		if ($oneDriveSetup) {
			Write-Host "Status: Uninstalling OneDrive..." -ForegroundColor Yellow
			taskkill /f /im OneDrive.exe > $null 2>&1
			foreach ($p in $oneDriveSetup) {
				Start-Process $p "/uninstall" -NoNewWindow -Wait
			}
		}
	}

    if (Test-OneDriveInstalled) {
        Invoke-OneDriveUninstall

        $folders = @(
            "$env:UserProfile\OneDrive",
            "$env:LocalAppData\Microsoft\OneDrive",
            "$env:ProgramData\Microsoft OneDrive"
        )
        foreach ($folder in $folders) {
            if (Test-Path $folder) {
                Remove-Item $folder -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        # Remove from Explorer sidebar (no policy that blocks reinstall) + Optional: prune scheduled tasks that relaunch it (doesn't block reinstall)
        Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskPath "\Microsoft\OneDrive\" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\OneDrive\" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

        Write-Host "Status: OneDrive uninstalled..." -ForegroundColor Yellow
    }
    else {
        Write-Host "Status: OneDrive is not installed. Skipping..." -ForegroundColor Yellow
    }
}

# ========================
# DISABLE TELEMETRY
# ========================
if ($disableTelemetry) {
    Write-Host "Status: Disabling Microsoft Telemetry & Cortana..." -ForegroundColor Cyan
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 -Type DWord
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Value 0
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0
}

# ========================
# OPTIMIZING SERVICES
# ========================
if ($manageServices) {
    Write-Host "Status: Optimizing services..." -ForegroundColor Cyan

    # Services set to manual (safe so the service will only start when it actually needs it)
	$manualServices = @(
		"SysMain",               		# Superfetch/Prefetch
		"TrkWks",                		# Distributed Link Tracking
		"TabletInputService",    		# Touch/pen input
		"DiagSvc",               		# Diagnostic Execution
		"wercplsupport",         		# Problem Reports
		"BTAGService",           		# Bluetooth Audio Gateway
		"BthAvctpSvc",           		# Bluetooth Audio/Video
		"bthserv",               		# Core Bluetooth
		"NgcCtnrSvc",            		# Microsoft Passport Container
		"NgcSvc",                		# Microsoft Passport
		"WpnService",            		# Windows Push Notifications
		"WpnUserService"         		# Notifications per-user
		"AxInstSV",     				# ActiveX Installer
		"BDESVC",       				# BitLocker Drive Encryption
		"tcsd",         				# Cellular Time (sometimes 'tzautoupdate')
		"CertPropSvc",  				# Certificate Propagation
		"CldFlt",       				# Cloud Backup/Restore
		"CDPUserSvc*",  				# Connected Devices Platform
		"PimIndexMaintenanceSvc*", 		# Contact Data
		"lfsvc",        				# Geolocation
		"SmsRouter",    				# SMS Router
		"Netlogon",     				# Netlogon (not in workgroup)
		"WpcMonSvc",    				# Parental Controls
		"SEMgrSvc",     				# Payments & NFC
		"PrintWorkflowUserSvc*", 		# Print Device Config
		"QWAVE",        				# Quality Windows Audio Video Experience
		"RmSvc",        				# Radio Management
		"RasAuto",      				# Remote Access Auto Connection
		"RasMan",       				# Remote Access Connection Manager
		"TermService",  				# Remote Desktop Services
		"SessionEnv",   				# RDS Config
		"UmRdpService", 				# RDS Redirector
		"seclogon",     				# Secondary Logon
		"SensorDataService",
		"SensrSvc",     				# Sensor Monitoring
		"SensorService",
		"LanmanServer",					# Server
		"shpamsvc",     				# Shared PC Account Manager
		"SCardSvr",     				# Smart Card
		"ScDeviceEnum", 				# Smart Card Device Enum
		"SCPolicySvc",  				# Smart Card Removal Policy
		"lmhosts",      				# TCP/IP NetBIOS Helper
		"TapiSrv",      				# Telephony
		"vds",          				# Virtual Disk
		"VSS",          				# Volume Shadow Copy
		"sdclt",        				# Windows Backup
		"WbioSrvc",     				# Biometric
		"FrameServer",  				# Camera Frame Server
		"Wcncsvc",      				# Windows Connect Now
		"stisvc",       				# WIA (Scanner service)
		"icssvc",       				# Mobile Hotspot
		"WinRM",        				# Windows Remote Management
		"WSearch",      				# Search Indexing
		"WorkFoldersSvc",
		"WwanSvc",       				# WWAN AutoConfig
		"XblAuthManager",
		"XblGameSave",
		"XboxGipSvc",
		"XboxNetApiSvc"
	)

	# Services set to disable (no need for these since they do nothing and they are just bloat and waste cpu usage)
	$disableServices = @(
		"DiagTrack",				# Connected User Experiences and Telemetry
		"dmwappushservice",     	# WAP Push Messaging
		"RetailDemo",   			# Retail Demo
		"WMPNetworkSvc",			# WMP Network Sharing
		"Fax",                   	# Fax service
		"MapsBroker",   			# Downloaded Maps Manager
		"MessagingService",      	# SMS Routing
		"PhoneSvc",     			# Phone Service
		"PrintNotify",           	# Printer Notifications
		"RemoteAccess",          	# Routing and Remote Access
		"RemoteRegistry", 			# Security risk
		"SharedAccess",          	# Internet Connection Sharing
		"Spooler",               	# Print Spooler
		"WalletService",			# Microsoft Wallet
		"wisvc"        				# Insider Service
	)

	# Apply Manual
	foreach ($svc in $manualServices) {
		try {
			Set-Service -Name $svc -StartupType Manual -ErrorAction Stop
			Write-Host "Status: Set $svc to Manual" -ForegroundColor Yellow
		} catch { Write-Warning "Could not change $svc ($_)" }
	}

	# Apply Disabled
	foreach ($svc in $disableServices) {
		try {
			Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
			Write-Host "Status: Set $svc to Disabled" -ForegroundColor Yellow
		} catch { Write-Warning "Could not change $svc ($_)" }
	}
}

# ========================
# POWER PLAN: ULTIMATE PERFORMANCE
# ========================
if ($setPowerPlanUltimate) {
    Write-Host "Status: Setting Ultimate Performance power plan..." -ForegroundColor Cyan

    $regPath      = "HKCU:\Software\F_PS_CSC_S"
    $regName      = "UltimatePlanGUID"
    $templateGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"  # Microsoft Ultimate Power Plan Template
    $ultimateGUID = $null

    function Get-PowerSchemeGuids {
        $out = powercfg -list 2>$null
        $guids = @()
        foreach ($line in $out) {
            if ($line -match '([0-9A-Fa-f\-]{36})') {
                $guids += $matches[1].ToLower()
            }
        }
        return $guids
    }

    function New-UltimateFromTemplate {
        $before = Get-PowerSchemeGuids
        $dupOut = powercfg -duplicatescheme $templateGUID 2>&1
        $after  = Get-PowerSchemeGuids

        $new = $after | Where-Object { $before -notcontains $_ } | Select-Object -First 1
        if (-not $new) {
            $m = ($dupOut | Select-String -Pattern '([0-9A-Fa-f\-]{36})' | Select-Object -First 1)
            if ($m) { $new = $m.Matches[0].Value.ToLower() }
        }
        if (-not $new) { throw "Could not determine newly created plan GUID." }
        return $new
    }

    $saved = $null
    if (Test-Path $regPath) {
        $saved = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
        if ($saved) { $saved = $saved.ToLower() }
    }

    $existing = Get-PowerSchemeGuids
    if ($saved -and ($existing -contains $saved)) {
        $ultimateGUID = $saved
        Write-Host "Status: Loaded Ultimate plan GUID from registry and verified it exists: $ultimateGUID" -ForegroundColor Yellow
    }
    else {
        if ($saved -and -not ($existing -contains $saved)) {
            Write-Host "Status: Registry GUID not present anymore (plan deleted). Recreating..." -ForegroundColor Yellow
        } else {
            Write-Host "Status: No registry GUID found. Ensuring plan exists..." -ForegroundColor Yellow
        }

        if ($existing -contains $templateGUID) {
            $ultimateGUID = $templateGUID
            Write-Host "Status: Found existing Ultimate Performance plan from template GUID." -ForegroundColor Yellow
        } else {
            try {
                $ultimateGUID = New-UltimateFromTemplate
                Write-Host "Status: Created Ultimate Performance plan: $ultimateGUID" -ForegroundColor Yellow
            } catch {
                Write-Warning "Failed to create Ultimate Performance plan: $_"
            }
        }

        if ($ultimateGUID) {
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name $regName -Value $ultimateGUID
            Write-Host "Status: Saved Ultimate plan GUID to registry." -ForegroundColor Yellow
        }
    }

    # Activate the plan
    if ($ultimateGUID) {
        try {
            powercfg -setactive $ultimateGUID
            Write-Host "Status: Ultimate Performance plan activated." -ForegroundColor Yellow
        } catch {
            Write-Warning "Failed to activate Ultimate Performance plan. $_"
        }
    }

    # Set AC timeouts to never
    if ($ultimateGUID) {
        try {
            powercfg -change -monitor-timeout-ac 0
            powercfg -change -disk-timeout-ac 0
            powercfg -change -standby-timeout-ac 0
            powercfg -setacvalueindex $ultimateGUID SUB_VIDEO VIDEOIDLE 0

            powercfg -change -monitor-timeout-dc 0
            powercfg -change -disk-timeout-dc 0
            powercfg -change -standby-timeout-dc 0
            powercfg -setdcvalueindex $ultimateGUID SUB_VIDEO VIDEOIDLE 0

			Write-Host "Status: Timeouts (AC) and (DC) set to never for Ultimate plan." -ForegroundColor Yellow
        } catch {
            Write-Warning "Failed to set power plan timeout values. $_"
        }
    }
}

# ========================
# FILE EXPLORER, DESKTOP, TASKBAR AND OTHER MISC STUFF...
# ========================
if ($tweakGeneralExplorerAndOther) {
    Write-Host "Status: Configuring File Explorer, Desktop, Taskbar and other misc stuff..." -ForegroundColor Cyan

    # Basic Explorer tweaks
	Write-Host "Status: Configuring file explorer settings..." -ForegroundColor Yellow
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name LaunchTo -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name NavPaneShowLibraries -Value 1 -Type DWord

	# Check "Allow files on this drive to have contents indexed in addition to file properties" option in the properties of the Windows local drive
	$drive = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter = 'C:'"
	if ($drive) {
		$drive.IndexingEnabled = $true
		$drive.Put() | Out-Null
	} else {
		Write-Warning "Could not find C: drive object"
	}

    # Desktop icons
	Write-Host "Status: Configuring desktop settings..." -ForegroundColor Yellow
    $desktopIcons = @{
		"{59031a47-3f72-44a7-89c5-5595fe6b30ee}" = 0  # User's Files Folder
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" = 0  # This PC/Computer
        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" = 0  # Network
		"{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" = 0  # Control Panel
        "{645FF040-5081-101B-9F08-00AA002F954E}" = 0  # Recycle Bin
    }

    foreach ($iconGuid in $desktopIcons.Keys) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name $iconGuid -Value $desktopIcons[$iconGuid] -Type DWord
    }

	# Restore right-click old context menu
	New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Force | Out-Null
	New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value "" -Force

	# Show Windows build at the bottom right of the desktop
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 1 -Force

	# Detect Windows version and pick default wallpaper
	$winBuild = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
	if ($winBuild -ge 22000) {
		# Windows 11 default
		$wallpaperPath = "C:\Windows\Web\Wallpaper\Windows\img19.jpg"
	}
	else {
		# Windows 10 default
		$wallpaperPath = "C:\Windows\Web\Wallpaper\Windows\img0.jpg"
	}

	# Registry paths for personalization
	$desktopReg = "HKCU:\Control Panel\Desktop"
	$themeReg   = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"

	# Background type set to 'Picture'
	Set-ItemProperty -Path $themeReg -Name BackgroundType -Value 1
	
	# Set wallpaper picture
	Set-ItemProperty -Path $desktopReg -Name Wallpaper -Value $wallpaperPath
	Set-ItemProperty -Path $desktopReg -Name WallpaperStyle -Value 10
	Set-ItemProperty -Path $desktopReg -Name TileWallpaper -Value 0

	Write-Host "Status: Configuring taskbar settings..." -ForegroundColor Yellow

	# Disable News/Weather Widget (Windows 10)
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2 -Type DWord

	# Disable News/Weather Widget (Windows 11)
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type DWord

	# Extra policy enforcement for News/Weather Widget
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord

	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type DWord
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type DWord

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 1 -Type DWord
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 1 -Type DWord

	# Taskbar search display set to icon (Windows 10)
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord

	# Taskbar search display set to icon (Windows 11)
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSearchMode" -Value 1 -Type DWord
	
	# Enable "End task" in app right-click menu taskbar (Windows 11 22H2+)
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" -Force | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" -Name TaskbarEndTask -Type DWord -Value 1

	# Taskbar start button, pinned and opened Apps, search filed bar set alignment to the left (Only on Windows 11)
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0
	
	# --- Set Windows Visual Effects: Best Performance + Custom Preferences ---
	Write-Host "Applying 'Adjust for best performance' baseline..." -ForegroundColor Cyan

	# 0 = Let Windows choose, 1 = Adjust for best appearance, 2 = Adjust for best performance, 3 = Custom
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -Type DWord -Value 2
	Start-Sleep -Milliseconds 500
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -Type DWord -Value 3

	# Default "best performance" UserPreferencesMask
	$PerfMask = [byte[]](144, 18, 3, 128, 16, 0, 0, 0)
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name UserPreferencesMask -Value $PerfMask
	
	# Fix "Animate controls and elements inside windows" master flag
	$mask = (Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name UserPreferencesMask).'UserPreferencesMask'
	$mask[0] = $mask[0] -bor 0x08
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name UserPreferencesMask -Value $mask

	# === RE-ENABLE SELECTED EFFECTS ===

	# Animate controls and elements inside windows
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "ControlAnimations" -Type String -Value 1

	# Show thumbnails instead of icons
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "IconsOnly" -Type DWord -Value 0

	# Show translucent selection rectangle
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "ListviewAlphaSelect" -Type DWord -Value 1

	# Show window contents while dragging
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "DragFullWindows" -Type String -Value "1"

	# Smooth edges of screen fonts
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "FontSmoothing" -Type String -Value "2"
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "FontSmoothingType" -Type DWord -Value 2

	# Use drop shadows for icon labels
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "ListviewShadow" -Type DWord -Value 1

	# Disable Peek explicitly (if still active from prior config)
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\DWM' -Name "EnableAeroPeek" -Type DWord -Value 0

	# Disable taskbar animations
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "TaskbarAnimations" -Type DWord -Value 0

	# Enable Verbose Status (additional log information when shutting down/restarting Windows)
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "verbosestatus" -Type DWord -Value 1 -Force

    # Restart explorer.exe and Desktop to apply changes
	Write-Host "Status: Restarting Explorer and Desktop..." -ForegroundColor Yellow
	# Restart desktop
	RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
	# Restart explorer.exe
    Stop-Process -Name explorer -Force

	# Enable DirectPlay. This is for some old games (for example: GTA San Andreas)
	Write-Host "Status: Enabling legacy feature 'DirectPlay'..." -ForegroundColor Yellow
	try {
		DISM /Online /Enable-Feature /FeatureName:DirectPlay /All /NoRestart | Out-Null
	} catch {
		Write-Warning "Failed to enable DirectPlay: $_"
	}
}

# ========================
# INSTALL ESSENTIAL APPS
# ========================
if ($installapps) {
    Write-Host "Status: Installing new apps..." -ForegroundColor Cyan

    # List of apps to install
    $apps = @(
		"Microsoft.VCRedist.2005.x86",
		"Microsoft.VCRedist.2005.x64",
		"Microsoft.VCRedist.2008.x86",
		"Microsoft.VCRedist.2008.x64",
		"Microsoft.VCRedist.2010.x86",
		"Microsoft.VCRedist.2010.x64",
		"Microsoft.VCRedist.2012.x86",
		"Microsoft.VCRedist.2012.x64",
		"Microsoft.VCRedist.2013.x86",
		"Microsoft.VCRedist.2013.x64",
		"Microsoft.VCRedist.2015+.x86",
		"Microsoft.VCRedist.2015+.x64",
		"Microsoft.DotNet.DesktopRuntime.3_1",
		"Microsoft.DotNet.DesktopRuntime.5",
		"Microsoft.DotNet.DesktopRuntime.6",
		"Microsoft.DotNet.DesktopRuntime.7",
		"Microsoft.DotNet.DesktopRuntime.8",
		"Microsoft.DotNet.DesktopRuntime.9",
		"Microsoft.DotNet.Runtime.3_1",
		"Microsoft.DotNet.Runtime.5",
		"Microsoft.DotNet.Runtime.6",
		"Microsoft.DotNet.Runtime.7",
		"Microsoft.DotNet.Runtime.8",
		"Microsoft.DotNet.Runtime.9",
		"Microsoft.DotNet.AspNetCore.3_1",
		"Microsoft.DotNet.AspNetCore.5",
		"Microsoft.DotNet.AspNetCore.6",
		"Microsoft.DotNet.AspNetCore.7",
		"Microsoft.DotNet.AspNetCore.8",
		"Microsoft.DotNet.AspNetCore.9",
		"Microsoft.DirectX",
		"Microsoft.PowerShell",
        "nepnep.neofetch-win",
		"Oracle.JavaRuntimeEnvironment",
		"Apple.QuickTime",
        "7zip.7zip",
        "Notepad++.Notepad++",
        "VideoLAN.VLC"
    )

    foreach ($app in $apps) {
        # Check if app already installed
        $isInstalled = winget list --id $app --accept-source-agreements --accept-package-agreements 2>$null | Select-String $app

        if ($isInstalled) {
            Write-Host "Status: $app already installed. Skipping..." -ForegroundColor Yellow
            continue
        }

        Write-Host "Status: Installing $app..." -ForegroundColor Yellow
        try {
            # Let winget show progress bar, but suppress its "already installed" error messages
            winget install --id $app --silent --accept-source-agreements --accept-package-agreements -e --disable-interactivity --no-upgrade | Out-Null
            Write-Host "Status: $app installed successfully!" -ForegroundColor Yellow
        } catch {
            Write-Warning ("Failed to install " + $app + ": " + $_)
        }
    }
}

Write-Host "`nScript completed! Its recommended to restart Windows for all settings to be applied." -ForegroundColor Green
$restart = Read-Host "Do you want to restart your PC now? (Y/N): "

if ($restart -match '^[Yy]$') {
    Write-Host "Restarting your PC..." -ForegroundColor Green
    Restart-Computer -Force
} else {
    Write-Host "Restart skipped." -ForegroundColor Green

}


