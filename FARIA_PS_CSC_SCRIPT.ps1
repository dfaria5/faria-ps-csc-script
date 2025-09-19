<#
    Faria Powershell Custom Setup Config Script Win 10/11
    Created by FARIA (github.com/dfaria5)
#>

# Relaunch as Admin if not already
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Script not running as Administrator. Relaunching with elevated privileges..." -ForegroundColor Yellow

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"

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
$installapps					= $true

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

		# Fallback: check exact Store package names only (avoid wildcard false-positives)
		$appx = Get-AppxPackage -AllUsers -Name "Microsoft.OneDrive" -ErrorAction SilentlyContinue
		if (-not $appx) {
			$appx = Get-AppxPackage -AllUsers -Name "Microsoft.OneDriveSync" -ErrorAction SilentlyContinue
		}
		return [bool]$appx
	}

	function Invoke-OneDriveUninstall {
		# Prefer the classic uninstall entry if present
		$entry = Get-OneDriveUninstallInfo
		if ($entry -and $entry.UninstallString) {
			Write-Host "Status: Uninstalling OneDrive..." -ForegroundColor Yellow

			# UninstallString may contain quotes and params; execute properly
			$cmdLine = $entry.UninstallString
			# If it's MSIEXEC, run directly; otherwise Start-Process with parsed exe/args
			if ($cmdLine -match 'msiexec') {
				Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmdLine" -Wait -NoNewWindow
			} else {
				# Split exe and args safely
				$exe  = $cmdLine
				$args = ""
				if ($cmdLine -match '^\s*\"([^"]+)\"\s*(.*)$') { $exe=$matches[1]; $args=$matches[2] }
				elseif ($cmdLine -match '^\s*(\S+)\s+(.*)$')    { $exe=$matches[1]; $args=$matches[2] }
				Start-Process -FilePath $exe -ArgumentList $args -Wait -NoNewWindow
			}
			return
		}

		# Otherwise, try the system setup stubs (only if present)
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

        # Cleanup leftovers (safe even if already gone)
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

    # Services set to disable.
	$servicesToDisable = @(
		"DiagTrack",             # Connected User Experiences and Telemetry
		"dmwappushservice",      # WAP Push Messaging (telemetry pipe)
		"RetailDemo",            # Retail Demo Service
		"WMPNetworkSvc",         # Windows Media Player Network Sharing
		"Fax",                   # Fax service
		"MapsBroker",            # Downloaded Maps Manager
		"MessagingService",      # SMS Routing
		"PhoneSvc",              # Phone Service (Continuity, not needed on desktops)
		"PrintNotify",           # Printer Notifications (disable if no printer ever used)
		"RemoteAccess",          # Routing and Remote Access (VPN/RRAS, rare)
		"RemoteRegistry",        # Security risk
		"SharedAccess",          # Internet Connection Sharing
		"Spooler",               # Print Spooler (disable if no printer at all)
		"WalletService",         # Microsoft Wallet
		"wisvc"                  # Windows Insider Service
	)

    foreach ($svc in $servicesToDisable) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            try {
                Stop-Service $svc -Force -ErrorAction SilentlyContinue
                Set-Service $svc -StartupType Disabled
            } catch {
				Write-Warning "Status: Failed to set Service to Disabled $_"
			}
        }
    }

    # Services to set to Manual. (Safe so the service will only start when it actually needs it)
	$servicesToManual = @(
		"SysMain",               # Superfetch/Prefetch
		"TrkWks",                # Distributed Link Tracking
		"TabletInputService",    # Touch/pen input
		"DiagSvc",               # Diagnostic Execution
		"wercplsupport",         # Problem Reports
		"WSearch",               # Windows Search (manual keeps it available)
		"TermService",           # Remote Desktop Services
		"BTAGService",           # Bluetooth Audio Gateway
		"BthAvctpSvc",           # Bluetooth Audio/Video
		"bthserv",               # Core Bluetooth
		"lfsvc",                 # Geolocation
		"NgcCtnrSvc",            # Microsoft Passport Container
		"NgcSvc",                # Microsoft Passport
		"SEMgrSvc",              # Payments and NFC
		"SmsRouter",             # SMS Routing
		"stisvc",                # Windows Image Acquisition (scanners/cameras)
		"WbioSrvc",              # Biometrics
		"WpnService",            # Windows Push Notifications
		"WpnUserService"         # Notifications per-user
		"XblAuthManager",        # Xbox Live Auth
		"XblGameSave",           # Xbox Live Game Save
		"XboxNetApiSvc",         # Xbox Networking
		"XboxGipSvc"             # Xbox Accessory Management
	)

    foreach ($svc in $servicesToManual) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            try {
                Set-Service $svc -StartupType Manual
            } catch {
				Write-Warning "Status: Failed to set Service to Manual $_"
			}
        }
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
        # Create from template and reliably capture the NEW GUID by diffing plan lists
        $before = Get-PowerSchemeGuids
        $dupOut = powercfg -duplicatescheme $templateGUID 2>&1
        $after  = Get-PowerSchemeGuids

        # Find the GUID that wasn't in the list before
        $new = $after | Where-Object { $before -notcontains $_ } | Select-Object -First 1
        if (-not $new) {
            # Fallback: parse directly from command output just in case
            $m = ($dupOut | Select-String -Pattern '([0-9A-Fa-f\-]{36})' | Select-Object -First 1)
            if ($m) { $new = $m.Matches[0].Value.ToLower() }
        }
        if (-not $new) { throw "Could not determine newly created plan GUID." }
        return $new
    }

    # Try registry, but only trust it if the plan still exists
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

        # If the Microsoft template already exists as a user plan, just use that
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

        # Save (or update) registry
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

    # Desktop icons registry keys with correct names and values (0 = show icon)
	Write-Host "Status: Configuring desktop settings..." -ForegroundColor Yellow
    $desktopIcons = @{
		"{59031a47-3f72-44a7-89c5-5595fe6b30ee}" = 0  # User's Files Folder
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" = 0  # This PC/Computer
        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" = 0  # Network
		"{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" = 0  # Control Panel
        "{645FF040-5081-101B-9F08-00AA002F954E}" = 0  # Recycle Bin
    }

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

    foreach ($iconGuid in $desktopIcons.Keys) {
        Set-ItemProperty -Path $regPath -Name $iconGuid -Value $desktopIcons[$iconGuid] -Type DWord
    }

	# Desktop icons size
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "Shell Icon Size" -Value "53"

	# Windows text size
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 106

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

	# Taskbar search display set to icon (Windows 10)
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord

	# Taskbar search display set to icon (Windows 11)
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSearchMode" -Value 1 -Type DWord

	# Taskbar start button, pinned and opened Apps, search filed bar set alignment to the left (Only on Windows 11)
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0

	# Restore right-click old context menu
	if (Test-Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32") {
		Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Recurse -Force -ErrorAction SilentlyContinue
	}

    # Restart explorer.exe to apply changes
	Write-Host "Status: Restarting Explorer..." -ForegroundColor Yellow
    Stop-Process -Name explorer -Force
    Start-Sleep -Seconds 2
    Start-Process explorer.exe

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

Write-Host "`nScript completed! Its recommended to restart Windows." -ForegroundColor Green
$restart = Read-Host "Do you want to restart your PC now? (Y/N): "

if ($restart -match '^[Yy]$') {
    Write-Host "Restarting your PC..." -ForegroundColor Green
    Restart-Computer -Force
} else {
    Write-Host "Restart skipped." -ForegroundColor Green
}