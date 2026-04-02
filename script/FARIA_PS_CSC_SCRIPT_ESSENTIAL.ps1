<#
    Faria Powershell Custom Setup Config Script Win 10/11
	Essential Version
    Created by FARIA (github.com/dfaria5)

		    @@@@@@@@@@@@@@@@@@@@@@@@@@
		   @@@@@@@@@@@@@@@@@@@@@@@@@@
	      @@@@@  @@@@@@@@@@@@@@@@@@@
	     @@@@@@@  @@@@@@@@@@@@@@@@@
	    @@@@@@@@@  @@@@@@@@@@@@@@@
	   @@@@@@@@  @@@@@@@@@@@@@@@@
	  @@@@@@@  @@@@@       @@@@@
	 @@@@@@@@@@@@@@@@@@@@@@@@@@
	@@@@@@@@@@@@@@@@@@@@@@@@@@
	 ______                    _   _       _ 
	|  ____|                  | | (_)     | |
	| |__   ___ ___  ___ _ __ | |_ _  __ _| |
	|  __| / __/ __|/ _ \ '_ \| __| |/ _' | |
	| |____\__ \__ \  __/ | | | |_| | (_| | |
	|______|___/___/\___|_| |_|\__|_|\__,_|_|
#>

# Relaunch as Admin if not already
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Host "Script not running as Administrator. Relaunching with elevated privileges..." -ForegroundColor Yellow

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Verb = "runas"

    if ($PSCommandPath) {
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    } else {
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
#  CONFIGURATION
# ========================
$removeApps						= $true
$disableTelemetry				= $true
$manageServices  				= $true
$setPowerPlanUltimate     		= $true
$forceDisableBitlocker			= $true
$tweakGeneralExplorerAndOther	= $true
$installapps					= $false

# Detect Windows build information
$osInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

Write-Host "                                                                                       " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "             @@@@@@@@@@@@@@@@@@@@@@@@@@  Faria Custom Setup Config Script Win10/11     " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "            @@@@@@@@@@@@@@@@@@@@@@@@@@   POWERSHELL SCRIPT VERSION:                    " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "           @@@@@  @@@@@@@@@@@@@@@@@@@                                                  " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "          @@@@@@@  @@@@@@@@@@@@@@@@@      ______                    _   _       _      " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "         @@@@@@@@@  @@@@@@@@@@@@@@@      |  ____|                  | | (_)     | |     " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "        @@@@@@@@  @@@@@@@@@@@@@@@@       | |__   ___ ___  ___ _ __ | |_ _  __ _| |     " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "       @@@@@@@  @@@@@       @@@@@        |  __| / __/ __|/ _ \ '_ \| __| |/ _' | |     " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "      @@@@@@@@@@@@@@@@@@@@@@@@@@         | |____\__ \__ \  __/ | | | |_| | (_| | |     " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "     @@@@@@@@@@@@@@@@@@@@@@@@@@          |______|___/___/\___|_| |_|\__|_|\__,_|_|     " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "                                                                                       " -ForegroundColor DarkBlue -BackgroundColor Black

Write-Host "`n                                                                  " -ForegroundColor Green -BackgroundColor Black
Write-Host "     https://github.com/dfaria5/faria-ps-csc-script               " -ForegroundColor Green -BackgroundColor Black
Write-Host "     FARIA                                                        " -ForegroundColor Green -BackgroundColor Black
Write-Host "                                                                  " -ForegroundColor Green -BackgroundColor Black

if ([int]$osInfo.CurrentBuildNumber -ge 22000) {
    $osName = "Windows 11"
} else {
    $osName = "Windows 10"
}
$displayVer = $osInfo.DisplayVersion
if (-not $displayVer) { $displayVer = $osInfo.ReleaseId }
Write-Host ("`nWindows OS Version Detected: {0} | {1} | {2} {3} | {4}`n" -f $osName, $osInfo.EditionID, $osInfo.DisplayVersion, $osInfo.ReleaseId, $osInfo.CurrentBuildNumber) -ForegroundColor Green -BackgroundColor Black

# ========================
#  START
# ========================
Write-Host "Script excuted and started! Recommended not to use your desktop while the script is running." -ForegroundColor White -BackgroundColor Green
$ErrorActionPreference = "SilentlyContinue"

# ========================
#  REMOVE UNWANTED/BLOAT APPS
# ========================
if ($removeApps) {
    Write-Host "Uninstalling unwanted/bloat apps..." -ForegroundColor White -BackgroundColor Blue

    $apps = @(
        "Microsoft.3DBuilder",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.MicrosoftSolitaireCollection",
		"Microsoft.BingSearch",
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
		"MicrosoftTeams",
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
        Write-Host "  Removing $app..." -ForegroundColor Cyan

		Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null

		Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    }

	# Remove any leftovers.
	Write-Host "  Removing any leftovers from bloat apps..." -ForegroundColor Cyan
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
	Write-Host "  Checking for OneDrive installation..." -ForegroundColor Cyan
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
			Write-Host "  Uninstalling OneDrive..." -ForegroundColor Cyan

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

		$oneDriveSetup = @("$env:SystemRoot\SysWOW64\OneDriveSetup.exe", "$env:SystemRoot\System32\OneDriveSetup.exe") | Where-Object { Test-Path $_ -PathType Leaf }

		if ($oneDriveSetup) {
			Write-Host "  Uninstalling OneDrive..." -ForegroundColor Cyan
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

        Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskPath "\Microsoft\OneDrive\" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\OneDrive\" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

        Write-Host "  OneDrive uninstalled." -ForegroundColor Cyan
    }
    else {
        Write-Host "  OneDrive is not installed. Skipping..." -ForegroundColor Cyan
    }
}

# ========================
#  DISABLE TELEMETRY
# ========================
if ($disableTelemetry) {
    Write-Host "Disabling Microsoft Telemetry & Cortana..." -ForegroundColor White -BackgroundColor Blue
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 -Type DWord
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Value 0
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0
	Write-Host "  Microsoft Telemtry & Cortana disabled." -ForegroundColor Cyan
}

# ========================
#  OPTIMIZING SERVICES
# ========================
if ($manageServices) {
    Write-Host "Optimizing services..." -ForegroundColor White -BackgroundColor Blue

	# Because of the issue before where Start Menu on Windows 11 would take up to a minute or more to start
	$autoServices = @(
		"Spooler",
		"WlanSvc",
		"LanmanServer",
		"LanmanWorkstation",
		"EventLog",
		"AudioSrv",
		"AudioEndpointBuilder",
		"ProfSvc",
		"AppReadiness",
		"AppXSvc",
		"ClipSVC",
		"DispBrokerDesktopSvc",
		"ShellHWDetection",
		"Themes",
		"WpnService",
		"WpnUserService_*",
		"CDPSvc",
		"CDPUserSvc_*",
		"UserDataSvc_*",
		"UnistoreSvc_*",
		"tiledatamodelsvc",
		"TimeBrokerSvc",
		"DcomLaunch",
		"WSearch"
	)

    $manualServices = @(
		"uhssvc",
		"SysMain",
		"TrkWks",
		"wercplsupport",
		"BthAvctpSvc",
		"tcsd",
		"CldFlt",
		"CDPUserSvc*",
		"PimIndexMaintenanceSvc*",
		"Netlogon",
		"PrintWorkflowUserSvc*",
		"TermService",
		"shpamsvc",
		"sdclt",
		"WwanSvc",
        "ALG",
		"AppIDSvc",
		"AppMgmt",
		"Appinfo",
		"AxInstSV",
		"BDESVC",
		"BFE",
		"BcastDVRUserService_*",
		"BluetoothUserService_*",
        "Browser",
		"BthHFSrv",
		"COMSysApp",
		"CaptureService_*",
		"CertPropSvc",
		"ConsentUxUserSvc_*",
		"CoreMessagingRegistrar",
		"CredentialEnrollmentManagerUserSvc_*",
        "CryptSvc",
		"CscService",
		"DPS",
		"DcpSvc",
		"DevQueryBroker",
		"DeviceAssociationBrokerSvc_*",
        "DeviceAssociationService",
		"DeviceInstall",
		"DevicePickerUserSvc_*",
		"DevicesFlowUserSvc_*",
		"Dhcp",
		"DisplayEnhancementService",
		"DmEnrollmentSvc",
		"EFS",
		"EapHost",
		"EntAppSvc",
		"EventSystem",
		"FDResPub",
		"FontCache",
		"FrameServer",
		"FrameServerMonitor",
		"GraphicsPerfSvc",
        "HomeGroupListener",
		"HomeGroupProvider",
		"HvHost",
		"IEEtwCollectorService",
		"IKEEXT",
		"InstallService",
        "InventorySvc",
		"IpxlatCfgSvc",
		"KtmRm",
		"LicenseManager",
		"LxpSvc",
		"MSDTC",
		"MSiSCSI",
        "McpManagementService",
		"MicrosoftEdgeElevationService",
		"MixedRealityOpenXRSvc",
		"MsKeyboardFilter",
        "NaturalAuthentication",
		"NcaSvc",
		"NcbService",
		"NcdAutoSetup",
		"NetSetupSvc",
		"Netman",
		"NgcCtnrSvc",
        "NgcSvc",
		"P9RdrService_*",
		"PNRPAutoReg",
		"PNRPsvc",
		"PeerDistSvc",
		"PenService_*",
		"PerfHost",
        "PimIndexMaintenanceSvc_*",
		"PlugPlay",
		"PolicyAgent",
		"PrintWorkflowUserSvc_*",
		"PushToInstall",
        "QWAVE",
		"RasAuto",
		"RasMan",
		"RmSvc",
		"RpcLocator",
		"SCPolicySvc",
		"SCardSvr",
		"SDRSVC",
		"SEMgrSvc",
        "SNMPTRAP",
		"SNMPTrap",
		"ScDeviceEnum",
		"Schedule",
		"Sense",
		"SensorDataService",
		"SensorService",
        "SensrSvc",
		"SessionEnv",
		"SharedRealitySvc",
		"SmsRouter",
		"SstpSvc",
		"StiSvc",
        "StorSvc",
		"TapiSrv",
		"TieringEngineService",
		"TimeBroker",
		"TokenBroker",
        "TroubleshootingSvc",
		"TrustedInstaller",
		"UI0Detect",
		"UdkUserSvc_*",
		"UmRdpService",
		"UsoSvc",
		"VSS",
		"VacSvc",
		"W32Time",
		"WFDSConMgrSvc",
		"WManSvc",
		"WPDBusEnum",
		"WSService",
        "WaaSMedicSvc",
		"WarpJITSvc",
		"WbioSrvc",
		"WcsPlugInService",
		"WdNisSvc",
		"WdiServiceHost",
		"WdiSystemHost",
        "WebClient",
		"Wecsvc",
		"WerSvc",
		"WiaRpc",
		"WinHttpAutoProxySvc",
		"WinRM",
		"WpcMonSvc",
		"XblAuthManager",
        "XblGameSave",
		"XboxGipSvc",
		"XboxNetApiSvc",
		"autotimesvc",
		"bthserv",
		"camsvc",
		"cloudidsvc",
		"dcsvc",
        "defragsvc",
		"diagnosticshub.standardcollector.service",
		"diagsvc",
		"dot3svc",
		"edgeupdate",
		"edgeupdatem",
        "embeddedmode",
		"fdPHost",
		"fhsvc",
		"hidserv",
		"icssvc",
		"lfsvc",
		"lltdsvc",
		"lmhosts",
		"msiserver",
		"netprofm",
        "p2pimsvc",
		"p2psvc",
		"perceptionsimulation",
		"pla",
		"seclogon",
		"smphost",
		"spectrum",
		"svsvc",
		"swprv",
		"upnphost",
		"vds",
		"vm3dservice",
		"vmicguestinterface",
		"vmicheartbeat",
		"vmickvpexchange",
        "vmicrdv",
		"vmicshutdown",
		"vmictimesync",
		"vmicvmsession",
		"vmicvss",
		"wbengine",
		"wcncsvc",
		"webthreatdefsvc",
        "wlidsvc",
		"wlpasvc",
		"wmiApSrv",
		"workfolderssvc",
		"wuauserv",
		"wudfsvc"
    )

    $disableServices = @(
		"DiagTrack",
		"dmwappushservice",
		"RetailDemo",
		"WMPNetworkSvc",
		"Fax",
		"MapsBroker",
		"MessagingService",
		"PhoneSvc",
		"PrintNotify",
		"WalletService",
		"wisvc",
		"AJRouter",
		"AppVClient",
		"AssignedAccessManagerSvc",
		"BTAGService",
		"DialogBlockingService",
        "NetTcpPortSharing",
		"UevAgentService",
		"ssh-agent",
		"tzautoupdate",
		"WebClient",
		"edgeupdate",
		"edgeupdatem"
    )

	# "WinRM",					# Windows Remote Management
	# "RemoteAccess",			# Routing and Remote Access
	# "RemoteRegistry",			# Security risk
	# "SharedAccess",			# Internet Connection Sharing

	foreach ($svc in $autoServices) {
        try {
            Set-Service -Name $svc -StartupType Automatic -ErrorAction Stop
            Write-Host "  Set $svc to Auto Start" -ForegroundColor Cyan
        } catch {
            try {
                sc.exe config $svc start= delayed-auto | Out-Null
                Write-Host "  Set $svc to Auto Start Delayed (via sc.exe)" -ForegroundColor Cyan
            } catch {
                Write-Warning "Could not change $svc ($_)" 
            }
        }
    }

    foreach ($svc in $manualServices) {
        try {
            Set-Service -Name $svc -StartupType Manual -ErrorAction Stop
            Write-Host "  Set $svc to Manual" -ForegroundColor Cyan
        } catch {
            try {
                sc.exe config $svc start= demand | Out-Null
                Write-Host "  Set $svc to Manual (via sc.exe)" -ForegroundColor Cyan
            } catch {
                Write-Warning "Could not change $svc ($_)" 
            }
        }
    }

    foreach ($svc in $disableServices) {
        try {
            Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
            Write-Host "  Set $svc to Disabled" -ForegroundColor Cyan
        } catch {
            try {
                sc.exe config $svc start= disabled | Out-Null
                Write-Host "  Set $svc to Disabled (via sc.exe)" -ForegroundColor Cyan
            } catch {
                Write-Warning "Could not change $svc ($_)" 
            }
        }
    }
	
	Write-Host "  All services optimized and set." -ForegroundColor Cyan
}

# ========================
#  POWER SETTINGS
# ========================
if ($setPowerPlanUltimate) {
    Write-Host "Setting power management options..." -ForegroundColor White -BackgroundColor Blue
	Write-Host "  Setting Ultimate Performance power plan..." -ForegroundColor Cyan

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
        Write-Host "  Loaded Ultimate plan GUID from registry and verified it exists: $ultimateGUID" -ForegroundColor Cyan
    }
    else {
        if ($saved -and -not ($existing -contains $saved)) {
            Write-Host "  Registry GUID not present anymore (plan deleted). Recreating..." -ForegroundColor Cyan
        } else {
            Write-Host "  No registry GUID found. Ensuring plan exists..." -ForegroundColor Cyan
        }

        if ($existing -contains $templateGUID) {
            $ultimateGUID = $templateGUID
            Write-Host "  Found existing Ultimate Performance plan from template GUID." -ForegroundColor Cyan
        } else {
            try {
                $ultimateGUID = New-UltimateFromTemplate
                Write-Host "  Created Ultimate Performance plan: $ultimateGUID" -ForegroundColor Cyan
            } catch {
                Write-Warning "Failed to create Ultimate Performance plan: $_"
            }
        }

        if ($ultimateGUID) {
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name $regName -Value $ultimateGUID
            Write-Host "  Saved Ultimate plan GUID to registry." -ForegroundColor Cyan
        }
    }

    # Activate the plan
    if ($ultimateGUID) {
        try {
            powercfg -setactive $ultimateGUID
            Write-Host "  Ultimate Performance plan activated." -ForegroundColor Cyan
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

			Write-Host "  Timeouts (AC) and (DC) set to never for Ultimate plan." -ForegroundColor Cyan
        } catch {
            Write-Warning "Failed to set power plan timeout values. $_"
        }
    }

	Write-Host "  Changing power settings for network adapters..." -ForegroundColor Cyan
    $netAdapters = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue

    # DNS prompt
    $setDnsYes = $false
    $setDns = Read-Host "Set Quad9 (9.9.9.9) and Cloudflare (1.1.1.1) DNS Servers? [Y/N]: "
    if ($setDns -match '^[Yy]$') { $setDnsYes = $true }

    foreach ($adapter in $netAdapters) {
        Write-Host "  Processing: $($adapter.Name)" -ForegroundColor Cyan

        try {
            $ifIndex = $adapter.InterfaceIndex

            # 1. Power Management Settings (your original)
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            $subKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue

            foreach ($key in $subKeys) {
                if ((Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue).DriverDesc -eq $adapter.InterfaceDescription) {
                    Set-ItemProperty -Path $key.PSPath -Name "PnPCapabilities" -Value 24 -Type DWord -Force
                    if (Get-ItemProperty -Path $key.PSPath -Name "WakeOnMagicPacket" -ErrorAction SilentlyContinue) {
                        Set-ItemProperty -Path $key.PSPath -Name "WakeOnMagicPacket" -Value 0 -Type DWord -Force
                    }
                    Start-Process -FilePath "powercfg.exe" -ArgumentList "/devicedisablewake", "$($adapter.Name)" -WindowStyle Hidden -NoNewWindow -Wait
                }
            }

            # 2. Disable NetBIOS over TCP/IP (this affects the GUI checkbox)
            $wmi = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex = $ifIndex" -ErrorAction SilentlyContinue
            if ($wmi) {
                $result = $wmi.SetTcpNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
                if ($result.ReturnValue -eq 0) {
                    Write-Host "    NetBIOS over TCP/IP disabled for $($adapter.Name)" -ForegroundColor DarkGray
                }
            }

            # 3. Disable LMHOSTS lookup globally
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -Value 0 -Type DWord -Force

            # 4. DNS Settings
            if ($setDnsYes) {
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses @("9.9.9.9", "1.1.1.1")
                    Write-Host "    DNS set to Quad9 + Cloudflare for $($adapter.Name)" -ForegroundColor DarkGray
                } catch {
                    Write-Host "    Failed to set DNS for $($adapter.Name)" -ForegroundColor Yellow
                }
            }
        }
        catch {
            Write-Warning "Error processing $($adapter.Name): $_"
        }
    }

    Write-Host "  Network adapter configuration completed (NetBIOS + LMHOSTS disabled)." -ForegroundColor Green
}

# ========================
#  FILE EXPLORER, DESKTOP, TASKBAR AND OTHER MISC STUFF...
# ========================
if ($tweakGeneralExplorerAndOther) {
    Write-Host "Configuring File Explorer, Desktop, Taskbar and other misc stuff..." -ForegroundColor White -BackgroundColor Blue

    # Basic Explorer tweaks
	Write-Host "  Configuring file explorer settings..." -ForegroundColor Cyan
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

    # Classic desktop icons
	Write-Host "  Configuring desktop settings..." -ForegroundColor Cyan
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
	$winBuildDesktop = Read-Host "Show Windows build at the bottom right of the desktop? [Y/N]: "
	if ($winBuildDesktop -match '^[Yy]$') {
		Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 1 -Force
	} else { <# Nothing #> }

	# Disable Spotlight
	$cdmPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
	if (-not (Test-Path $cdmPath)) { New-Item -Path $cdmPath -Force | Out-Null }
	Set-ItemProperty -Path $cdmPath -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 -Force  # Desktop Spotlight off
	Set-ItemProperty -Path $cdmPath -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 -Force  # Lock bleed-over off
	Set-ItemProperty -Path $cdmPath -Name "RotatingLockScreenEnabled"     -Type DWord -Value 0 -Force
	
	$spotlightSettingsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings"
	if (-not (Test-Path $spotlightSettingsPath)) { New-Item -Path $spotlightSettingsPath -Force | Out-Null }
	Set-ItemProperty -Path $spotlightSettingsPath -Name "EnabledState" -Type DWord -Value 0 -Force
	
	# Clear Spotlight cache (prevents old images/state from reloading)
	$cachePaths = @(
		"$env:LocalAppData\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\Assets",
		"$env:LocalAppData\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\RoamingState",
		"$env:LocalAppData\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalCache\Microsoft\IrisService"
	)
	foreach ($path in $cachePaths) {
		if (Test-Path $path) {
			Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	$themeReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
	# Determine dark mode (1 = light mode, 0 = dark mode)
    $isLightMode = (Get-ItemProperty -Path $themeReg -Name "AppsUseLightTheme" -ErrorAction SilentlyContinue).AppsUseLightTheme

	# Set wallpaper path depending of which Windows version
	if ($osInfo.CurrentBuildNumber -ge 22000) {
		# Windows 11 default
		if ($isLightMode -eq 1) {
            $wallpaperPath = "C:\Windows\Web\Wallpaper\Windows\img0.jpg"
        } else {
            $wallpaperPath = "C:\Windows\Web\Wallpaper\Windows\img19.jpg"
        }
	} else {
		# Windows 10 default
		$wallpaperPath = "C:\Windows\Web\4K\Wallpaper\Windows\img0_3840x2160.jpg"
	}
	
	$wallpaperModePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers"
	if (-not (Test-Path $wallpaperModePath)) { New-Item -Path $wallpaperModePath -Force | Out-Null }

	# DEFAULT WINDOWS WALLPAPER
	# Wallpaper Mode set to Image
	Set-ItemProperty -Path $wallpaperModePath -Name "BackgroundType" -Type DWord -Value 0 -Force
	# Set wallpaper
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WallPaper" -Value $wallpaperPath -Force

	Write-Host "  Configuring taskbar settings..." -ForegroundColor Cyan

	# Taskbar search display set to icon (Windows 10)
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Type DWord

	# Taskbar search display set to icon (Windows 11)
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSearchMode" -Value 1 -Type DWord
	
	# Enable "End task" in app right-click menu taskbar (Only on Windows 11)
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" -Force | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" -Name TaskbarEndTask -Type DWord -Value 1

	# Taskbar start button, pinned and opened Apps, search filed bar set alignment to the left (Only on Windows 11)
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0

	# Set Performance options preset to "Best Performance" to "Custom"
	Write-Host "  Applying custom set performance options..." -ForegroundColor Cyan
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -Type DWord -Value 2
	Start-Sleep -Milliseconds 500
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -Type DWord -Value 3

	# Default "best performance" UserPreferencesMask
	$PerfMask = [byte[]](144, 18, 3, 128, 16, 0, 0, 0)
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name UserPreferencesMask -Value $PerfMask

	# Enable/Check 'Animate controls and elements inside windows'
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations' -Name "DefaultApplied" -Type DWord -Value 1
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations' -Name "DefaultValue" -Type DWord -Value 1
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations' -Name "Value" -Type DWord -Value 1

	# Disable/Uncheck 'Animate windows when minimising and maximising'
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name "MinAnimate" -Type String -Value "0"

	# Disable/Uncheck 'Enable Peek'
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\DWM' -Name "EnableAeroPeek" -Type DWord -Value 0

	# Enable/Check 'Show thumbnails instead of icons'
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "IconsOnly" -Type DWord -Value 0

	# Enable/Check 'Show translucent selection rectangle'
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "ListviewAlphaSelect" -Type DWord -Value 1

	# Enable/Check 'Show window contents while dragging'
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "DragFullWindows" -Type String -Value "1"

	# Enable/Check 'Smooth edges of screen fonts'
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "FontSmoothing" -Type String -Value "2"
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "FontSmoothingType" -Type DWord -Value 2

	# Enable/Check 'Use drop shadows for icon labels'
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "ListviewShadow" -Type DWord -Value 1

	# Disable taskbar animations
	Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "TaskbarAnimations" -Type DWord -Value 0

	# Enable Verbose Status (additional log information when shutting down/restarting Windows)
    $verboseS = Read-Host "Enable Verbose Status? (additional log information when shutting down/restarting Windows) [Y/N]: "
	if ($verboseS -match '^[Yy]$') {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "verbosestatus" -Type DWord -Value 1 -Force
	} else { <# Nothing #> }

    # Restart explorer.exe and Desktop to apply changes
	Write-Host "  Restarting Explorer and Desktop..." -ForegroundColor Cyan
	# Restart desktop
	RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
	# Restart explorer.exe
    Stop-Process -Name explorer -Force

	# Enable DirectPlay. This is for some old games (for example: GTA San Andreas)
	Write-Host "  Enabling legacy feature 'DirectPlay'..." -ForegroundColor Cyan
	try {
		DISM /Online /Enable-Feature /FeatureName:DirectPlay /All /NoRestart | Out-Null
	} catch {
		Write-Warning "Failed to enable DirectPlay: $_"
	}
}

# ========================
# Remove ALL pinned apps from Start Menu (Windows 10 only)
# ========================


# ?? ASK USER
# ?? INSTALL APPS
$installapps = Read-Host "Do you wish to install extra essential apps? (7zip, Java, VLC Media Player, Microsoft Distributions/Redistributables, Powershell 7) [Y/N]: "
if ($installapps -match '^[Yy]$') {
	$installapps = $true
} else { 
	$installapps = $false
}

# ========================
#  INSTALL ESSENTIAL APPS
# ========================
if ($installapps) {
    Write-Host "Installing new apps..." -ForegroundColor White -BackgroundColor Blue

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
		"Oracle.JavaRuntimeEnvironment",
        "7zip.7zip",
        "Notepad++.Notepad++",
        "VideoLAN.VLC"
    )

    foreach ($app in $apps) {
        $isInstalled = winget list --id $app --accept-source-agreements --accept-package-agreements 2>$null | Select-String $app

        if ($isInstalled) {
            Write-Host "  $app already installed. Skipping..." -ForegroundColor Cyan
            continue
        }

        Write-Host "  Installing $app..." -ForegroundColor Cyan
        try {
            winget install --id $app --silent --accept-source-agreements --accept-package-agreements -e --disable-interactivity --no-upgrade | Out-Null
            Write-Host "  $app installed successfully!" -ForegroundColor Cyan
        } catch {
            Write-Warning ("Failed to install " + $app + ": " + $_)
        }
    }
}


# ========================
#  END
# ========================
Write-Host "`n"
Write-Host "Script completed! Windows needs to restart for all applied settings changes to have full effect!" -ForegroundColor White -BackgroundColor Green
$restart = Read-Host "Restart your PC now? (Y/N): "

if ($restart -match '^[Yy]$') {
    Write-Host "Restarting your PC..." -ForegroundColor Green
    Restart-Computer -Force
} else {
    Write-Host "Understood. Remember to restart your PC later!" -ForegroundColor Green
}