<#
    Faria Powershell Custom Setup Config Script Win 10/11
	Optimise Services Only
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
$manageServices  				= $true

# Detect Windows build information
$osInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

Write-Host "                                                " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "  Faria Custom Setup Config Script Win10/11     " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "  Powershell Script # Optimise Services Only    " -ForegroundColor DarkBlue -BackgroundColor Black
Write-Host "                                                " -ForegroundColor DarkBlue -BackgroundColor Black


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
Write-Host ("`nWindows OS Version Detected: {0} | {1} | {2} | {3}`n" -f $osName, $osInfo.EditionID, $osInfo.DisplayVersion, $osInfo.CurrentBuildNumber) -ForegroundColor Green -BackgroundColor Black

# ========================
#  START
# ========================
Write-Host "Status: Script excuted and started. Recommended not to use your desktop while the script is running." -ForegroundColor Green
$ErrorActionPreference = "SilentlyContinue"

# ========================
#  OPTIMIZING SERVICES
# ========================
if ($manageServices) {
    Write-Host "[Status]: Optimizing services..." -ForegroundColor Cyan

	# Because of the issue before where Start Menu on Windows 11 would take up to a minute or more to start
	$autoServices = @(
		"Spooler",
		"WlanSvc",
		"EventLog",
		"AudioSrv",
		"AudioEndpointBuilder",
		"ProfSvc",
		"AppReadiness",
		"AppXSvc",
		"ClipSVC",
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
		"LanmanServer",
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
        "DispBrokerDesktopSvc",
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
		"LanmanWorkstation",
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
            Write-Host "Status: Set $svc to Auto Start" -ForegroundColor Yellow
        } catch {
            try {
                sc.exe config $svc start= delayed-auto | Out-Null
                Write-Host "Status: Set $svc to Auto Start (via sc.exe)" -ForegroundColor Yellow
            } catch {
                Write-Warning "Could not change $svc ($_)" 
            }
        }
    }

    foreach ($svc in $manualServices) {
        try {
            Set-Service -Name $svc -StartupType Manual -ErrorAction Stop
            Write-Host "Status: Set $svc to Manual" -ForegroundColor Yellow
        } catch {
            try {
                sc.exe config $svc start= demand | Out-Null
                Write-Host "Status: Set $svc to Manual (via sc.exe)" -ForegroundColor Yellow
            } catch {
                Write-Warning "Could not change $svc ($_)" 
            }
        }
    }

    foreach ($svc in $disableServices) {
        try {
            Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
            Write-Host "Status: Set $svc to Disabled" -ForegroundColor Yellow
        } catch {
            try {
                sc.exe config $svc start= disabled | Out-Null
                Write-Host "Status: Set $svc to Disabled (via sc.exe)" -ForegroundColor Yellow
            } catch {
                Write-Warning "Could not change $svc ($_)" 
            }
        }
    }
}

# ========================
#  END
# ========================
Write-Host "`nScript completed! Recommended to restart for full effect!" -ForegroundColor Green
$restart = Read-Host "Restart your PC now? [Y/N]: "

if ($restart -match '^[Yy]$') {
    Write-Host "Restarting your PC..." -ForegroundColor Green
    Restart-Computer -Force
} else {
    Write-Host "Understood. Remember to restart your PC later!" -ForegroundColor Green

}
