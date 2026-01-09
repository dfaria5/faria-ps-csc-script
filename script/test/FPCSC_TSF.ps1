# ========================
#  TEST POWERSHELL SCRIPT FUNCTIONS
# ========================
# ========================
#  BEFORE START
# ========================
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
# Detect Windows build information
$osInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
if ([int]$osInfo.CurrentBuildNumber -ge 22000) {
    $osName = "Windows 11"
} else {
    $osName = "Windows 10"
}
$displayVer = $osInfo.DisplayVersion
if (-not $displayVer) { $displayVer = $osInfo.ReleaseId }
Write-Host ("`nWindows OS Version Detected: {0} | {1} | {2} {3} | {4}`n" -f $osName, $osInfo.EditionID, $osInfo.DisplayVersion, $osInfo.ReleaseId, $osInfo.CurrentBuildNumber) -ForegroundColor Green -BackgroundColor Black

# ========================
#  CONFIGURATION
# ========================
$testWallpaperChange 			= $false
$testRemovePinnedShortcutsStart = $true

# ========================
#  START
# ========================

<# Choose
Write-Host "`nTEST SCRIPT FUNCTION `n1 - Test Wallpaper Change (after Win11 25H2) `n2 - Test Remove Pinned Promotion Shortcuts on Start" -ForegroundColor Green
$chooseMenuTest = Read-Host "Choose: " #>

if ($testWallpaperChange) {
	$themeReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"

	# Old keys (keep them - they still help with lock screen and suggestions)
	$cdmPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
	if (-not (Test-Path $cdmPath)) { New-Item -Path $cdmPath -Force | Out-Null }
	Set-ItemProperty -Path $cdmPath -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path $cdmPath -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path $cdmPath -Name "RotatingLockScreenEnabled"     -Type DWord -Value 0 -Force

	# New key: Critical for desktop Spotlight in 25H2+ (prevents auto-takeover)
	$spotlightSettingsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings"
	if (-not (Test-Path $spotlightSettingsPath)) { New-Item -Path $spotlightSettingsPath -Force | Out-Null }
	Set-ItemProperty -Path $spotlightSettingsPath -Name "EnabledState" -Type DWord -Value 0 -Force

	# Optional: Disable transparency if any residual blur/glow persists
	<# $personalizePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
	Set-ItemProperty -Path $personalizePath -Name "EnableTransparency" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue #>

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
		# Currently changing wallpaper on Windows 11 is too buggy and will not work 100% all the time.
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

	# Restart explorer.exe and Desktop to apply changes
	Write-Host "Status: Restarting Explorer and Desktop..." -ForegroundColor Yellow
	RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
	Start-Sleep -Seconds 2
	RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
	Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
	Start-Sleep -Seconds 2
	Start-Process explorer
}

if ($testRemovePinnedShortcutsStart) {
	# Super aggressive LinkedIn removal (installed + provisioned + all variants)
	Write-Host "Status: Removing LinkedIn app, provisioned package, and any stubs..." -ForegroundColor Yellow

	# Installed packages (all users)
	Get-AppxPackage -AllUsers "*LinkedIn*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

	# Provisioned (prevents re-install for new profiles/updates)
	Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*LinkedIn*" -or $_.PackageName -like "*7EE7776C.LinkedInforWindows*" } |
	Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction SilentlyContinue
	
	# Clear Start menu pinned/recommended cache (removes LinkedIn stub without installing)
	Write-Host "Status: Clearing Start menu layout cache to remove LinkedIn stub..." -ForegroundColor Yellow

	# Stop Start menu host
	Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue

	# Nuke local state (pinned items, recommendations, stubs)
	$startHostPath = "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_*\LocalState"
	if (Test-Path $startHostPath) {
		Remove-Item "$startHostPath\*" -Recurse -Force -ErrorAction SilentlyContinue
	}

	# Also clean common shortcut locations (just in case)
	Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\LinkedIn*" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\LinkedIn*" -Recurse -Force -ErrorAction SilentlyContinue
	
	# Disable recommended/sponsored apps in Start (prevents LinkedIn stubs from coming back)
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -Force

	# Extra: Turn off content delivery for recommendations
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force  # Already in your script, but confirm
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0 -Type DWord -Force
	
	# Restart explorer to rebuild Start menu
	Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
	Start-Sleep -Seconds 2
	Start-Process explorer
}

# ========================
#  END
# ========================
Write-Host "`nScript completed! Windows needs to restart for all applied settings changes to have full effect!" -ForegroundColor Green
$restart = Read-Host "Restart your PC now? (Y/N): "

if ($restart -match '^[Yy]$') {
    Write-Host "Restarting your PC..." -ForegroundColor Green
    Restart-Computer -Force
} else {
    Write-Host "Understood. Remember to restart your PC later!" -ForegroundColor Green
}