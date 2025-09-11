# Prep-Win11Upgrade.ps1
# Purpose: Assist with a Windows 11 in-place upgrade

# Run as Admin check
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
    Write-Warning "Please run PowerShell as Administrator."
    Exit
}

Write-Host "🔍 Checking basic system info..." -ForegroundColor Cyan
Get-ComputerInfo | Select-Object OSName, WindowsVersion, CsSystemManufacturer, CsSystemModel

# Save system info to desktop
$sysInfoPath = "$env:USERPROFILE\Desktop\SystemInfo-Win11Upgrade.txt"
Get-ComputerInfo | Out-File -Encoding UTF8 -FilePath $sysInfoPath
Write-Host "✅ System info saved to: $sysInfoPath" -ForegroundColor Green

# Check TPM presence
Write-Host "`n🔐 Checking TPM status..." -ForegroundColor Cyan
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
if ($tpm) {
    Write-Host "✅ TPM is present and version: $($tpm.SpecVersion)" -ForegroundColor Green
} else {
    Write-Warning "⚠️ TPM not found or unsupported. Windows 11 may require a workaround."
}

# Check Secure Boot
Write-Host "`n🔐 Checking Secure Boot status..." -ForegroundColor Cyan
$secureBoot = Confirm-SecureBootUEFI
if ($secureBoot) {
    Write-Host "✅ Secure Boot is enabled." -ForegroundColor Green
} else {
    Write-Warning "⚠️ Secure Boot is disabled or unsupported. Windows 11 may require a workaround."
}

# Disk Cleanup
Write-Host "`n🧹 Running Disk Cleanup..." -ForegroundColor Cyan
Start-Process "cleanmgr.exe" -ArgumentList "/sagerun:1"

# Offer to disable Defender temporarily (optional)
$disableAV = Read-Host "`n🛡️ Do you want to temporarily disable Windows Defender Real-time protection? (Y/N)"
if ($disableAV -eq "Y") {
    Write-Host "Disabling real-time protection..." -ForegroundColor Yellow
    Set-MpPreference -DisableRealtimeMonitoring $true
    Write-Host "✅ Defender real-time protection disabled. It will re-enable after reboot." -ForegroundColor Green
}

# Offer to download Windows 11 Installation Assistant
$downloadAssistant = Read-Host "`n⬇️ Do you want to download the Windows 11 Installation Assistant now? (Y/N)"
if ($downloadAssistant -eq "Y") {
    $url = "https://go.microsoft.com/fwlink/?linkid=2171764"  # Official Microsoft URL
    $dest = "$env:USERPROFILE\Desktop\Windows11InstallationAssistant.exe"
    Invoke-WebRequest -Uri $url -OutFile $dest
    Write-Host "✅ Downloaded to Desktop: Windows11InstallationAssistant.exe" -ForegroundColor Green
    Start-Process $dest
} else {
    Write-Host "You can download it manually from: https://www.microsoft.com/software-download/windows11" -ForegroundColor Yellow
}

Write-Host "`n🚀 All prep steps completed. You’re ready to proceed with the in-place upgrade!" -ForegroundColor Cyan