# Start-Win11-BypassUpgrade.ps1
# Author: ChatGPT
# Purpose: In-place upgrade to Windows 11 on unsupported hardware by bypassing TPM, Secure Boot, and CPU checks

# -------- SETTINGS --------
$isoPath = "C:\ISOs\Win11.iso"   # ✅ Set the path to your ISO file here

# -------- CHECKS --------
if (-not (Test-Path $isoPath)) {
    Write-Error "❌ Windows 11 ISO not found at: $isoPath"
    exit
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
    Write-Warning "⚠️ Please run this PowerShell session as Administrator."
    exit
}

Write-Host "🛠️ Adding registry key to allow upgrade on unsupported hardware..." -ForegroundColor Cyan

# -------- REGISTRY TWEAK --------
try {
    New-Item -Path "HKLM:\SYSTEM\Setup\MoSetup" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\Setup\MoSetup" -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -Type DWord
    Write-Host "✅ Registry key applied." -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to apply registry key. Error: $_"
    exit
}

# -------- MOUNT ISO --------
Write-Host "📀 Mounting ISO: $isoPath" -ForegroundColor Cyan
try {
    $mountResult = Mount-DiskImage -ImagePath $isoPath -PassThru
    Start-Sleep -Seconds 2
    $vol = ($mountResult | Get-Volume)
    $driveLetter = $vol.DriveLetter + ":"
    Write-Host "✅ ISO mounted at $driveLetter" -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to mount ISO. Error: $_"
    exit
}

# -------- RUN SETUP.EXE --------
$setupExe = Join-Path -Path $driveLetter -ChildPath "setup.exe"

if (-not (Test-Path $setupExe)) {
    Write-Error "❌ setup.exe not found inside mounted ISO at $setupExe"
    exit
}

Write-Host "🚀 Launching Windows 11 Setup..." -ForegroundColor Cyan
Start-Process -FilePath $setupExe -ArgumentList "/auto upgrade /compat IgnoreWarning" -Wait

Write-Host "`n🎉 Setup started! Follow the on-screen instructions to complete your in-place upgrade." -ForegroundColor Green
