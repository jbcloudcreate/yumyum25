# MTR-ProMgmt-Diag.ps1
# Purpose: Side-by-side diagnostics for Teams Rooms Pro Management visibility issues

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$hostName = $env:COMPUTERNAME
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$outRoot = "C:\Temp"
$newDir = Join-Path $outRoot "MTR_ProMgmtDiag-$hostName-$stamp"
New-Item -ItemType Directory -Path $newDir -Force | Out-Null

# Helper
function Safe-GetReg {
  param($Path,$Name)
  try {
    (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
  } catch { $null }
}

# 1) Core versions & OS
$core = [ordered]@{
  Hostname   = $hostName
  OSVersion  = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId, `
               (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion -join " "
  Build      = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
  UBR        = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
}

# 2) Teams Rooms App version (best-effort from installed apps + common paths)
$apps = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Teams Rooms*" -or $_.DisplayName -like "*Skype Room System*" } |
        Select-Object DisplayName, DisplayVersion, InstallDate
$core.MTRApp = $apps

# 3) Sign-in hint (from common log location)
$logRoot = "C:\ProgramData\Microsoft\TeamsRooms\Logs"
if (Test-Path $logRoot) {
  $latestLog = Get-ChildItem $logRoot -File -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  $core.LatestLog = $latestLog.FullName
}

# 4) Proxy & WinHTTP
$proxy = @{
  WinHTTP = (cmd /c 'netsh winhttp show proxy') -join "`n"
  IEProxy = Safe-GetReg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer
  AutoConfigURL = Safe-GetReg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name AutoConfigURL
}
$core.Proxy = $proxy

# 5) Time & NTP
$time = @{
  Status = (w32tm /query /status) -join "`n"
  Config = (w32tm /query /configuration) -join "`n"
}
$core.Time = $time

# 6) Device identity (AAD/Entra) – best effort
$dsregcmd = (dsregcmd /status) -join "`n"
$core.DeviceJoin = $dsregcmd

# 7) Services, Scheduled Tasks, WMI presence
$services = Get-Service | Where-Object { $_.Name -match 'Teams|Skype|Room|MTR' -or $_.DisplayName -match 'Teams|Skype|Room|MTR' } |
            Select-Object Name, DisplayName, Status, StartType
$core.Services = $services

$tasks = Get-ScheduledTask | Where-Object { $_.TaskName -match 'Teams|Room|Skype|MTR' -or $_.TaskPath -match 'Teams|Room|Skype|MTR' } |
         Select-Object TaskName, TaskPath, State
$core.ScheduledTasks = $tasks

# WMI namespace probe
try {
  $wmi = Get-WmiObject -Namespace root\TeamsRooms -Class DeviceStatus -ErrorAction Stop | Select-Object *
} catch { $wmi = $null }
$core.WMI_DeviceStatus = $wmi

# 8) Endpoint reachability tests
$targets = @(
  'rooms.microsoft.com',
  'login.microsoftonline.com',
  'graph.microsoft.com',
  'microsoft.com',
  'teams.microsoft.com',
  'azureedge.net'
)
$reach = foreach ($t in $targets) {
  [pscustomobject]@{
    Target = $t
    TNC443 = (Test-NetConnection $t -Port 443 -InformationLevel Quiet)
    DNS    = (Resolve-DnsName $t -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)
  }
}
$core.Reachability = $reach

# 9) Export event logs (last 3 days)
$evPath = Join-Path $newDir "EventLogs"
New-Item -ItemType Directory $evPath | Out-Null
wevtutil epl "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" (Join-Path $evPath "MDM-CSP.evtx") /q:"*[System[TimeCreated[timediff(@SystemTime) <= 259200000]]]"
wevtutil epl "Microsoft-Windows-WinINet/Analytic" (Join-Path $evPath "WinINet.evtx")
wevtutil epl "Application" (Join-Path $evPath "Application.evtx") /q:"*[System[TimeCreated[timediff(@SystemTime) <= 259200000]]]"

# 10) Copy Teams Rooms logs (if present)
if (Test-Path $logRoot) {
  $destLogs = Join-Path $newDir "TeamsRoomsLogs"
  robocopy $logRoot $destLogs /E /NFL /NDL /NJH /NJS /NC /NS | Out-Null
}

# 11) Save JSON summary
$core | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $newDir "summary.json") -Encoding UTF8

# 12) ZIP it
Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
$zipPath = Join-Path $outRoot "MTR_ProMgmtDiag-$hostName.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($newDir, $zipPath)

Write-Host "Diagnostics complete: $zipPath"
