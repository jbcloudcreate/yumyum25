<#
.SYNOPSIS
    Exports raw Event Viewer logs and Exchange state for the MB1/MB2 store outage
    (Windows patching 14/10/2026, silent store failures 15/10/2026) for offline / AI analysis.

.DESCRIPTION
    READ-ONLY against the Exchange servers. The only thing it creates on a server is a
    temporary export folder under C:\Windows\Temp, which it copies back and then removes
    (use -KeepRemoteTemp to leave it in place). Everything else is written under -OutRoot
    on the machine you run it from.

    Run it all at once, or one stage at a time with -Stage and check the output between stages.

      Stage 1  Events         Raw .evtx per server/log (wevtutil epl, time-filtered) + LocaleMetaData
      Stage 2  Text           Raw event XML + flattened CSV per server/log, plus 00-key-timeline.csv
      Stage 3  ExchangeState  Exchange cmdlet snapshots (copy status, queues, certs, patches,
                              boot times, delivery counts per hour, admin audit log)
      Stage 4  Package        MANIFEST.md (analysis steps + reference findings), SHA256SUMS.txt, .zip

.PARAMETER Start / End
    Time window in LOCAL time. Use the format 'yyyy-MM-dd HH:mm' to avoid date-order mix-ups.

.EXAMPLE
    .\Export-ExchStoreIncident.ps1
    Runs every stage with the default servers and window.

.EXAMPLE
    .\Export-ExchStoreIncident.ps1 -Stage Events
    .\Export-ExchStoreIncident.ps1 -Stage Text
    .\Export-ExchStoreIncident.ps1 -Stage ExchangeState
    .\Export-ExchStoreIncident.ps1 -Stage Package
    Step-by-step: check export-status.csv after Events before moving on.

.NOTES
    - Run from the Exchange Management Shell, elevated, with local admin on the Exchange servers
      (needs PowerShell remoting and the C$ admin share).
    - Run Stage 2 on an Exchange server so Exchange event messages render properly.
    - Data handling: exports contain server, database and account names. Message tracking is
      exported as hourly COUNTS only - no addresses or subjects. Store and share per SWP policy.
#>
[CmdletBinding()]
param(
    [string[]]$Servers = @('SWPHQ-MBS01','SWPHQ-MBS02','SWPHQ-MBS03','SWPFW-MBS04','SWPFW-MBS05'),
    [datetime]$Start   = '2026-10-14 08:00',
    [datetime]$End     = '2026-10-15 13:30',
    [string]$OutRoot   = 'C:\Temp\INC-ExchStore-20261015',
    [ValidateSet('All','Events','Text','ExchangeState','Package')]
    [string[]]$Stage   = 'All',
    [switch]$KeepRemoteTemp
)

# ---------------------------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------------------------
$Logs = @(
    'Application'
    'System'
    'Setup'
    'Microsoft-Exchange-HighAvailability/Operational'
    'Microsoft-Exchange-ManagedAvailability/RecoveryActionResults'
    'Microsoft-Exchange-ManagedAvailability/Monitoring'
    'Microsoft-Windows-WindowsUpdateClient/Operational'
    'Microsoft-Windows-TaskScheduler/Operational'
    'Microsoft-Windows-Windows Defender/Operational'
)

$RunId    = Get-Date -Format 'yyyyMMdd_HHmmss'
$EvtxDir  = Join-Path $OutRoot '1-evtx'
$TextDir  = Join-Path $OutRoot '2-text'
$StateDir = Join-Path $OutRoot '3-exchange-state'

# wevtutil filters on UTC SystemTime
$UtcFmt   = 'yyyy-MM-ddTHH:mm:ss.fffZ'
$StartUtc = $Start.ToUniversalTime().ToString($UtcFmt)
$EndUtc   = $End.ToUniversalTime().ToString($UtcFmt)
$XPath    = "*[System[TimeCreated[@SystemTime>='$StartUtc' and @SystemTime<='$EndUtc']]]"

function Write-Step([string]$Message) {
    Write-Host ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message) -ForegroundColor Cyan
}
function Get-SafeName([string]$LogName) { $LogName -replace '[\\/:*?"<>| ]', '_' }
function Test-Stage([string]$Name)      { ($Stage -contains 'All') -or ($Stage -contains $Name) }

# Which events go into the combined key-event timeline (the full logs are always exported too)
function Test-KeyEvent($Rec, [string]$Log) {
    switch ($Log) {
        'Application' {
            if ($Rec.Id -eq 12015) { return $false }          # expired transport cert - repeats every few minutes
            if ($Rec.Level -in 1, 2, 3) { return $true }      # critical / error / warning
            return ($Rec.Id -in 210, 213, 910, 913, 9002)     # ESE backup start/end, assistants stopped processing DB
        }
        'System' {
            if ($Rec.Id -in 41, 1074, 6005, 6006, 6008, 7031, 7032) { return $true }   # boots, shutdowns, service crashes
            if ($Rec.Id -eq 7036 -and $Rec.Message -match 'Windows Modules Installer|Windows Update|Microsoft Exchange') { return $true }
            return ($Rec.Level -in 1, 2)
        }
        'Microsoft-Windows-Windows Defender/Operational'    { return ($Rec.Id -ne 2010) }   # 2010 = routine cloud lookups
        'Microsoft-Windows-TaskScheduler/Operational'       { return ($Rec.Level -in 1, 2, 3) }
        'Microsoft-Exchange-ManagedAvailability/Monitoring' { return ($Rec.Level -in 1, 2, 3) }
        default { return $true }   # HA, MA recovery actions, Setup, Windows Update client: keep everything
    }
}

New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null
Write-Step "Output folder : $OutRoot"
Write-Step "Window (local): $($Start.ToString('yyyy-MM-dd HH:mm')) -> $($End.ToString('yyyy-MM-dd HH:mm'))   (UTC $StartUtc -> $EndUtc)"
Write-Step "Servers       : $($Servers -join ', ')"

# ---------------------------------------------------------------------------------------------
# Stage 1 - raw .evtx export
# ---------------------------------------------------------------------------------------------
if (Test-Stage 'Events') {
    Write-Step 'STAGE 1 - exporting raw .evtx files'
    New-Item -ItemType Directory -Path $EvtxDir -Force | Out-Null

    $status = foreach ($srv in $Servers) {
        Write-Step "  $srv"
        $remoteDir = "C:\Windows\Temp\IncExport_$RunId"
        try {
            $rows = Invoke-Command -ComputerName $srv -ErrorAction Stop -ArgumentList $Logs, $XPath, $remoteDir -ScriptBlock {
                param($Logs, $XPath, $Dir)
                New-Item -ItemType Directory -Path $Dir -Force | Out-Null
                foreach ($log in $Logs) {
                    if (-not (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue)) {
                        [pscustomobject]@{ Log = $log; Status = 'LogNotPresent'; Detail = '' }
                        continue
                    }
                    $file = Join-Path $Dir (($log -replace '[\\/:*?"<>| ]', '_') + '.evtx')
                    $out  = & wevtutil.exe epl $log $file "/q:$XPath" /ow:true 2>&1
                    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $file)) {
                        [pscustomobject]@{ Log = $log; Status = 'ExportFailed'; Detail = ($out -join ' ') }
                        continue
                    }
                    # Bundle display metadata so the .evtx opens with full messages on another machine
                    $null = & wevtutil.exe al $file /l:en-US 2>&1
                    [pscustomobject]@{ Log = $log; Status = 'Exported'; Detail = ('{0:N1} MB' -f ((Get-Item $file).Length / 1MB)) }
                }
            }

            $dest = Join-Path $EvtxDir $srv
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $unc = "\\$srv\C$\Windows\Temp\IncExport_$RunId"
            Copy-Item -Path "$unc\*" -Destination $dest -Recurse -Force -ErrorAction Stop
            if (-not $KeepRemoteTemp) { Remove-Item -Path $unc -Recurse -Force -ErrorAction SilentlyContinue }

            $rows | Select-Object @{ n = 'Server'; e = { $srv } }, Log, Status, Detail
        }
        catch {
            [pscustomobject]@{ Server = $srv; Log = '*'; Status = 'ServerFailed'; Detail = $_.Exception.Message }
        }
    }

    $status | Export-Csv (Join-Path $OutRoot 'export-status.csv') -NoTypeInformation -Encoding UTF8
    $status | Format-Table Server, Log, Status, Detail -AutoSize
    Write-Step 'STAGE 1 done - check export-status.csv before continuing'
}

# ---------------------------------------------------------------------------------------------
# Stage 2 - raw XML + flattened CSV + combined key-event timeline
# ---------------------------------------------------------------------------------------------
if (Test-Stage 'Text') {
    Write-Step 'STAGE 2 - converting to XML / CSV and building the key-event timeline'
    if (-not (Test-Path $EvtxDir)) { throw "No .evtx folder at $EvtxDir - run -Stage Events first." }
    New-Item -ItemType Directory -Path $TextDir -Force | Out-Null

    $safeToLog = @{}
    foreach ($l in $Logs) { $safeToLog[(Get-SafeName $l)] = $l }

    $timeline = New-Object System.Collections.Generic.List[object]

    foreach ($srvDir in Get-ChildItem $EvtxDir -Directory) {
        $srv     = $srvDir.Name
        $outDir  = Join-Path $TextDir $srv
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null

        foreach ($file in Get-ChildItem $srvDir.FullName -Filter *.evtx -File) {
            $base = $file.BaseName
            $log  = if ($safeToLog.ContainsKey($base)) { $safeToLog[$base] } else { $base }
            Write-Step "  $srv  $log"

            try   { $events = @(Get-WinEvent -Path $file.FullName -Oldest -ErrorAction Stop) }
            catch { $events = @() }   # "No events were found" is thrown for empty exports

            # Raw XML - full fidelity, every field Windows recorded (SystemTime is UTC)
            $xmlPath = Join-Path $outDir "$base.xml"
            $sw = New-Object System.IO.StreamWriter($xmlPath, $false, (New-Object System.Text.UTF8Encoding($false)))
            $sw.WriteLine('<?xml version="1.0" encoding="utf-8"?>')
            $sw.WriteLine("<Events server=""$srv"" log=""$log"" windowStartUtc=""$StartUtc"" windowEndUtc=""$EndUtc"">")
            foreach ($e in $events) { $sw.WriteLine($e.ToXml()) }
            $sw.WriteLine('</Events>')
            $sw.Close()

            # Flattened CSV - rendered messages, easier to read and search
            $rows = foreach ($e in $events) {
                $msg = $e.Message
                if ([string]::IsNullOrWhiteSpace($msg)) { $msg = '(message not rendered - see XML EventData)' }
                $row = [pscustomobject]@{
                    TimeLocal = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    TimeUtc   = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    Server    = $srv
                    Log       = $log
                    Provider  = $e.ProviderName
                    Id        = $e.Id
                    Level     = $e.LevelDisplayName
                    RecordId  = $e.RecordId
                    Message   = $msg.Trim()
                }
                if (Test-KeyEvent -Rec $e -Log $log) { $timeline.Add($row) }
                $row
            }
            if ($rows) { $rows | Export-Csv (Join-Path $outDir "$base.csv") -NoTypeInformation -Encoding UTF8 }
            else       { 'No events in window' | Out-File (Join-Path $outDir "$base.csv") -Encoding utf8 }
        }
    }

    $timeline | Sort-Object TimeUtc, Server |
        Export-Csv (Join-Path $TextDir '00-key-timeline.csv') -NoTypeInformation -Encoding UTF8
    Write-Step "STAGE 2 done - $($timeline.Count) events in 00-key-timeline.csv"
}

# ---------------------------------------------------------------------------------------------
# Stage 3 - Exchange state snapshots (current state + history the logs don't hold)
# ---------------------------------------------------------------------------------------------
if (Test-Stage 'ExchangeState') {
    Write-Step 'STAGE 3 - Exchange state snapshots'
    if (-not (Get-Command Get-MailboxDatabaseCopyStatus -ErrorAction SilentlyContinue)) {
        Write-Warning 'Exchange cmdlets not found - run Stage 3 from the Exchange Management Shell. Skipping.'
    }
    else {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

        function Save-State([string]$Name, [scriptblock]$Block) {
            Write-Step "  $Name"
            $path = Join-Path $StateDir $Name
            try {
                $data = @(& $Block)
                $data | Format-List * | Out-File "$path.txt" -Width 4096 -Encoding utf8
                if ($data.Count) { $data | Export-Csv "$path.csv" -NoTypeInformation -Encoding UTF8 }
            }
            catch {
                "FAILED: $($_.Exception.Message)" | Out-File "$path.txt" -Encoding utf8
                Write-Warning "$Name failed: $($_.Exception.Message)"
            }
        }

        Save-State '01-ExchangeServers' {
            Get-ExchangeServer | Select-Object Name, Site, ServerRole, Edition, AdminDisplayVersion
        }
        Save-State '02-BootTimes' {
            foreach ($s in $Servers) {
                Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $s -ErrorAction Stop |
                    Select-Object CSName, LastBootUpTime, Caption, Version
            }
        }
        Save-State '03-Hotfixes-Last30Days' {
            foreach ($s in $Servers) {
                Get-HotFix -ComputerName $s -ErrorAction Stop | Where-Object { $_.InstalledOn -ge $Start.AddDays(-30) } |
                    Select-Object CSName, HotFixID, Description, InstalledOn
            }
        }
        Save-State '04-DAG' {
            Get-DatabaseAvailabilityGroup -Status |
                Select-Object Name, Servers, OperationalServers, PrimaryActiveManager, WitnessServer, WitnessDirectory
        }
        Save-State '05-Databases' {
            Get-MailboxDatabase -Status |
                Select-Object Name, Server, Mounted, MountedOnServer, ActivationPreference, EdbFilePath, LogFolderPath,
                              CircularLoggingEnabled, LastFullBackup, LastIncrementalBackup, DatabaseSize
        }
        Save-State '06-DatabaseCopyStatus' {
            Get-MailboxDatabase | Get-MailboxDatabaseCopyStatus |
                Select-Object Name, Status, LastStatusTransitionTime, CopyQueueLength, ReplayQueueLength,
                              ContentIndexState, ErrorEventId, ErrorMessage, DiskFreeSpacePercent
        }
        Save-State '07-MapiConnectivity-NOW' {
            Get-MailboxDatabase | ForEach-Object { Test-MAPIConnectivity -Database $_.Name } |
                Select-Object MailboxServer, Database, Result, Error
        }
        Save-State '08-Queues-NOW' {
            Get-ExchangeServer | Where-Object IsHubTransportServer | ForEach-Object { Get-Queue -Server $_.Name } |
                Select-Object Identity, DeliveryType, Status, MessageCount, NextHopDomain, LastError
        }
        Save-State '09-ServerComponentState' {
            Get-ExchangeServer | ForEach-Object { Get-ServerComponentState -Identity $_.Name } |
                Select-Object ServerFqdn, Component, State
        }
        Save-State '10-Certificates' {
            foreach ($s in $Servers) {
                Get-ExchangeCertificate -Server $s |
                    Select-Object @{ n = 'Server'; e = { $s } }, Thumbprint, Subject, NotBefore, NotAfter, Services
            }
        }
        Save-State '11-AuthConfig' {
            Get-AuthConfig | Select-Object CurrentCertificateThumbprint, PreviousCertificateThumbprint,
                                           NextCertificateThumbprint, NextCertificateEffectiveDate
        }
        Save-State '12-AdminAudit-DatabaseActions' {
            Search-AdminAuditLog -StartDate $Start -EndDate (Get-Date) -Cmdlets Move-ActiveMailboxDatabase, Mount-Database,
                Dismount-Database, Suspend-MailboxDatabaseCopy, Resume-MailboxDatabaseCopy, Set-MailboxDatabase,
                Set-MailboxServer, Set-ServerComponentState |
                Select-Object RunDate, Caller, CmdletName, ObjectModified, Succeeded, Error,
                              @{ n = 'Parameters'; e = { ($_.CmdletParameters | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ' } }
        }
        Save-State '13-DeliveriesPerHour-CountsOnly' {
            foreach ($s in $Servers) {
                Get-MessageTrackingLog -Server $s -EventId DELIVER -Start $Start -End (Get-Date) -ResultSize Unlimited -ErrorAction Stop |
                    Group-Object { $_.Timestamp.ToString('yyyy-MM-dd HH:00') } |
                    ForEach-Object { [pscustomobject]@{ Server = $s; HourLocal = $_.Name; Delivered = $_.Count } }
            }
        }
        Write-Step 'STAGE 3 done'
    }
}

# ---------------------------------------------------------------------------------------------
# Stage 4 - manifest, hashes, zip
# ---------------------------------------------------------------------------------------------
if (Test-Stage 'Package') {
    Write-Step 'STAGE 4 - manifest, SHA256 hashes and zip'

    $manifest = @'
# Exchange store outage - raw evidence pack

Generated: {{GENERATED}}  |  Window (local, BST = UTC+1): {{START}} -> {{END}}
Servers: {{SERVERS}}

## Folder layout
| Folder / file | Contents |
|---|---|
| 1-evtx/<server>/*.evtx | Raw Windows event logs, time-filtered, with LocaleMetaData (opens in Event Viewer anywhere) |
| 2-text/<server>/*.xml | Raw event XML, every field. System/TimeCreated/@SystemTime is UTC |
| 2-text/<server>/*.csv | Same events flattened: TimeLocal, TimeUtc, Server, Log, Provider, Id, Level, RecordId, Message |
| 2-text/00-key-timeline.csv | All servers merged and sorted: errors/warnings plus key IDs (boots, HA, recovery actions, patching, backups) |
| 3-exchange-state/*.txt/.csv | Exchange cmdlet snapshots. Files marked NOW show state at export time (after recovery) |
| export-status.csv | What exported from each server and log |
| SHA256SUMS.txt | Hash of every file, for integrity |

Logs per server: Application, System, Setup, Exchange HighAvailability/Operational,
ManagedAvailability/RecoveryActionResults, ManagedAvailability/Monitoring,
WindowsUpdateClient/Operational, TaskScheduler/Operational, Windows Defender/Operational.

## Analysis steps (work through in order; cite Server + Log + RecordId for every finding)
1. Current state - 3-exchange-state 05, 06, 07, 08: which database is active where, copy health, queues.
2. Error signature - Application logs: MapiExceptionMdbOffline (ec=1142, StoreEc 0x476), Win32Error 0x6D8 (1752),
   MSExchange Mailbox Replication 1006, MSExchange Assistants 9042 / 9002. Which databases, which servers, first occurrence.
3. Database location history - HighAvailability/Operational IDs 337 (mount finished), 2037 (monitored DB started,
   IsActive), 837 (passive copy starting, names the active server), 2099 (dismount). Build a per-database timeline.
4. Patching - Setup log IDs 1/2/4 and 03-Hotfixes: which servers were patched, which KBs, when installs completed.
5. Boot times - System IDs 6005/6006/1074/6008 and 02-BootTimes.
6. Exact failure time per database - 13-DeliveriesPerHour (delivery stops) and the first 9042 per database.
7. Trigger search - for each failure time, list everything within 30 minutes either side: WindowsUpdateClient,
   TaskScheduler, Defender, System 7036, ESE backup 210/213/910/913. Separate routine/recurring activity from one-offs.
8. Self-healing - ManagedAvailability/RecoveryActionResults 500/501: what was attempted, and was the store targeted?
9. Pattern - compute time from patch reboot to failure for each affected server and compare.
10. Housekeeping - expired certificates (Application 12015, 403, 2010; 10-Certificates), backup history (05-Databases),
    MSExchangeIS 40013/40017 frequency over time, ADAccess 2070.
11. Conclude: root cause (confirmed vs probable), contributing factors, detection gap, recurrence risk, actions.

## Reference findings from the initial investigation (15/10/2026) - for validation, provisional
- MBS02 and MBS01 received KB5127685, KB5126650 and KB5126651 on 14/10; installs completed 09:10:39 (MBS02) and
  11:09:26 (MBS01). MBS03 was not patched. Patch completion used as a proxy for boot time - confirm with System 6005.
- MB2 active on MBS02 from 14/10 09:21:50. Last delivery 15/10 06:31:37; assistants 9042 from 06:32:02;
  MRS 1006 MdbOffline (ec=1142, 0x6D8) from 06:40:56.
- MB1 active on MBS01 from 14/10 11:33:07. Assistants 9042 from 15/10 08:28:41; MRS 1006 from 08:43:37.
- Patch-to-failure was about 21h20m on both servers. No one-off trigger found near either failure: WU scan at 06:29
  found 0 updates; TrustedInstaller runs hourly (~:18) as routine; Defender showed only 2010 cloud lookups; 06:01 backup succeeded.
- Active Manager kept reporting both databases Mounted, so no failover. Managed Availability only restarted MRS (06:40)
  and recycled the ECP app pool (06:47) - it never targeted the store. Silent failure for about 5 hours.
- Recovery: MB2 moved to MBS03 ~11:38, MB1 ~11:49 (manual); MBS01/MBS02 rebooted ~12:05; copies Healthy; MB2 back on
  MBS02 12:11; queues drained.
- Unrelated housekeeping: autodiscover cert 532EB0C2... expired 03/09/2026 and still bound to SMTP; Federation cert
  1F4CD6A0... and two Auth certs expired 2023; MB1 has no recorded backup; MB1 tombstone warnings (40013) pre-date
  patching; ADAccess 2070 to Azure/conf DCs every 15 min; MBS03's passive MB2 copy restarts hourly.
- Open risk: if the fault is uptime-related it may recur about 21h after the ~12:05 reboots (around 09:15-09:30 on 16/10).
'@
    $manifest = $manifest.Replace('{{GENERATED}}', (Get-Date -Format 'yyyy-MM-dd HH:mm'))
    $manifest = $manifest.Replace('{{START}}', $Start.ToString('yyyy-MM-dd HH:mm'))
    $manifest = $manifest.Replace('{{END}}', $End.ToString('yyyy-MM-dd HH:mm'))
    $manifest = $manifest.Replace('{{SERVERS}}', ($Servers -join ', '))
    $manifest | Out-File (Join-Path $OutRoot 'MANIFEST.md') -Encoding utf8

    $hashFile = Join-Path $OutRoot 'SHA256SUMS.txt'
    Get-ChildItem $OutRoot -Recurse -File | Where-Object FullName -ne $hashFile | ForEach-Object {
        $h = Get-FileHash $_.FullName -Algorithm SHA256
        '{0}  {1}' -f $h.Hash, $_.FullName.Substring($OutRoot.Length).TrimStart('\')
    } | Out-File $hashFile -Encoding utf8

    $zip = "$OutRoot.zip"
    Compress-Archive -Path (Join-Path $OutRoot '*') -DestinationPath $zip -Force
    Write-Step ("STAGE 4 done - {0} ({1:N1} MB)" -f $zip, ((Get-Item $zip).Length / 1MB))
}

Write-Step 'Finished.'
