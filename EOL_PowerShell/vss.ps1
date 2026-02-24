#Requires -Version 5.1

<#
.SYNOPSIS
    Collects VSS Writer failure events from the past 3 days and exports to CSV + TXT.
.NOTES
    Run as Administrator for full event log access.
#>

# ── Configuration ────────────────────────────────────────────────────────────
$DaysBack   = 3
$OutputRoot = "C:\Logs\VSS_Reports"
$TimeStamp  = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutputDir  = Join-Path $OutputRoot $TimeStamp

# VSS-related Event IDs across Application + System logs
$VSSEventIDs = @(8193, 8194, 8196, 12289, 12291, 12293, 12298, 12302, 12306, 13, 14)

# ── Create output folder if it doesn't exist ──────────────────────────────────
if (-not (Test-Path -Path $OutputDir)) {
    try {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Output folder created: $OutputDir" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create output folder: $_"
        exit 1
    }
}

# ── Calculate start time ──────────────────────────────────────────────────────
$StartTime = (Get-Date).AddDays(-$DaysBack)

Write-Host "`n[INFO] Collecting VSS failure events from the past $DaysBack days..." -ForegroundColor Cyan
Write-Host "[INFO] Start time filter: $StartTime`n" -ForegroundColor Cyan

# ── Query event logs ──────────────────────────────────────────────────────────
$LogSources = @("Application", "System")
$AllEvents  = @()

foreach ($Log in $LogSources) {
    Write-Host "[QUERY] Searching '$Log' event log..." -ForegroundColor Yellow

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = $Log
            Id        = $VSSEventIDs
            StartTime = $StartTime
        } -ErrorAction Stop

        Write-Host "  --> Found $($Events.Count) event(s) in '$Log'" -ForegroundColor Green
        $AllEvents += $Events
    }
    catch [System.Exception] {
        if ($_.Exception.Message -match "No events were found") {
            Write-Host "  --> No matching events found in '$Log'" -ForegroundColor Gray
        }
        else {
            Write-Warning "  --> Error querying '$Log': $_"
        }
    }
}

# ── Also check the dedicated VSS/Operational log if accessible ────────────────
$VSSOperational = "Microsoft-Windows-VSS/Operational"
try {
    $OpsEvents = Get-WinEvent -FilterHashtable @{
        LogName   = $VSSOperational
        StartTime = $StartTime
    } -ErrorAction Stop

    Write-Host "[QUERY] Found $($OpsEvents.Count) event(s) in '$VSSOperational'" -ForegroundColor Green
    $AllEvents += $OpsEvents
}
catch {
    Write-Host "[QUERY] '$VSSOperational' not available or empty (this is normal)." -ForegroundColor Gray
}

# ── Process and export results ────────────────────────────────────────────────
if ($AllEvents.Count -eq 0) {
    Write-Host "`n[RESULT] No VSS failure events found in the past $DaysBack days. The server looks clean." -ForegroundColor Green
}
else {
    Write-Host "`n[RESULT] Total VSS events found: $($AllEvents.Count)" -ForegroundColor Magenta

    # Sort newest first
    $AllEvents = $AllEvents | Sort-Object TimeCreated -Descending

    # Build structured output
    $Structured = $AllEvents | Select-Object @{
        Name       = 'TimeCreated'
        Expression = { $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") }
    },
    @{
        Name       = 'EventID'
        Expression = { $_.Id }
    },
    LogName,
    ProviderName,
    LevelDisplayName,
    @{
        Name       = 'Message'
        Expression = { ($_.Message -replace "`r`n|`n", " ").Trim() }
    }

    # ── Export CSV ────────────────────────────────────────────────────────────
    $CsvPath = Join-Path $OutputDir "VSS_Events_$TimeStamp.csv"
    $Structured | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[EXPORT] CSV saved: $CsvPath" -ForegroundColor Green

    # ── Export readable TXT report ────────────────────────────────────────────
    $TxtPath = Join-Path $OutputDir "VSS_Events_$TimeStamp.txt"
    $Header  = @"
========================================================
  VSS Writer Failure Report
  Server   : $($env:COMPUTERNAME)
  Period   : $StartTime  -->  $(Get-Date)
  Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Total    : $($AllEvents.Count) event(s)
========================================================

"@
    $Header | Out-File -FilePath $TxtPath -Encoding UTF8

    foreach ($Event in $AllEvents) {
        $Block = @"
--------------------------------------------------------
Time      : $($Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"))
Event ID  : $($Event.Id)
Log       : $($Event.LogName)
Source    : $($Event.ProviderName)
Level     : $($Event.LevelDisplayName)
Message   :
$($Event.Message)

"@
        $Block | Out-File -FilePath $TxtPath -Append -Encoding UTF8
    }

    Write-Host "[EXPORT] TXT report saved: $TxtPath" -ForegroundColor Green

    # ── Console summary table ─────────────────────────────────────────────────
    Write-Host "`n[SUMMARY TABLE]" -ForegroundColor Cyan
    $Structured | Format-Table -AutoSize -Wrap
}

Write-Host "`n[DONE] Script completed. Output folder: $OutputDir`n" -ForegroundColor Cyan
```

---

## What to check & report back

Run the script as **Administrator** and let me know:

**1. Did the folder get created?**
Check that `C:\Logs\VSS_Reports\<timestamp>\` exists.

**2. What's the event count output?**
The console will show per-log counts like:
```
--> Found 12 event(s) in 'Application'
