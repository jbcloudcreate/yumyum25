<#
.SYNOPSIS
    Retrieves Exchange Online mailbox information using a partial alias lookup.

.DESCRIPTION
    This script connects to Exchange Online and retrieves detailed mailbox information
    for a specified user. You only need to provide the alias (the part before the @ sign)
    and the script appends the hardcoded UPN domain suffix.
    
    The script implements delta processing by caching mailbox data locally and comparing
    against previous runs to highlight what has changed. It uses ExchangeGuid as the
    primary identifier for accuracy and performance.
    
    By default, the script runs in WhatIf (dry-run) mode showing what would be retrieved
    without making any state file changes. Use -Commit to save the current state for
    future delta comparisons.

.OUTPUTS
    PSCustomObject containing mailbox properties including:
    - DisplayName, PrimarySmtpAddress, ExchangeGuid
    - MailboxType, RecipientTypeDetails
    - ProhibitSendQuota, ProhibitSendReceiveQuota
    - ItemCount, TotalItemSize (if statistics requested)
    - Delta changes from previous run (if state file exists)

.NOTES
    Version:        0.3
    Author:         Exchange Admin Team
    Requires:       ExchangeOnlineManagement module
    Compatibility:  PowerShell 5.1+
    
    State file location: Same directory as script, named <ScriptName>_State.json

.EXAMPLE
    .\Get-MailboxInfoByAlias.ps1 -Alias "john.smith"
    
    Runs in default WhatIf mode - shows mailbox info for john.smith@<domain> 
    without updating the state file.

    .\Get-MailboxInfoByAlias.ps1 -Alias "john.smith" -Commit
    
    Retrieves mailbox info and saves current state to the local JSON file 
    for future delta comparisons.

    .\Get-MailboxInfoByAlias.ps1 -Alias "john.smith" -IncludeStatistics -Commit
    
    Retrieves mailbox info including mailbox statistics and commits state.

.CHANGELOG
    0.3 — Certificate-based authentication
        - Replaced interactive connection with certificate-based app authentication
        - Uses splatting for cleaner connection parameters

    0.2 — Interactive prompts
        - Added interactive prompt for alias when not provided
        - Added interactive prompt for commit confirmation

    0.1 — Initial version
        - Basic mailbox lookup by alias
        - Delta processing with JSON state file
        - ExchangeGuid-based hashtable storage
        - UK date format throughout
        - WhatIf/Commit safety pattern
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Enter the alias (part before @ sign)")]
    [string]$Alias,

    [Parameter(Mandatory = $false, HelpMessage = "Include mailbox statistics")]
    [switch]$IncludeStatistics,

    [Parameter(Mandatory = $false, HelpMessage = "Commit changes to state file")]
    [switch]$Commit
)

# Prompt for alias if not provided
if ([string]::IsNullOrWhiteSpace($Alias)) {
    $Alias = Read-Host -Prompt "Enter the alias (part before @ sign)"
    if ([string]::IsNullOrWhiteSpace($Alias)) {
        Write-Host "[ERROR] Alias cannot be empty." -ForegroundColor Red
        exit 1
    }
}

# Prompt for commit if not specified
if (-not $PSBoundParameters.ContainsKey('Commit')) {
    $CommitResponse = Read-Host -Prompt "Do you want to commit changes to state file? (Y/N)"
    if ($CommitResponse -eq 'Y' -or $CommitResponse -eq 'y') {
        $Commit = $true
    }
}

#region Configuration
# ============================================================================
# CONFIGURATION - Edit these values as needed
# ============================================================================

# Hardcoded UPN domain suffix (edit this to match your tenant)
$UPNDomain = "@south-wales.police.uk"

# State file path (same directory as script)
$ScriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$StateFileName = "MailboxInfo_State.json"
$StateFilePath = Join-Path -Path $ScriptDirectory -ChildPath $StateFileName

# UK date format for logging
$UKDateFormat = "dd/MM/yyyy HH:mm:ss"
$UKDateFormatShort = "dd/MM/yyyy"

# Properties to retrieve from Get-EXOMailbox
$MailboxProperties = @(
    'DisplayName',
    'PrimarySmtpAddress',
    'UserPrincipalName',
    'ExchangeGuid',
    'Alias',
    'RecipientTypeDetails',
    'ProhibitSendQuota',
    'ProhibitSendReceiveQuota',
    'IssueWarningQuota',
    'WhenCreated',
    'WhenMailboxCreated',
    'IsMailboxEnabled',
    'HiddenFromAddressListsEnabled',
    'ForwardingSmtpAddress',
    'DeliverToMailboxAndForward',
    'ArchiveStatus',
    'ArchiveGuid',
    'LitigationHoldEnabled'
)

#endregion Configuration

#region Input / Filters
# ============================================================================
# INPUT / FILTERS - Build the full UPN from alias
# ============================================================================

# Construct full UPN from alias
$FullUPN = "{0}{1}" -f $Alias.Trim(), $UPNDomain

# Initialize counters hashtable
$Counters = @{
    TotalRead    = 0
    Changed      = 0
    Unchanged    = 0
    Skipped      = 0
    Failed       = 0
}

# Initialize stopwatch
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Timestamp for this run
$RunTimestamp = Get-Date -Format $UKDateFormat
$RunTimestampShort = Get-Date -Format $UKDateFormatShort

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Mailbox Information Lookup v0.3" -ForegroundColor Cyan
Write-Host " Run Date: $RunTimestamp" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "[INFO] Target UPN: $FullUPN" -ForegroundColor Yellow

if (-not $Commit) {
    Write-Host "[WHATIF] Running in dry-run mode. Use -Commit to save state." -ForegroundColor Magenta
}

#endregion Input / Filters

#region Exchange Connection
# ============================================
# CONNECT TO EXCHANGE ONLINE
# ============================================

$ExoSplat = @{
    CertificateThumbPrint = $ExchangeOnlineCertRO
    AppID = $ExchangeOnlineAppIDRO
    Organization = $SouthWalesPoliceOrg
    ShowBanner = $false
    ErrorAction = "stop"
}

# If the connection fails, we want it to exit here
try {
    Connect-ExchangeOnline @ExoSplat
}
catch {
    Write-Error $_
    exit
}

#endregion Exchange Connection

#region Data Collection
# ============================================================================
# DATA COLLECTION - Retrieve mailbox information
# ============================================================================

Write-Host "`n[STEP] Retrieving mailbox information..." -ForegroundColor White

# Hashtable keyed on ExchangeGuid for fast lookups
$MailboxHashtable = @{}
$MailboxData = $null
$StatisticsData = $null

try {
    # Get mailbox using Get-EXOMailbox (optimized for EXO)
    $MailboxData = Get-EXOMailbox -Identity $FullUPN -Properties $MailboxProperties -ErrorAction Stop
    
    if ($MailboxData) {
        $Counters.TotalRead++
        Write-Host "[OK] Mailbox found: $($MailboxData.DisplayName)" -ForegroundColor Green
        
        # Store in hashtable using ExchangeGuid as key
        $ExchangeGuidKey = $MailboxData.ExchangeGuid.ToString()
        
        # Build data object for storage
        $MailboxRecord = [ordered]@{
            ExchangeGuid                    = $ExchangeGuidKey
            DisplayName                     = $MailboxData.DisplayName
            PrimarySmtpAddress              = $MailboxData.PrimarySmtpAddress
            UserPrincipalName               = $MailboxData.UserPrincipalName
            Alias                           = $MailboxData.Alias
            RecipientTypeDetails            = $MailboxData.RecipientTypeDetails.ToString()
            ProhibitSendQuota               = $MailboxData.ProhibitSendQuota.ToString()
            ProhibitSendReceiveQuota        = $MailboxData.ProhibitSendReceiveQuota.ToString()
            IssueWarningQuota               = $MailboxData.IssueWarningQuota.ToString()
            WhenCreated                     = if ($MailboxData.WhenCreated) { $MailboxData.WhenCreated.ToString($UKDateFormat) } else { $null }
            WhenMailboxCreated              = if ($MailboxData.WhenMailboxCreated) { $MailboxData.WhenMailboxCreated.ToString($UKDateFormat) } else { $null }
            IsMailboxEnabled                = $MailboxData.IsMailboxEnabled
            HiddenFromAddressListsEnabled   = $MailboxData.HiddenFromAddressListsEnabled
            ForwardingSmtpAddress           = $MailboxData.ForwardingSmtpAddress
            DeliverToMailboxAndForward      = $MailboxData.DeliverToMailboxAndForward
            ArchiveStatus                   = $MailboxData.ArchiveStatus.ToString()
            ArchiveGuid                     = if ($MailboxData.ArchiveGuid) { $MailboxData.ArchiveGuid.ToString() } else { $null }
            LitigationHoldEnabled           = $MailboxData.LitigationHoldEnabled
            LastRetrieved                   = $RunTimestamp
        }
        
        # Get statistics if requested
        if ($IncludeStatistics) {
            Write-Host "[INFO] Retrieving mailbox statistics..." -ForegroundColor Gray
            try {
                $StatisticsData = Get-EXOMailboxStatistics -Identity $FullUPN -ErrorAction Stop
                
                $MailboxRecord['ItemCount'] = $StatisticsData.ItemCount
                $MailboxRecord['TotalItemSize'] = $StatisticsData.TotalItemSize.ToString()
                $MailboxRecord['DeletedItemCount'] = $StatisticsData.DeletedItemCount
                $MailboxRecord['TotalDeletedItemSize'] = $StatisticsData.TotalDeletedItemSize.ToString()
                $MailboxRecord['LastLogonTime'] = if ($StatisticsData.LastLogonTime) { $StatisticsData.LastLogonTime.ToString($UKDateFormat) } else { "Never" }
                
                Write-Host "[OK] Statistics retrieved" -ForegroundColor Green
            }
            catch {
                Write-Host "[WARN] Could not retrieve statistics: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        $MailboxHashtable[$ExchangeGuidKey] = $MailboxRecord
    }
}
catch {
    if ($_.Exception.Message -like "*couldn't be found*" -or $_.Exception.Message -like "*wasn't found*") {
        Write-Host "[WARN] Mailbox not found for: $FullUPN" -ForegroundColor Yellow
        $Counters.Skipped++
    }
    else {
        Write-Host "[ERROR] Failed to retrieve mailbox: $($_.Exception.Message)" -ForegroundColor Red
        $Counters.Failed++
    }
}

#endregion Data Collection

#region Delta Logic
# ============================================================================
# DELTA LOGIC - Compare with previous state
# ============================================================================

Write-Host "`n[STEP] Processing delta comparison..." -ForegroundColor White

$PreviousState = @{}
$DeltaChanges = @()

# Load previous state if exists
if (Test-Path -Path $StateFilePath) {
    try {
        $PreviousStateRaw = Get-Content -Path $StateFilePath -Raw -ErrorAction Stop | ConvertFrom-Json
        
        # Convert JSON back to hashtable
        foreach ($Item in $PreviousStateRaw.PSObject.Properties) {
            $PreviousState[$Item.Name] = @{}
            foreach ($Prop in $Item.Value.PSObject.Properties) {
                $PreviousState[$Item.Name][$Prop.Name] = $Prop.Value
            }
        }
        
        Write-Host "[OK] Previous state loaded from: $StateFilePath" -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Could not load previous state: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
else {
    Write-Host "[INFO] No previous state file found. This is the first run." -ForegroundColor Gray
}

# Compare current data with previous state
if ($MailboxHashtable.Count -gt 0) {
    foreach ($GuidKey in $MailboxHashtable.Keys) {
        $CurrentRecord = $MailboxHashtable[$GuidKey]
        
        if ($PreviousState.ContainsKey($GuidKey)) {
            $PreviousRecord = $PreviousState[$GuidKey]
            $ChangedProperties = @()
            
            # Compare each property (excluding LastRetrieved)
            foreach ($PropName in $CurrentRecord.Keys) {
                if ($PropName -eq 'LastRetrieved') { continue }
                
                $CurrentValue = $CurrentRecord[$PropName]
                $PreviousValue = $PreviousRecord[$PropName]
                
                if ($CurrentValue -ne $PreviousValue) {
                    $ChangedProperties += [PSCustomObject]@{
                        Property      = $PropName
                        PreviousValue = $PreviousValue
                        CurrentValue  = $CurrentValue
                    }
                }
            }
            
            if ($ChangedProperties.Count -gt 0) {
                $Counters.Changed++
                $DeltaChanges = $ChangedProperties
                Write-Host "[DELTA] Changes detected for: $($CurrentRecord['DisplayName'])" -ForegroundColor Yellow
            }
            else {
                $Counters.Unchanged++
                Write-Host "[INFO] No changes since last run" -ForegroundColor Gray
            }
        }
        else {
            $Counters.Changed++
            Write-Host "[DELTA] New mailbox record (not in previous state)" -ForegroundColor Yellow
        }
    }
}

#endregion Delta Logic

#region Write Actions
# ============================================================================
# WRITE ACTIONS - Save state (respects WhatIf/Commit)
# ============================================================================

Write-Host "`n[STEP] Processing state save..." -ForegroundColor White

if ($MailboxHashtable.Count -gt 0) {
    if ($Commit) {
        if ($PSCmdlet.ShouldProcess($StateFilePath, "Save current mailbox state")) {
            try {
                $MailboxHashtable | ConvertTo-Json -Depth 10 | Out-File -FilePath $StateFilePath -Encoding UTF8 -Force
                Write-Host "[OK] State saved to: $StateFilePath" -ForegroundColor Green
            }
            catch {
                Write-Host "[ERROR] Failed to save state: $($_.Exception.Message)" -ForegroundColor Red
                $Counters.Failed++
            }
        }
    }
    else {
        Write-Host "[WHATIF] Would save state to: $StateFilePath" -ForegroundColor Magenta
        Write-Host "[WHATIF] Use -Commit switch to actually save the state" -ForegroundColor Magenta
    }
}

#endregion Write Actions

#region Reporting / Export
# ============================================================================
# REPORTING / EXPORT - Display results
# ============================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " MAILBOX INFORMATION REPORT" -ForegroundColor Cyan
Write-Host " Retrieved: $RunTimestamp" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($MailboxHashtable.Count -gt 0) {
    foreach ($GuidKey in $MailboxHashtable.Keys) {
        $Record = $MailboxHashtable[$GuidKey]
        
        Write-Host "`n--- Mailbox Details ---" -ForegroundColor White
        Write-Host "Display Name:            $($Record['DisplayName'])"
        Write-Host "Primary SMTP:            $($Record['PrimarySmtpAddress'])"
        Write-Host "UPN:                     $($Record['UserPrincipalName'])"
        Write-Host "Alias:                   $($Record['Alias'])"
        Write-Host "Exchange GUID:           $($Record['ExchangeGuid'])"
        Write-Host "Recipient Type:          $($Record['RecipientTypeDetails'])"
        Write-Host "Mailbox Enabled:         $($Record['IsMailboxEnabled'])"
        #Write-Host "Hidden from GAL:         $($Record['HiddenFromAddressListsEnabled'])"
        
        Write-Host "`n--- Quotas ---" -ForegroundColor White
        Write-Host "Issue Warning Quota:     $($Record['IssueWarningQuota'])"
        Write-Host "Prohibit Send Quota:     $($Record['ProhibitSendQuota'])"
        Write-Host "Prohibit Send/Receive:   $($Record['ProhibitSendReceiveQuota'])"
        
        Write-Host "`n--- Forwarding ---" -ForegroundColor White
        Write-Host "Forwarding Address:      $(if ($Record['ForwardingSmtpAddress']) { $Record['ForwardingSmtpAddress'] } else { 'None' })"
        #Write-Host "Deliver to Mailbox:      $($Record['DeliverToMailboxAndForward'])"
        
       #Write-Host "`n--- Compliance ---" -ForegroundColor White
        #Write-Host "Litigation Hold:         $($Record['LitigationHoldEnabled'])"
        #Write-Host "Archive Status:          $($Record['ArchiveStatus'])"
        #Write-Host "Archive GUID:            $(if ($Record['ArchiveGuid'] -and $Record['ArchiveGuid'] -ne '00000000-0000-0000-0000-000000000000') { $Record['ArchiveGuid'] } else { 'N/A' })"
        
        Write-Host "`n--- Dates ---" -ForegroundColor White
        Write-Host "When Created:            $($Record['WhenCreated'])"
        Write-Host "Mailbox Created:         $($Record['WhenMailboxCreated'])"
        
        if ($IncludeStatistics -and $Record['ItemCount']) {
            Write-Host "`n--- Statistics ---" -ForegroundColor White
            Write-Host "Item Count:              $($Record['ItemCount'])"
            Write-Host "Total Size:              $($Record['TotalItemSize'])"
            Write-Host "Deleted Items:           $($Record['DeletedItemCount'])"
            Write-Host "Deleted Size:            $($Record['TotalDeletedItemSize'])"
            Write-Host "Last Logon:              $($Record['LastLogonTime'])"
        }
    }
    
    # Display delta changes if any
    if ($DeltaChanges.Count -gt 0) {
        Write-Host "`n--- Delta Changes Since Last Run ---" -ForegroundColor Yellow
        foreach ($Change in $DeltaChanges) {
            Write-Host "  $($Change.Property):" -ForegroundColor Yellow
            Write-Host "    Previous: $($Change.PreviousValue)" -ForegroundColor Gray
            Write-Host "    Current:  $($Change.CurrentValue)" -ForegroundColor White
        }
    }
}
else {
    Write-Host "`n[INFO] No mailbox data to display" -ForegroundColor Gray
}

# Summary counts
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Read:      $($Counters.TotalRead)"
Write-Host "Changed:         $($Counters.Changed)"
Write-Host "Unchanged:       $($Counters.Unchanged)"
Write-Host "Skipped:         $($Counters.Skipped)"
Write-Host "Failed:          $($Counters.Failed)"
Write-Host "----------------------------------------"
Write-Host "Run Timestamp:   $RunTimestamp"
Write-Host "Mode:            $(if ($Commit) { 'COMMIT' } else { 'WHATIF (Dry-Run)' })"

#endregion Reporting / Export

#region Cleanup
# ============================================================================
# CLEANUP - Stop timer and final output
# ============================================================================

$Stopwatch.Stop()
$Duration = $Stopwatch.Elapsed

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "[COMPLETE] Duration: {0:00}m {1:00}s" -f $Duration.Minutes, $Duration.Seconds -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Return mailbox object for pipeline use if needed
if ($MailboxHashtable.Count -gt 0) {
    foreach ($GuidKey in $MailboxHashtable.Keys) {
        [PSCustomObject]$MailboxHashtable[$GuidKey]
    }
}

#endregion Cleanup
