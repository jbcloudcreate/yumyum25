<#
.SYNOPSIS
    Retrieves Exchange Online mailbox information and shared mailbox permissions.

.DESCRIPTION
    This script connects to Exchange Online and retrieves detailed mailbox information
    for a specified user. You only need to provide the alias (the part before the @ sign)
    and the script appends the hardcoded UPN domain suffix.

    The script implements delta processing by caching mailbox data locally and comparing
    against previous runs to highlight what has changed. It uses ExchangeGuid as the
    primary identifier for accuracy and performance.

    Optionally retrieves shared mailbox permissions (Full Access, Send As, Send on Behalf)
    and calendar access the user has been granted.

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
    - Shared mailbox permissions (if -IncludePermissions specified)
    - Calendar access (if -IncludeCalendars specified)

.NOTES
    Version:        0.4
    Author:         Exchange Admin Team
    Requires:       ExchangeOnlineManagement module
    Compatibility:  PowerShell 5.1+

    State file location: Same directory as script, named <ScriptName>_State.json

.EXAMPLE
    .\Get-MailboxInfo.ps1 -Alias "john.smith"

    Runs in default WhatIf mode - shows mailbox info for john.smith@<domain>
    without updating the state file.

.EXAMPLE
    .\Get-MailboxInfo.ps1 -Alias "john.smith" -Commit

    Retrieves mailbox info and saves current state to the local JSON file
    for future delta comparisons.

.EXAMPLE
    .\Get-MailboxInfo.ps1 -Alias "john.smith" -IncludeStatistics -Commit

    Retrieves mailbox info including mailbox statistics and commits state.

.EXAMPLE
    .\Get-MailboxInfo.ps1 -Alias "john.smith" -IncludePermissions

    Retrieves mailbox info and shows all shared mailboxes the user has
    Full Access, Send As, or Send on Behalf permissions to.

.EXAMPLE
    .\Get-MailboxInfo.ps1 -Alias "john.smith" -IncludePermissions -IncludeCalendars

    Retrieves mailbox info, shared mailbox permissions, and calendar access.
    Note: Calendar lookup is slower as it checks each shared mailbox individually.

.CHANGELOG
    0.4 - Shared mailbox and calendar permissions
        - Added -IncludePermissions switch for Full Access, Send As, Send on Behalf
        - Added -IncludeCalendars switch for calendar access (separate due to performance)
        - Progress indicators for permission lookups

    0.3 - Certificate-based authentication
        - Replaced interactive connection with certificate-based app authentication
        - Uses splatting for cleaner connection parameters

    0.2 - Interactive prompts
        - Added interactive prompt for alias when not provided
        - Added interactive prompt for commit confirmation

    0.1 - Initial version
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
    [switch]$Commit,

    [Parameter(Mandatory = $false, HelpMessage = "Include shared mailbox permissions (Full Access, Send As, Send on Behalf)")]
    [switch]$IncludePermissions,

    [Parameter(Mandatory = $false, HelpMessage = "Include calendar permissions (slower operation)")]
    [switch]$IncludeCalendars
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

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Mailbox Information Lookup v0.4" -ForegroundColor Cyan
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

<#$ExoSplat = @{
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

#>

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
            #Write-Host "[INFO] Retrieving mailbox statistics..." -ForegroundColor Gray
            try {
                $StatisticsData = Get-EXOMailboxStatistics -Identity $FullUPN -ErrorAction Stop
                
                $MailboxRecord['ItemCount'] = $StatisticsData.ItemCount
                $MailboxRecord['TotalItemSize'] = $StatisticsData.TotalItemSize.ToString()
                $MailboxRecord['DeletedItemCount'] = $StatisticsData.DeletedItemCount
                $MailboxRecord['TotalDeletedItemSize'] = $StatisticsData.TotalDeletedItemSize.ToString()
                $MailboxRecord['LastLogonTime'] = if ($StatisticsData.LastLogonTime) { $StatisticsData.LastLogonTime.ToString($UKDateFormat) } else { "Never" }
                
                #Write-Host "[OK] Statistics retrieved" -ForegroundColor Green
            }
            catch {
                #Write-Host "[WARN] Could not retrieve statistics: $($_.Exception.Message)" -ForegroundColor Yellow
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

#region Permissions Collection
# ============================================================================
# PERMISSIONS COLLECTION - Retrieve shared mailbox and calendar permissions
# ============================================================================

$PermissionsData = @{
    FullAccess   = @()
    SendAs       = @()
    SendOnBehalf = @()
    Calendars    = @()
}

if ($IncludePermissions -and $MailboxData) {
    Write-Host "`n[STEP] Retrieving shared mailbox permissions..." -ForegroundColor White

    try {
        # Get all shared mailboxes
        $SharedMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties DisplayName, PrimarySmtpAddress, GrantSendOnBehalfTo -ErrorAction Stop
        $TotalShared = ($SharedMailboxes | Measure-Object).Count
        Write-Host "[INFO] Found $TotalShared shared mailboxes to check" -ForegroundColor Gray

        # --- Full Access Permissions ---
        Write-Host "[INFO] Checking Full Access permissions..." -ForegroundColor Gray
        $ProgressCount = 0
        foreach ($SharedMbx in $SharedMailboxes) {
            $ProgressCount++
            Write-Progress -Activity "Checking Full Access Permissions" -Status "$ProgressCount of $TotalShared - $($SharedMbx.DisplayName)" -PercentComplete (($ProgressCount / $TotalShared) * 100)

            try {
                $FullAccessPerms = Get-EXOMailboxPermission -Identity $SharedMbx.PrimarySmtpAddress -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.User -like "*$FullUPN*" -and
                        $_.AccessRights -contains "FullAccess" -and
                        -not $_.IsInherited -and
                        -not $_.Deny
                    }

                if ($FullAccessPerms) {
                    $PermissionsData.FullAccess += [PSCustomObject]@{
                        MailboxName    = $SharedMbx.DisplayName
                        MailboxAddress = $SharedMbx.PrimarySmtpAddress
                    }
                }
            }
            catch {
                # Silently continue on individual mailbox errors
            }
        }
        Write-Progress -Activity "Checking Full Access Permissions" -Completed
        Write-Host "[OK] Full Access: Found $($PermissionsData.FullAccess.Count) shared mailboxes" -ForegroundColor Green

        # --- Send As Permissions ---
        Write-Host "[INFO] Checking Send As permissions..." -ForegroundColor Gray
        try {
            $SendAsPerms = Get-EXORecipientPermission -Trustee $FullUPN -ResultSize Unlimited -ErrorAction SilentlyContinue |
                Where-Object { $_.AccessRights -contains "SendAs" }

            foreach ($Perm in $SendAsPerms) {
                $PermissionsData.SendAs += [PSCustomObject]@{
                    MailboxName    = $Perm.Identity
                    MailboxAddress = $Perm.Identity
                }
            }
        }
        catch {
            Write-Host "[WARN] Could not retrieve Send As permissions: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        Write-Host "[OK] Send As: Found $($PermissionsData.SendAs.Count) mailboxes" -ForegroundColor Green

        # --- Send on Behalf Permissions ---
        Write-Host "[INFO] Checking Send on Behalf permissions..." -ForegroundColor Gray
        $SendOnBehalfMbx = $SharedMailboxes | Where-Object {
            $_.GrantSendOnBehalfTo -contains $MailboxData.DisplayName -or
            $_.GrantSendOnBehalfTo -like "*$FullUPN*"
        }

        foreach ($Mbx in $SendOnBehalfMbx) {
            $PermissionsData.SendOnBehalf += [PSCustomObject]@{
                MailboxName    = $Mbx.DisplayName
                MailboxAddress = $Mbx.PrimarySmtpAddress
            }
        }
        Write-Host "[OK] Send on Behalf: Found $($PermissionsData.SendOnBehalf.Count) shared mailboxes" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve shared mailboxes: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Calendar Permissions (separate due to performance) ---
if ($IncludeCalendars -and $MailboxData) {
    Write-Host "`n[STEP] Retrieving calendar permissions (this may take a while)..." -ForegroundColor White

    try {
        # Use the shared mailboxes we already retrieved, or get them if we haven't
        if (-not $SharedMailboxes) {
            $SharedMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties DisplayName, PrimarySmtpAddress -ErrorAction Stop
        }

        $TotalShared = ($SharedMailboxes | Measure-Object).Count
        $ProgressCount = 0

        foreach ($SharedMbx in $SharedMailboxes) {
            $ProgressCount++
            Write-Progress -Activity "Checking Calendar Permissions" -Status "$ProgressCount of $TotalShared - $($SharedMbx.DisplayName)" -PercentComplete (($ProgressCount / $TotalShared) * 100)

            $CalendarFolder = "$($SharedMbx.PrimarySmtpAddress):\Calendar"

            try {
                $CalPerms = Get-MailboxFolderPermission -Identity $CalendarFolder -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.User.DisplayName -eq $MailboxData.DisplayName -or
                        $_.User.DisplayName -like "*$($MailboxData.Alias)*" -or
                        ($_.User.ADRecipient.PrimarySmtpAddress -eq $FullUPN)
                    }

                foreach ($CalPerm in $CalPerms) {
                    # Skip default/anonymous entries
                    if ($CalPerm.User.DisplayName -in @('Default', 'Anonymous')) { continue }

                    $PermissionsData.Calendars += [PSCustomObject]@{
                        MailboxName  = $SharedMbx.DisplayName
                        MailboxAddress = $SharedMbx.PrimarySmtpAddress
                        AccessRights = ($CalPerm.AccessRights -join ", ")
                    }
                }
            }
            catch {
                # Silently continue on individual calendar errors
            }
        }
        Write-Progress -Activity "Checking Calendar Permissions" -Completed
        Write-Host "[OK] Calendars: Found $($PermissionsData.Calendars.Count) calendar permissions" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve calendar permissions: $($_.Exception.Message)" -ForegroundColor Red
    }
}

#endregion Permissions Collection

#region Delta Logic
# ============================================================================
# DELTA LOGIC - Compare with previous state
# ============================================================================

#Write-Host "`n[STEP] Processing delta comparison..." -ForegroundColor White

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
        
        #Write-Host "[OK] Previous state loaded from: $StateFilePath" -ForegroundColor Green
    }
    catch {
        #Write-Host "[WARN] Could not load previous state: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
else {
    #Write-Host "[INFO] No previous state file found. This is the first run." -ForegroundColor Gray
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
                #Write-Host "[DELTA] Changes detected for: $($CurrentRecord['DisplayName'])" -ForegroundColor Yellow
            }
            else {
                $Counters.Unchanged++
                #Write-Host "[INFO] No changes since last run" -ForegroundColor Gray
            }
        }
        else {
            $Counters.Changed++
            #Write-Host "[DELTA] New mailbox record (not in previous state)" -ForegroundColor Yellow
        }
    }
}

#endregion Delta Logic

#region Write Actions
# ============================================================================
# WRITE ACTIONS - Save state (respects WhatIf/Commit)
# ============================================================================

#Write-Host "`n[STEP] Processing state save..." -ForegroundColor White

if ($MailboxHashtable.Count -gt 0) {
    if ($Commit) {
        if ($PSCmdlet.ShouldProcess($StateFilePath, "Save current mailbox state")) {
            try {
                $MailboxHashtable | ConvertTo-Json -Depth 10 | Out-File -FilePath $StateFilePath -Encoding UTF8 -Force
                #Write-Host "[OK] State saved to: $StateFilePath" -ForegroundColor Green
            }
            catch {
                #Write-Host "[ERROR] Failed to save state: $($_.Exception.Message)" -ForegroundColor Red
                $Counters.Failed++
            }
        }
    }
    else {
        #Write-Host "[WHATIF] Would save state to: $StateFilePath" -ForegroundColor Magenta
        #Write-Host "[WHATIF] Use -Commit switch to actually save the state" -ForegroundColor Magenta
    }
}

#endregion Write Actions

#region Reporting / Export
# ============================================================================
# REPORTING / EXPORT - Display results
# ============================================================================

#Write-Host "`n========================================" -ForegroundColor Cyan
#Write-Host " MAILBOX INFORMATION REPORT" -ForegroundColor Cyan
#Write-Host " Retrieved: $RunTimestamp" -ForegroundColor Cyan
#Write-Host "========================================" -ForegroundColor Cyan

if ($MailboxHashtable.Count -gt 0) {
    foreach ($GuidKey in $MailboxHashtable.Keys) {
        $Record = $MailboxHashtable[$GuidKey]
        
        Write-Host "`n--- Mailbox Details ---" -ForegroundColor White
        Write-Host "Display Name:            $($Record['DisplayName'])"
        Write-Host "Primary SMTP:            $($Record['PrimarySmtpAddress'])"
        #Write-Host "UPN:                     $($Record['UserPrincipalName'])"
        Write-Host "Alias:                   $($Record['Alias'])"
        Write-Host "Exchange GUID:           $($Record['ExchangeGuid'])"
        Write-Host "Recipient Type:          $($Record['RecipientTypeDetails'])"
        Write-Host "Mailbox Enabled:         $($Record['IsMailboxEnabled'])"
        #Write-Host "Hidden from GAL:         $($Record['HiddenFromAddressListsEnabled'])"
        
        Write-Host "`n--- Quotas ---" -ForegroundColor White
        Write-Host "Issue Warning Quota:     $($Record['IssueWarningQuota'])"
        Write-Host "Prohibit Send Quota:     $($Record['ProhibitSendQuota'])"
        Write-Host "Prohibit Send/Receive:   $($Record['ProhibitSendReceiveQuota'])"
        
        #Write-Host "`n--- Forwarding ---" -ForegroundColor White
        #Write-Host "Forwarding Address:      $(if ($Record['ForwardingSmtpAddress']) { $Record['ForwardingSmtpAddress'] } else { 'None' })"
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
            #Write-Host "Last Logon:              $($Record['LastLogonTime'])"
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

    # Display permissions if requested
    if ($IncludePermissions) {
        Write-Host "`n--- Full Access Permissions ---" -ForegroundColor White
        if ($PermissionsData.FullAccess.Count -eq 0) {
            Write-Host "  No Full Access permissions found" -ForegroundColor Gray
        }
        else {
            foreach ($Perm in $PermissionsData.FullAccess) {
                Write-Host "  $($Perm.MailboxName)" -ForegroundColor White
                Write-Host "    Address: $($Perm.MailboxAddress)" -ForegroundColor Gray
            }
        }

        Write-Host "`n--- Send As Permissions ---" -ForegroundColor White
        if ($PermissionsData.SendAs.Count -eq 0) {
            Write-Host "  No Send As permissions found" -ForegroundColor Gray
        }
        else {
            foreach ($Perm in $PermissionsData.SendAs) {
                Write-Host "  $($Perm.MailboxName)" -ForegroundColor White
            }
        }

        Write-Host "`n--- Send on Behalf Permissions ---" -ForegroundColor White
        if ($PermissionsData.SendOnBehalf.Count -eq 0) {
            Write-Host "  No Send on Behalf permissions found" -ForegroundColor Gray
        }
        else {
            foreach ($Perm in $PermissionsData.SendOnBehalf) {
                Write-Host "  $($Perm.MailboxName)" -ForegroundColor White
                Write-Host "    Address: $($Perm.MailboxAddress)" -ForegroundColor Gray
            }
        }
    }

    # Display calendar permissions if requested
    if ($IncludeCalendars) {
        Write-Host "`n--- Calendar Access ---" -ForegroundColor White
        if ($PermissionsData.Calendars.Count -eq 0) {
            Write-Host "  No calendar permissions found" -ForegroundColor Gray
        }
        else {
            foreach ($Cal in $PermissionsData.Calendars) {
                Write-Host "  $($Cal.MailboxName)" -ForegroundColor White
                Write-Host "    Address: $($Cal.MailboxAddress)" -ForegroundColor Gray
                Write-Host "    Access:  $($Cal.AccessRights)" -ForegroundColor Gray
            }
        }
    }
}
else {
    Write-Host "`n[INFO] No mailbox data to display" -ForegroundColor Gray
}

# Summary counts
#Write-Host "`n========================================" -ForegroundColor Cyan
#Write-Host " SUMMARY" -ForegroundColor Cyan
#Write-Host "========================================" -ForegroundColor Cyan
#Write-Host "Total Read:      $($Counters.TotalRead)"
#Write-Host "Changed:         $($Counters.Changed)"
#Write-Host "Unchanged:       $($Counters.Unchanged)"
#Write-Host "Skipped:         $($Counters.Skipped)"
#Write-Host "Failed:          $($Counters.Failed)"
#Write-Host "----------------------------------------"
#Write-Host "Run Timestamp:   $RunTimestamp"
#Write-Host "Mode:            $(if ($Commit) { 'COMMIT' } else { 'WHATIF (Dry-Run)' })"

#endregion Reporting / Export

#region Cleanup
# ============================================================================
# CLEANUP - Stop timer and final output
# ============================================================================

$Stopwatch.Stop()
$Duration = $Stopwatch.Elapsed

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host ("[COMPLETE] Duration: {0:00}m {1:00}s" -f $Duration.Minutes, $Duration.Seconds, $Duration.Milliseconds) -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Return mailbox object for pipeline use if needed
#if ($MailboxHashtable.Count -gt 0) {
    #foreach ($GuidKey in $MailboxHashtable.Keys) {
        #[PSCustomObject]$MailboxHashtable[$GuidKey]
    #}
#}

#endregion Cleanup
