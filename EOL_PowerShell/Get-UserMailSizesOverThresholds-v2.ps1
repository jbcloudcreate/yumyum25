<#
.SYNOPSIS
    Monitors user mailbox sizes and sends alerts for mailboxes exceeding storage thresholds.

.DESCRIPTION
    Connects to Exchange Online and retrieves all user mailboxes in bulk.
    Filters mailboxes exceeding the 90GB threshold.

    For each mailbox over threshold, the script:
      - Logs results to a file (C:\temp\MailboxSizeReport.log)
      - Sends a summary email to the UC team with all flagged mailboxes
      - Sends individual warning emails to users approaching their limit

.OUTPUTS
    $global:LargeMailboxes - Collection of user mailboxes over the 90GB threshold

.NOTES
    Version: 2.0
    Author: James Buller
    Requires: Exchange Online PowerShell module
    Requires: Pre-configured environment variables for certificate-based authentication in Powershell Universal
    Requires: PowerShell 5.1+

.EXAMPLE
    .\Get-UserMailSizesOverThresholds.ps1

.CHANGELOG
    Version 2.0 - 22/01/2026
    - Removed Get-User calls - now parses FirstName/LastName from DisplayName
    - Changed hashtable lookup from DisplayName to ExchangeGuid for reliability
    - Added delta processing to avoid re-notifying users within cooldown period
    - Improved email sending with delta processing to reduce unnecessary sends
    - Pre-calculated threshold bytes to avoid repeated multiplication
    - Added SkipNotification tracking in results and logs
    - New configuration options: $EnableDeltaProcessing, $DeltaFilePath, $DeltaCooldownHours

    Version 1.0
    - Initial release
#>

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

# ============================================
# GET MAILBOX SIZES
# ============================================

#Start Stopwatch
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Threshold in GB
$ThresholdGB = 90
$ThresholdBytes = $ThresholdGB * 1GB

# Delta Processing Configuration
$EnableDeltaProcessing = $true
$DeltaFilePath = "C:\temp\MailboxSizeReport_LastRun.json"
$DeltaCooldownHours = 24  # Don't re-notify users within this period

# Load previous run data for delta processing
$previouslyNotified = @{}
if ($EnableDeltaProcessing -and (Test-Path $DeltaFilePath)) {
    try {
        $deltaData = Get-Content $DeltaFilePath -Raw | ConvertFrom-Json
        foreach ($entry in $deltaData) {
            $previouslyNotified[$entry.UPN] = [datetime]$entry.NotifiedAt
        }
    }
    catch {
        Write-Warning "Could not load delta file, processing all mailboxes: $_"
    }
}

# Get all user mailboxes with required properties only
$allMailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -Properties ExchangeGuid, ProhibitSendReceiveQuota, UserPrincipalName, DisplayName

# Create hashtable lookup by ExchangeGuid (more reliable than DisplayName)
$mailboxLookup = @{}
foreach ($mbx in $allMailboxes) {
    $mailboxLookup[$mbx.ExchangeGuid.ToString()] = $mbx
}

# Pipeline the mailboxes to get stats in bulk - this should batch internally
$allStats = $allMailboxes | Get-EXOMailboxStatistics -Properties TotalItemSize, ItemCount, DeletedItemCount, TotalDeletedItemSize -ErrorAction SilentlyContinue

# Filter and process using hashtables
$results = [System.Collections.Generic.List[object]]::new()
$newNotifications = [System.Collections.Generic.List[object]]::new()
$currentTime = Get-Date

foreach ($stat in $allStats) {

    # Check size and check threshold
    $sizeBytes = 0
    if ($stat.TotalItemSize -match '\(([0-9,]+) bytes\)') {
        $sizeBytes = [long]($matches[1] -replace ',', '')
    }

    # Skip if under threshold
    if ($sizeBytes -lt $ThresholdBytes) { continue }

    # Get mailbox from hashtable using MailboxGuid
    $mailbox = $mailboxLookup[$stat.MailboxGuid.ToString()]
    if (-not $mailbox) { continue }

    # Parse FirstName and LastName from DisplayName (eliminates Get-User call)
    # Handles formats: "LastName, FirstName" or "FirstName LastName"
    $firstName = ""
    $lastName = ""
    $displayName = $mailbox.DisplayName

    if ($displayName -match '^(.+),\s*(.+)$') {
        # Format: "LastName, FirstName"
        $lastName = $matches[1].Trim()
        $firstName = $matches[2].Trim()
    }
    elseif ($displayName -match '^(\S+)\s+(.+)$') {
        # Format: "FirstName LastName"
        $firstName = $matches[1].Trim()
        $lastName = $matches[2].Trim()
    }
    else {
        # Single name - use as both
        $firstName = $displayName
        $lastName = $displayName
    }

    # Skip if we couldn't parse a name
    if (-not $lastName) { continue }

    # Delta processing - check if user was recently notified
    $skipNotification = $false
    if ($EnableDeltaProcessing -and $previouslyNotified.ContainsKey($mailbox.UserPrincipalName)) {
        $lastNotified = $previouslyNotified[$mailbox.UserPrincipalName]
        if (($currentTime - $lastNotified).TotalHours -lt $DeltaCooldownHours) {
            $skipNotification = $true
        }
    }

    # Change deleted size to show as GB only
    $deletedSizeGB = "0 GB"
    if ($stat.TotalDeletedItemSize -match '\(([0-9,]+) bytes\)') {
        $deletedBytes = [long]($matches[1] -replace ',', '')
        $deletedSizeGB = "$([math]::Round($deletedBytes / 1GB, 2)) GB"
    }

    # Change quota size to show as GB only
    $quotaGB = "Unlimited"
    if ($mailbox.ProhibitSendReceiveQuota -match '\(([0-9,]+) bytes\)') {
        $quotaBytes = [long]($matches[1] -replace ',', '')
        $quotaGB = "$([math]::Round($quotaBytes / 1GB, 2)) GB"
    }

    # Drop the UPN for easier to read output to log
    $username = ($mailbox.UserPrincipalName -split '@')[0]

    $resultObj = [PSCustomObject]@{
        FirstName           = $firstName
        Surname             = $lastName
        EmailAddress        = $username
        UPN                 = $mailbox.UserPrincipalName
        MaxQuota            = $quotaGB
        CurrentSize         = "$([math]::Round($sizeBytes / 1GB, 2)) GB"
        SizeBytes           = $sizeBytes
        ItemCount           = $stat.ItemCount
        DeletedItemCount    = $stat.DeletedItemCount
        DeletedItemSize     = $deletedSizeGB
        SkipNotification    = $skipNotification
    }

    $results.Add($resultObj)

    # Track for delta file update
    if (-not $skipNotification) {
        $newNotifications.Add([PSCustomObject]@{
            UPN        = $mailbox.UserPrincipalName
            NotifiedAt = $currentTime.ToString('o')
        })
    }
}

# Stop stopwatch
$stopwatch.Stop()

Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green

# Store results for piping to email
$global:LargeMailboxes = $results

# ============================================
# LOG TO FILE SECTION
# ============================================

# Log Configuration
$EnableLogging = $true
$LogFilePath = "C:\temp\MailboxSizeReport.log"  # Update with your server path


# Logging Function
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Append to log file
    if ($EnableLogging) {
        Add-Content -Path $LogFilePath -Value $logEntry -ErrorAction SilentlyContinue
    }
        
}

# Write Log Entries
if ($EnableLogging) {
    # Log header
    Write-Log "========================================"
    Write-Log "Mailbox Size Report - Run Started"
    Write-Log "========================================"
    Write-Log "Threshold: $ThresholdGB GB"
    Write-Log "Total mailboxes scanned: $($allMailboxes.Count)"
    Write-Log "Mailboxes over threshold: $($results.Count)"
    Write-Log "Delta processing: $(if ($EnableDeltaProcessing) { 'Enabled' } else { 'Disabled' })"
    if ($EnableDeltaProcessing) {
        $skippedCount = ($LargeMailboxes | Where-Object { $_.SkipNotification }).Count
        Write-Log "Users to notify: $($LargeMailboxes.Count - $skippedCount) (Skipped due to cooldown: $skippedCount)"
    }
    Write-Log "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds"
    Write-Log "----------------------------------------"

    # Log each large mailbox
    foreach ($user in $LargeMailboxes) {
        $skipStatus = if ($user.SkipNotification) { " [SKIPPED - Within cooldown]" } else { "" }
        Write-Log "$($user.FirstName) $($user.Surname) | $($user.UPN) | $($user.CurrentSize) | Items: $($user.ItemCount)$skipStatus" "WARNING"
    }

    Write-Log "----------------------------------------"
    Write-Log "Report completed" "SUCCESS"
    Write-Log "========================================"
}
# Write Log Entries

# ============================================
# SEND EMAIL NOTIFICATION
# ============================================

# Email Configuration
$SendEmails = $true  # Set to $true to actually send emails
$TestMode = $true     # Set to $true to send test emails to TestEmailAddress instead of real users
$TestEmailAddress = "james.buller@south-wales.police.uk"  # Test recipient for TestMode
$MonitoredEmailAddress = "james.buller@south-wales.police.uk"  # Email address to receive mailbox summary
$FromAddress = "ICT Mailbox Notifications <ict-noreply@south-wales.police.uk>"
$SMTPServer = "smtp-in.swp.police.uk"
$EmailSubject = "Mailbox Storage Warning - Action Required"

# Email Template
$EmailBodyTemplate = @"
Dear {FirstName}, 

We are writing to inform you that your mailbox size has exceeded the recommended limit. To ensure you can continue to send and receive emails without any interruptions, we kindly ask you to reduce your mailbox size. 

Our records show that your mailbox has reached {CurrentSize} of your {MaxQuota} allocated storage.

Current Mailbox Statistics:
- Current Size: {CurrentSize}
- Maximum Quota: {MaxQuota}
- Items in Mailbox: {ItemCount}
- Deleted Items: {DeletedItemCount} ({DeletedItemSize})

Please look at the following document for steps to reduce mailbox size: <Link here>

If the mailbox size is not reduced, it will be unable to send or receive new emails. 

We appreciate your urgent attention to this matter. 
If you have any questions or need assistance, please do not hesitate to contact the ICT Service Desk 
Telephone: x20888 / 01656 869505 - ICTServiceDesk@south-wales.police.uk

Thank you for your cooperation. 

Best regards, 

---
This is an automated message. Please do not reply directly to this email.
"@

# Send summary email to UC team
if ($SendEmails -and $LargeMailboxes.Count -gt 0) {

    # Build mailbox list for the summary email
    $mailboxList = ""
    foreach ($user in $LargeMailboxes | Sort-Object SizeBytes -Descending) {
        $mailboxList += "- $($user.FirstName) $($user.Surname)`n"
        $mailboxList += "  Email: $($user.UPN)`n"
        $mailboxList += "  Current Size: $($user.CurrentSize) / $($user.MaxQuota)`n"
        $mailboxList += "  Items: $($user.ItemCount) | Deleted Items: $($user.DeletedItemCount) ($($user.DeletedItemSize))`n"
        $mailboxList += "`n"
    }

    # Create summary email body
    $summaryEmailBody = @"
Unified Communication Team - User Mailbox Storage Alert
========================================

USER MAILBOXES OVER ${ThresholdGB}GB
------------------------------
The following user mailboxes have exceeded the ${ThresholdGB}GB storage threshold.
These users have been sent individual notification emails.

Total Mailboxes Over Threshold: $($LargeMailboxes.Count)

Mailboxes Requiring Attention:
$mailboxList
Recommended Actions:
1. Review each mailbox and contact user if necessary
2. Ensure users are following mailbox management guidelines
3. Consider archiving options for heavy email users

========================================
SUMMARY
========================================
Threshold: ${ThresholdGB}GB
Total Mailboxes Scanned: $($allMailboxes.Count)
Mailboxes Over Threshold: $($LargeMailboxes.Count)

---
This is an automated report generated on $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
"@

    $summarySubject = "User Mailbox Report - $($LargeMailboxes.Count) Mailbox(es) Over ${ThresholdGB}GB Threshold"

    # Determine recipient based on test mode
    $summaryRecipient = if ($TestMode) { $TestEmailAddress } else { $MonitoredEmailAddress }
    $summarySubject = if ($TestMode) { "[TEST] $summarySubject" } else { $summarySubject }

    try {
        $summaryEmailParams = @{
            From       = $FromAddress
            To         = $summaryRecipient
            Subject    = $summarySubject
            Body       = $summaryEmailBody
            SmtpServer = $SMTPServer
            Priority   = 'High'
        }

        Send-MailMessage @summaryEmailParams
    }
    catch {
        Write-Host "Failed to send summary email to: $summaryRecipient - $_" -ForegroundColor Red
    }
}

# Send individual user emails
if ($SendEmails -and $LargeMailboxes.Count -gt 0) {

    # Filter to only users who should receive notifications (delta processing)
    $usersToNotify = $LargeMailboxes | Where-Object { -not $_.SkipNotification }

    if ($usersToNotify.Count -gt 0) {
        foreach ($user in $usersToNotify) {

            # Build personalised email body
            $emailBody = $EmailBodyTemplate -replace '{FirstName}', $user.FirstName `
                                            -replace '{Surname}', $user.Surname `
                                            -replace '{CurrentSize}', $user.CurrentSize `
                                            -replace '{MaxQuota}', $user.MaxQuota `
                                            -replace '{ItemCount}', $user.ItemCount `
                                            -replace '{DeletedItemCount}', $user.DeletedItemCount `
                                            -replace '{DeletedItemSize}', $user.DeletedItemSize

            # Determine recipient - test account or real user
            $recipient = if ($TestMode) { $TestEmailAddress } else { $user.UPN }

            # Modify subject in test mode to show intended recipient
            $subject = if ($TestMode) { "[TEST - Intended for: $($user.UPN)] $EmailSubject" } else { $EmailSubject }

            try {
                $emailParams = @{
                    From       = $FromAddress
                    To         = $recipient
                    Subject    = $subject
                    Body       = $emailBody
                    SmtpServer = $SMTPServer
                    Priority   = 'High'
                }

                Send-MailMessage @emailParams
            }
            catch {
                Write-Host "Failed to send email to: $recipient - $_" -ForegroundColor Red
            }
        }

        Write-Host "Sent $($usersToNotify.Count) notification emails" -ForegroundColor Green
    }
    else {
        Write-Host "No new notifications to send (all users within cooldown period)" -ForegroundColor Yellow
    }
}

# ============================================
# SAVE DELTA PROCESSING DATA
# ============================================
if ($EnableDeltaProcessing -and $newNotifications.Count -gt 0) {
    try {
        # Merge new notifications with existing (keeping recent entries)
        $cutoffTime = $currentTime.AddHours(-$DeltaCooldownHours * 2)  # Keep 2x cooldown period
        $mergedNotifications = @()

        # Keep existing entries that are still within retention period
        foreach ($upn in $previouslyNotified.Keys) {
            if ($previouslyNotified[$upn] -gt $cutoffTime) {
                $mergedNotifications += [PSCustomObject]@{
                    UPN        = $upn
                    NotifiedAt = $previouslyNotified[$upn].ToString('o')
                }
            }
        }

        # Add new notifications (overwriting if exists)
        $existingUPNs = $mergedNotifications | ForEach-Object { $_.UPN }
        foreach ($notification in $newNotifications) {
            if ($notification.UPN -notin $existingUPNs) {
                $mergedNotifications += $notification
            }
            else {
                # Update existing entry
                $mergedNotifications | Where-Object { $_.UPN -eq $notification.UPN } | ForEach-Object {
                    $_.NotifiedAt = $notification.NotifiedAt
                }
            }
        }

        $mergedNotifications | ConvertTo-Json -Depth 2 | Set-Content -Path $DeltaFilePath -Force
        Write-Host "Delta file updated with $($newNotifications.Count) new entries" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to save delta file: $_"
    }
}
