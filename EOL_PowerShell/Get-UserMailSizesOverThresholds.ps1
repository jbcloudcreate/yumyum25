<# Pull statistics for ALL mailboxes in one bulk call
# Filter down to only those over 90GB
# Get the detailed user info only for those few large mailboxes
# One bulk statistics call instead of thousands of individual calls
# Stores results in $LargeMailboxes for piping to email
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

# Get all user mailboxes
$allMailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, UserPrincipalName, DisplayName

# Pipeline the mailboxes to get stats in bulk - this should batch internally
$allStats = $allMailboxes | Get-EXOMailboxStatistics -Properties TotalItemSize, ItemCount, DeletedItemCount, TotalDeletedItemSize -ErrorAction SilentlyContinue

# Create lookup for mailbox details by DisplayName
$mailboxLookup = @{}
foreach ($mbx in $allMailboxes) {
    $mailboxLookup[$mbx.DisplayName] = $mbx
}

# Filter and process
$results = [System.Collections.Generic.List[object]]::new()

foreach ($stat in $allStats) {

    # Check size and check threshold
    $sizeBytes = 0
    if ($stat.TotalItemSize -match '\(([0-9,]+) bytes\)') {
        $sizeBytes = [long]($matches[1] -replace ',', '')
    }
    
    # Skip if under threshold
    if ($sizeBytes -lt ($ThresholdGB * 1GB)) { continue }
    
    # Get mailbox from lookup
    $mailbox = $mailboxLookup[$stat.DisplayName]
    if (-not $mailbox) { continue }
    
    # Get user details for name
    $user = Get-User -Identity $mailbox.UserPrincipalName -ErrorAction SilentlyContinue
    if (-not $user -or -not $user.LastName) { continue }
    
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
    
    $results.Add([PSCustomObject]@{
        FirstName        = $user.FirstName
        Surname          = $user.LastName
        EmailAddress     = $username
        UPN              = $mailbox.UserPrincipalName
        MaxQuota         = $quotaGB
        CurrentSize      = "$([math]::Round($sizeBytes / 1GB, 2)) GB"
        SizeBytes        = $sizeBytes
        ItemCount        = $stat.ItemCount
        DeletedItemCount = $stat.DeletedItemCount
        DeletedItemSize  = $deletedSizeGB
    })
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
    Write-Log "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds"
    Write-Log "----------------------------------------"
    
    # Log each large mailbox
    foreach ($user in $LargeMailboxes) {
        Write-Log "$($user.FirstName) $($user.Surname) | $($user.UPN) | $($user.CurrentSize) | Items: $($user.ItemCount)" "WARNING"
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

    foreach ($user in $LargeMailboxes) {

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
}
