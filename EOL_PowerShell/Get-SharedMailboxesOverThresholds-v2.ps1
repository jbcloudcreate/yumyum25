<#
.SYNOPSIS
    Monitors shared mailbox sizes and sends alerts for mailboxes approaching storage limits.

.DESCRIPTION
    Connects to Exchange Online and retrieves all shared mailboxes in bulk.
    Filters mailboxes into two warning categories:
      - Unlicensed (40-50GB): Approaching the 50GB free tier limit
      - Licensed (85-100GB): Approaching the 100GB licensed limit

    For each category, the script:
      - Logs results to a file (C:\temp\SharedMailboxSizeReport.log)
      - Sends a summary email to the UC team with all flagged mailboxes
      - Sends individual warning emails to licensed mailboxes approaching their limit

.OUTPUTS 
    $global:UnlicensedMailboxes - Collection of unlicensed mailboxes in the 40-50GB range
    $global:LicensedMailboxes - Collection of licensed mailboxes in the 85-100GB range

.NOTES
    Requires: Exchange Online PowerShell module
    Requires: Pre-configured environment variables for certificate-based authentication in Powershell Universal
.EXAMPLE
.\SharedMailboxesOverThresholds-v2.ps1
#>

# ============================================
# CONNECT TO EXCHANGE ONLINE
# ============================================

# Connect-ExchangeOnline -CertificateThumbPrint "B9FED654D4DD7FB3F16A227FA760CBA13DD8A54D" -AppID "eeb65737-0d8c-4728-b376-fd33e5ca4258" -Organization "southwalespolice.onmicrosoft.com" -ShowBanner:$false

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

# Threshold ranges in GB
$UnlicensedMinGB = 40
$UnlicensedMaxGB = 50
$LicensedMinGB = 85
$LicensedMaxGB = 100

# START
Write-Host "Fetching all shared mailboxes..." -ForegroundColor Cyan

# Get all shared mailboxes and output to a message
$allMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, UserPrincipalName, DisplayName

Write-Host "Found $($allMailboxes.Count) shared mailboxes" -ForegroundColor Green

# Pipeline the mailboxes to get stats in bulk - this should batch internally
$allStats = $allMailboxes | Get-EXOMailboxStatistics -Properties TotalItemSize, ItemCount, DeletedItemCount, TotalDeletedItemSize -ErrorAction SilentlyContinue

# Create lookup for mailbox details by DisplayName
$mailboxLookup = @{}
foreach ($mbx in $allMailboxes) {
    $mailboxLookup[$mbx.DisplayName] = $mbx
}

# Filter and process - two separate collections
$unlicensedResults = [System.Collections.Generic.List[object]]::new()
$licensedResults = [System.Collections.Generic.List[object]]::new()

foreach ($stat in $allStats) {
        
    # Check size and check threshold
    $sizeBytes = 0
    if ($stat.TotalItemSize -match '\(([0-9,]+) bytes\)') {
        $sizeBytes = [long]($matches[1] -replace ',', '')
    }
    
    $sizeGB = [math]::Round($sizeBytes / 1GB, 2)
    
    # Skip if not in either threshold range
    $isUnlicensedRange = ($sizeGB -ge $UnlicensedMinGB -and $sizeGB -le $UnlicensedMaxGB)
    $isLicensedRange = ($sizeGB -ge $LicensedMinGB -and $sizeGB -le $LicensedMaxGB)
    
    if (-not $isUnlicensedRange -and -not $isLicensedRange) { continue }
    
    # Get mailbox from lookup
    $mailbox = $mailboxLookup[$stat.DisplayName]
    if (-not $mailbox) { continue }
    
    # For shared mailboxes, use DisplayName directly (no separate user object)
    $displayName = $mailbox.DisplayName
    if (-not $displayName) { continue }
    
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
    
    # Create the mailbox object for use with logging and email
    $mailboxObject = [PSCustomObject]@{
        DisplayName      = $displayName
        EmailAddress     = $username
        UPN              = $mailbox.UserPrincipalName
        MaxQuota         = $quotaGB
        CurrentSize      = "$sizeGB GB"
        SizeBytes        = $sizeBytes
        SizeGB           = $sizeGB
        ItemCount        = $stat.ItemCount
        DeletedItemCount = $stat.DeletedItemCount
        DeletedItemSize  = $deletedSizeGB
        Category         = if ($isUnlicensedRange) { "Unlicensed" } else { "Licensed" }
    }
    
    # Add to appropriate collection
    if ($isUnlicensedRange) {
        $unlicensedResults.Add($mailboxObject)
    }
    elseif ($isLicensedRange) {
        $licensedResults.Add($mailboxObject)
    }
}


# Stop stopwatch
$stopwatch.Stop()

Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green

# Store results for piping to email
$global:UnlicensedMailboxes = $unlicensedResults
$global:LicensedMailboxes = $licensedResults

# ============================================
# LOG TO FILE SECTION
# ============================================

# Log Configuration
$EnableLogging = $true
$LogFilePath = "C:\temp\SharedMailboxSizeReport.log" 


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
    Write-Log "Shared Mailbox Size Report - Run Started"
    Write-Log "========================================"
    Write-Log "Unlicensed Threshold: $UnlicensedMinGB-$UnlicensedMaxGB GB"
    Write-Log "Licensed Threshold: $LicensedMinGB-$LicensedMaxGB GB"
    Write-Log "Total shared mailboxes scanned: $($allMailboxes.Count)"
    Write-Log "Unlicensed mailboxes in range: $($unlicensedResults.Count)"
    Write-Log "Licensed mailboxes in range: $($licensedResults.Count)"
    Write-Log "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds"
    Write-Log "----------------------------------------"
    
    # Log unlicensed mailboxes details
    if ($unlicensedResults.Count -gt 0) {
        Write-Log "UNLICENSED MAILBOXES ($UnlicensedMinGB-$UnlicensedMaxGB GB):" "WARNING"
        foreach ($mbx in $UnlicensedMailboxes) {
            Write-Log "  $($mbx.DisplayName) | $($mbx.UPN) | $($mbx.CurrentSize) | Items: $($mbx.ItemCount)" "WARNING"
        }
    }
    
    # Log licensed mailbox details
    if ($licensedResults.Count -gt 0) {
        Write-Log "LICENSED MAILBOXES ($LicensedMinGB-$LicensedMaxGB GB):" "WARNING"
        foreach ($mbx in $LicensedMailboxes) {
            Write-Log "  $($mbx.DisplayName) | $($mbx.UPN) | $($mbx.CurrentSize) | Items: $($mbx.ItemCount)" "WARNING"
        }
    }
    # Log footer
    Write-Log "----------------------------------------"
    Write-Log "Report completed" "SUCCESS"
    Write-Log "========================================"
}

# ============================================
# SEND EMAIL NOTIFICATION
# ============================================

# Email Configuration
$SendEmails = $true  # Set to $true to actually send emails
$TestMode = $true     # Set to $true to send test emails to TestEmailAddress instead of real users
$TestEmailAddress = "james.buller@south-wales.police.uk"  # Recipient for TestMode
$MonitoredEmailAddress = @("james.buller@south-wales.police.uk", "another.user@south-wales.police.uk")  # Email addresses to receive mailbox summary
$FromAddress = "ICT Mailbox Notifications <ict-noreply@south-wales.police.uk>"
$SMTPServer = "smtp-in.swp.police.uk"

# LICENSED Email Template (85-100GB range)
$LicensedEmailSubject = "Shared Mailbox Storage Warning - Licensed Limit Approaching"
$LicensedEmailTemplate = @"
FYI users of  {DisplayName}

We are writing to inform you that a licensed shared mailbox under your management is approaching its maximum storage limit of 100GB.

Our records show that the shared mailbox '{DisplayName}' has reached {CurrentSize} of its 100GB licensed limit.

Current Mailbox Statistics:
- Mailbox: {DisplayName}
- Email Address: {UPN}
- Current Size: {CurrentSize}
- Maximum Licensed Limit: 100 GB
- Items in Mailbox: {ItemCount}
- Deleted Items: {DeletedItemCount} ({DeletedItemSize})

IMPORTANT: This mailbox will stop functioning when it reaches 100GB. Immediate action is required.

Please look at the following document for steps to reduce mailbox size: <Link here>

If the mailbox size is not reduced, it will be unable to send or receive new emails. We appreciate your urgent attention to this matter. 

If you have any questions or need assistance, please contact the ICT Service Desk:
Telephone: x20888 / 01656 869505 - ICTServiceDesk@south-wales.police.uk

Thank you for your cooperation. 

Best regards, 

---
This is an automated message. Please do not reply directly to this email.
"@

# Send summary email for ALL mailboxes (both licensed and unlicensed) to monitored address
if ($SendEmails -and ($UnlicensedMailboxes.Count -gt 0 -or $LicensedMailboxes.Count -gt 0)) {

    # Unlicensed mailbox list for the email 
    $unlicensedMailboxList = ""
    foreach ($mbx in $UnlicensedMailboxes | Sort-Object SizeGB -Descending) {
        $unlicensedMailboxList += "- $($mbx.DisplayName)`n"
        $unlicensedMailboxList += "  Email: $($mbx.UPN)`n"
        $unlicensedMailboxList += "  Current Size: $($mbx.CurrentSize)`n"
        $unlicensedMailboxList += "  Items: $($mbx.ItemCount) | Deleted Items: $($mbx.DeletedItemCount) ($($mbx.DeletedItemSize))`n"
        $unlicensedMailboxList += "`n"
    }

    # Licensed mailbox list for the email 
    $licensedMailboxList = ""
    foreach ($mbx in $LicensedMailboxes | Sort-Object SizeGB -Descending) {
        $licensedMailboxList += "- $($mbx.DisplayName)`n"
        $licensedMailboxList += "  Email: $($mbx.UPN)`n"
        $licensedMailboxList += "  Current Size: $($mbx.CurrentSize)`n"
        $licensedMailboxList += "  Items: $($mbx.ItemCount) | Deleted Items: $($mbx.DeletedItemCount) ($($mbx.DeletedItemSize))`n"
        $licensedMailboxList += "`n"
    }

    # Create summary email body
    $summaryEmailBody = @"
Unified Communication Team - Shared Mailbox Storage Alert
========================================

UNLICENSED MAILBOXES (40-50GB)
------------------------------
The following shared mailboxes are approaching the 50GB storage limit.
These mailboxes are currently unlicensed and will stop functioning when they reach 50GB.

Total Unlicensed Mailboxes in Warning Range: $($UnlicensedMailboxes.Count)

$(if ($UnlicensedMailboxes.Count -gt 0) { "Mailboxes Requiring Attention:`n$unlicensedMailboxList" } else { "No unlicensed mailboxes in warning range.`n" })
Recommended Actions for Unlicensed Mailboxes:
1. Review each mailbox and determine if it should remain unlicensed
2. For mailboxes that need to stay active:
   - Reduce mailbox size below 40GB, OR
   - Request a license to increase limit to 100GB


LICENSED MAILBOXES (85-100GB)
-----------------------------
The following licensed shared mailboxes are approaching their 100GB storage limit.
These mailboxes will stop functioning when they reach 100GB.

An email has been sent to alert them of this and potential actions.

Total Licensed Mailboxes in Warning Range: $($LicensedMailboxes.Count)

$(if ($LicensedMailboxes.Count -gt 0) { "Mailboxes Requiring Attention:`n$licensedMailboxList" } else { "No licensed mailboxes in warning range.`n" })
Recommended Actions for Licensed Mailboxes:
1. Review mailbox contents and remove unnecessary items
2. Empty Deleted Items and Junk folders
3. Archive old emails to reduce mailbox size
4. Save large attachments externally and remove from emails


========================================
SUMMARY
========================================
Total Unlicensed (40-50GB): $($UnlicensedMailboxes.Count)
Total Licensed (85-100GB): $($LicensedMailboxes.Count)
Combined Total: $($UnlicensedMailboxes.Count + $LicensedMailboxes.Count)

---
This is an automated report generated on $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
"@

    $summarySubject = "Shared Mailbox Report - $($UnlicensedMailboxes.Count) Unlicensed & $($LicensedMailboxes.Count) Licensed Mailbox(es) Approaching Limits"
    
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
        }
        
        Send-MailMessage @summaryEmailParams
    }
    catch {
        Write-Host "Failed to send summary email to: $summaryRecipient - $_" -ForegroundColor Red
    }
}

# Send Emails for LICENSED mailboxes
if ($SendEmails -and $LicensedMailboxes.Count -gt 0) {

    foreach ($mbx in $LicensedMailboxes) {
        
        # Build personalised email body
        $emailBody = $LicensedEmailTemplate -replace '{DisplayName}', $mbx.DisplayName `
                                            -replace '{CurrentSize}', $mbx.CurrentSize `
                                            -replace '{ItemCount}', $mbx.ItemCount `
                                            -replace '{DeletedItemCount}', $mbx.DeletedItemCount `
                                            -replace '{DeletedItemSize}', $mbx.DeletedItemSize `
                                            -replace '{UPN}', $mbx.UPN
        
        # Determine recipient - test account or shared mailbox address
        $recipient = if ($TestMode) { $TestEmailAddress } else { $mbx.UPN }
        
        # Modify subject in test mode
        $subject = if ($TestMode) { "[TEST - Intended for: $($mbx.UPN)] $LicensedEmailSubject" } else { $LicensedEmailSubject }
        
        try {
            $emailParams = @{
                From       = $FromAddress
                To         = $recipient
                Subject    = $subject
                Body       = $emailBody
                SmtpServer = $SMTPServer
            }
            
            Send-MailMessage @emailParams
        }
        catch {
            Write-Host "Failed to send email to: $recipient - $_" -ForegroundColor Red
        }
    }
}

