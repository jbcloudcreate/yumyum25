<# Pull statistics for ALL shared mailboxes in one bulk call
# Filter into two categories:
#   - Unlicensed (40-50GB): Approaching free tier limit
#   - Licensed (85-100GB): Approaching licensed tier limit
# One bulk statistics call instead of thousands of individual calls
# Stores results in $UnlicensedMailboxes and $LicensedMailboxes
#>

# Connect-ExchangeOnline -CertificateThumbPrint "B9FED654D4DD7FB3F16A227FA760CBA13DD8A54D" -AppID "eeb65737-0d8c-4728-b376-fd33e5ca4258" -Organization "southwalespolice.onmicrosoft.com" -ShowBanner:$false

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
Write-Host "Fetching all statistics as a bulk operation..." -ForegroundColor Cyan

# Pipeline the mailboxes to get stats in bulk - this should batch internally
$allStats = $allMailboxes | Get-EXOMailboxStatistics -Properties TotalItemSize, ItemCount, DeletedItemCount, TotalDeletedItemSize -ErrorAction SilentlyContinue

Write-Host "Retrieved $($allStats.Count) statistics" -ForegroundColor Green
Write-Host "Filtering to mailboxes in threshold ranges..." -ForegroundColor Cyan

# Create lookup for mailbox details by DisplayName
$mailboxLookup = @{}
foreach ($mbx in $allMailboxes) {
    $mailboxLookup[$mbx.DisplayName] = $mbx
}

# Filter and process - two separate collections
$unlicensedResults = [System.Collections.Generic.List[object]]::new()
$licensedResults = [System.Collections.Generic.List[object]]::new()
$processedCount = 0
$totalCount = $allStats.Count

foreach ($stat in $allStats) {
    $processedCount++
    
    #Progress Bar - Filtering Statistics
    if ($processedCount % 500 -eq 0) {
        Write-Progress -Activity "Filtering statistics" -Status "$processedCount of $totalCount" -PercentComplete (($processedCount / $totalCount) * 100)
    }
        
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
    
    # Create the mailbox object
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
        Write-Host "  [UNLICENSED] Found: $displayName - $sizeGB GB" -ForegroundColor Yellow
    }
    elseif ($isLicensedRange) {
        $licensedResults.Add($mailboxObject)
        Write-Host "  [LICENSED] Found: $displayName - $sizeGB GB" -ForegroundColor Magenta
    }
}

# Progress Bar - Complete
Write-Progress -Activity "Filtering statistics" -Completed

# Display results
Write-Host "`n=== UNLICENSED SHARED MAILBOXES ($UnlicensedMinGB-$UnlicensedMaxGB GB) ===" -ForegroundColor Yellow
if ($unlicensedResults.Count -gt 0) {
    $unlicensedResults | Sort-Object SizeBytes -Descending | Select-Object DisplayName, EmailAddress, MaxQuota, CurrentSize, ItemCount, DeletedItemCount, DeletedItemSize | Format-Table -AutoSize
} else {
    Write-Host "No mailboxes in this range" -ForegroundColor Green
}

Write-Host "`n=== LICENSED SHARED MAILBOXES ($LicensedMinGB-$LicensedMaxGB GB) ===" -ForegroundColor Magenta
if ($licensedResults.Count -gt 0) {
    $licensedResults | Sort-Object SizeBytes -Descending | Select-Object DisplayName, EmailAddress, MaxQuota, CurrentSize, ItemCount, DeletedItemCount, DeletedItemSize | Format-Table -AutoSize
} else {
    Write-Host "No mailboxes in this range" -ForegroundColor Green
}

# Stop stopwatch
$stopwatch.Stop()

# Summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total shared mailboxes scanned: $($allMailboxes.Count)" -ForegroundColor Cyan
Write-Host "Unlicensed ($UnlicensedMinGB-$UnlicensedMaxGB GB): $($unlicensedResults.Count)" -ForegroundColor Yellow
Write-Host "Licensed ($LicensedMinGB-$LicensedMaxGB GB): $($licensedResults.Count)" -ForegroundColor Magenta
Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green

# Store results for piping to email
$global:UnlicensedMailboxes = $unlicensedResults
$global:LicensedMailboxes = $licensedResults

# ============================================
# LOG TO FILE SECTION
# ============================================

# Log Configuration
$EnableLogging = $true
$LogFilePath = "C:\temp\SharedMailboxSizeReport.log"  # Update with your server path


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
    
    # Log unlicensed mailboxes
    if ($unlicensedResults.Count -gt 0) {
        Write-Log "UNLICENSED MAILBOXES ($UnlicensedMinGB-$UnlicensedMaxGB GB):" "WARNING"
        foreach ($mbx in $UnlicensedMailboxes) {
            Write-Log "  $($mbx.DisplayName) | $($mbx.UPN) | $($mbx.CurrentSize) | Items: $($mbx.ItemCount)" "WARNING"
        }
    }
    
    # Log licensed mailboxes
    if ($licensedResults.Count -gt 0) {
        Write-Log "LICENSED MAILBOXES ($LicensedMinGB-$LicensedMaxGB GB):" "WARNING"
        foreach ($mbx in $LicensedMailboxes) {
            Write-Log "  $($mbx.DisplayName) | $($mbx.UPN) | $($mbx.CurrentSize) | Items: $($mbx.ItemCount)" "WARNING"
        }
    }
    
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
$TestEmailAddress = "james.buller@south-wales.police.uk"  # Test recipient for TestMode
$MonitoredEmailAddress = "ict-monitoring@south-wales.police.uk"  # Email address to receive unlicensed mailbox summary
$FromAddress = "ict-noreply@south-wales.police.uk"
$SMTPServer = "smtp-in.swp.police.uk"

# LICENSED Email Template (85-100GB range)
$LicensedEmailSubject = "Shared Mailbox Storage Warning - Licensed Limit Approaching"
$LicensedEmailTemplate = @"
Dear Mailbox Administrator, 

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

Steps to reduce mailbox size:

Step 1: Sort and Delete Large Emails 
    Open Outlook and access the shared mailbox.
    Go to the Inbox (or any folder). 
    Click View > Arrange By > Size (or use the Sort by Size option). 
    Review the largest emails at the top. 
    Delete emails that are no longer needed. 
	
If you need the attachment: 
    Open the email. 
    Save the attachment to a secure location (e.g., SharePoint or shared drive). 
    Delete the email or remove the attachment. 

Step 2: Empty Deleted Items and Junk 
    In the Folder Pane, right-click Deleted Items. 
    Select Empty Folder. 
    Repeat for Junk Email folder. 

Step 3: Archive Old Emails
    Consider implementing an archiving strategy for emails older than 6-12 months.
    Move historical emails to an archive location (PST file or SharePoint).

If the mailbox size is not reduced, it will be unable to send or receive new emails. We appreciate your urgent attention to this matter. 

If you have any questions or need assistance, please contact the ICT Service Desk:
Telephone: x20888 / 01656 869505 - ICTServiceDesk@south-wales.police.uk

Thank you for your cooperation. 

Best regards, 

---
This is an automated message. Please do not reply directly to this email.
"@

# ============================================
# SEND EMAIL NOTIFICATIONS
# ============================================

# Send summary email for UNLICENSED mailboxes to monitored address
if ($SendEmails -and $UnlicensedMailboxes.Count -gt 0) {
    
    Write-Host "`n--- Unlicensed Mailbox Summary Report ---" -ForegroundColor Yellow
    
    # Build the mailbox list for the email body
    $mailboxList = ""
    foreach ($mbx in $UnlicensedMailboxes | Sort-Object SizeGB -Descending) {
        $mailboxList += "- $($mbx.DisplayName)`n"
        $mailboxList += "  Email: $($mbx.UPN)`n"
        $mailboxList += "  Current Size: $($mbx.CurrentSize)`n"
        $mailboxList += "  Items: $($mbx.ItemCount) | Deleted Items: $($mbx.DeletedItemCount) ($($mbx.DeletedItemSize))`n"
        $mailboxList += "`n"
    }
    
    # Create summary email body
    $summaryEmailBody = @"
Unlicensed Shared Mailbox Storage Alert
========================================

The following shared mailboxes are approaching the FREE TIER 50GB storage limit.
These mailboxes are currently unlicensed and will stop functioning when they reach 50GB.

Total Mailboxes in Warning Range (40-50GB): $($UnlicensedMailboxes.Count)

Mailboxes Requiring Attention:
$mailboxList

Recommended Actions:
1. Review each mailbox and determine if it should remain unlicensed
2. For mailboxes that need to stay active:
   - Reduce mailbox size below 40GB, OR
   - Request a license to increase limit to 100GB
3. For mailboxes no longer needed:
   - Archive or delete old content
   - Consider decommissioning the mailbox

---
This is an automated report generated on $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
"@
    
    $summarySubject = "Shared Mailbox Report - $($UnlicensedMailboxes.Count) Unlicensed Mailbox(es) Approaching 50GB Limit"
    
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
        Write-Host "Summary email sent to: $summaryRecipient" -ForegroundColor Green
        
        if ($TestMode) {
            Write-Host "TEST MODE: Summary intended for $MonitoredEmailAddress" -ForegroundColor Magenta
        }
    }
    catch {
        Write-Host "Failed to send summary email to: $summaryRecipient - $_" -ForegroundColor Red
    }
}
elseif ($UnlicensedMailboxes.Count -eq 0) {
    Write-Host "`nNo unlicensed mailboxes in warning range (40-50GB)" -ForegroundColor Green
}

# Send Emails for LICENSED mailboxes
if ($SendEmails -and $LicensedMailboxes.Count -gt 0) {
    
    if ($TestMode) {
        Write-Host "`n--- TEST MODE: Licensed mailbox emails will be sent to $TestEmailAddress ---" -ForegroundColor Magenta
    }
    
    Write-Host "`n--- Email Notifications - LICENSED MAILBOXES ---" -ForegroundColor Magenta
    
    $emailsSent = 0
    $emailsFailed = 0
    
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
            Write-Host "  Email sent to: $recipient $(if ($TestMode) { "(intended for $($mbx.UPN))" })" -ForegroundColor Green
            $emailsSent++
        }
        catch {
            Write-Host "  Failed to send email to: $recipient - $_" -ForegroundColor Red
            $emailsFailed++
        }
    }
    
    Write-Host "Licensed emails sent: $emailsSent" -ForegroundColor Green
    Write-Host "Licensed emails failed: $emailsFailed" -ForegroundColor $(if ($emailsFailed -gt 0) { 'Red' } else { 'Green' })
}

# Summary
if ($SendEmails) {
    Write-Host "`n=== EMAIL SUMMARY ===" -ForegroundColor Cyan
    
    if ($UnlicensedMailboxes.Count -gt 0) {
        Write-Host "Unlicensed mailboxes: Summary report sent to monitored address" -ForegroundColor Yellow
    }
    
    if ($LicensedMailboxes.Count -gt 0) {
        Write-Host "Licensed mailboxes: Individual emails sent to each mailbox" -ForegroundColor Magenta
    }
    
    if ($TestMode) {
        Write-Host "`nTEST MODE: All emails sent to $TestEmailAddress" -ForegroundColor Magenta
        Write-Host "Unlicensed summary intended for: $MonitoredEmailAddress" -ForegroundColor Magenta
        Write-Host "Set `$TestMode = `$false to send to actual addresses" -ForegroundColor Magenta
    }
}
elseif ($UnlicensedMailboxes.Count -eq 0 -and $LicensedMailboxes.Count -eq 0) {
    Write-Host "`nNo mailboxes in threshold ranges - no emails to send." -ForegroundColor Green
}
else {
    Write-Host "`nEmail sending is disabled. Set `$SendEmails = `$true to enable." -ForegroundColor Yellow
}
