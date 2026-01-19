<# Pull statistics for ALL shared mailboxes in one bulk call
# Filter down to only those over 40GB
# Get the detailed mailbox info only for those few large mailboxes
# One bulk statistics call instead of thousands of individual calls
# Stores results in $LargeMailboxes for piping to email
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

# Threshold in GB
$ThresholdGB = 40

# START
Write-Host "Fetching all shared mailboxes..." -ForegroundColor Cyan

# Get all shared mailboxes and output to a message
$allMailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, UserPrincipalName, DisplayName

Write-Host "Found $($allMailboxes.Count) shared mailboxes" -ForegroundColor Green
Write-Host "Fetching all statistics as a bulk operation..." -ForegroundColor Cyan

# Pipeline the mailboxes to get stats in bulk - this should batch internally
$allStats = $allMailboxes | Get-EXOMailboxStatistics -Properties TotalItemSize, ItemCount, DeletedItemCount, TotalDeletedItemSize -ErrorAction SilentlyContinue

Write-Host "Retrieved $($allStats.Count) statistics" -ForegroundColor Green
Write-Host "Filtering to mailboxes over $ThresholdGB GB..." -ForegroundColor Cyan

# Create lookup for mailbox details by DisplayName
$mailboxLookup = @{}
foreach ($mbx in $allMailboxes) {
    $mailboxLookup[$mbx.DisplayName] = $mbx
}

# Filter and process
$results = [System.Collections.Generic.List[object]]::new()
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
    
    # Skip if under threshold
    if ($sizeBytes -lt ($ThresholdGB * 1GB)) { continue }
    
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
    
    $results.Add([PSCustomObject]@{
        DisplayName      = $displayName
        EmailAddress     = $username
        UPN              = $mailbox.UserPrincipalName
        MaxQuota         = $quotaGB
        CurrentSize      = "$([math]::Round($sizeBytes / 1GB, 2)) GB"
        SizeBytes        = $sizeBytes
        ItemCount        = $stat.ItemCount
        DeletedItemCount = $stat.DeletedItemCount
        DeletedItemSize  = $deletedSizeGB
    })
    
    Write-Host "  Found: $displayName - $([math]::Round($sizeBytes / 1GB, 2)) GB" -ForegroundColor Yellow
}

# Progress Bar - Complete
Write-Progress -Activity "Filtering statistics" -Completed

# Sort and display
$results | Sort-Object SizeBytes -Descending | Select-Object DisplayName, EmailAddress, MaxQuota, CurrentSize, ItemCount, DeletedItemCount, DeletedItemSize | Format-Table -AutoSize

# Stop stopwatch
$stopwatch.Stop()

# List mailboxes over threshold
Write-Host "`nShared mailboxes over $ThresholdGB GB: $($results.Count)" -ForegroundColor Cyan

# How long did it take
Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green

# Store results for piping to email
$global:LargeMailboxes = $results

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
    Write-Log "Threshold: $ThresholdGB GB"
    Write-Log "Total shared mailboxes scanned: $($allMailboxes.Count)"
    Write-Log "Shared mailboxes over threshold: $($results.Count)"
    Write-Log "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds"
    Write-Log "----------------------------------------"
    
    # Log each large mailbox
    foreach ($mbx in $LargeMailboxes) {
        Write-Log "$($mbx.DisplayName) | $($mbx.UPN) | $($mbx.CurrentSize) | Items: $($mbx.ItemCount)" "WARNING"
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
$FromAddress = "ict-noreply@south-wales.police.uk"
$SMTPServer = "smtp-in.swp.police.uk"
$EmailSubject = "Shared Mailbox Storage Warning - Action Required"

# Email Template
$EmailBodyTemplate = @"
Dear Mailbox Administrator, 

We are writing to inform you that a shared mailbox under your management has exceeded the recommended storage limit. To ensure the mailbox can continue to function without any interruptions, we kindly ask you to reduce the mailbox size. 

Our records show that the shared mailbox '{DisplayName}' has reached {CurrentSize} of its {MaxQuota} allocated storage.

Current Mailbox Statistics:
- Mailbox: {DisplayName}
- Email Address: {UPN}
- Current Size: {CurrentSize}
- Maximum Quota: {MaxQuota}
- Items in Mailbox: {ItemCount}
- Deleted Items: {DeletedItemCount} ({DeletedItemSize})

Here are a few steps you can take to manage the mailbox size: 

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

If the mailbox size is not reduced, it may soon be unable to send or receive new emails. We appreciate your prompt attention to this matter. 

If you have any questions or need assistance, please do not hesitate to contact the ICT Service Desk 
Telephone: x20888 / 01656 869505 - ICTServiceDesk@south-wales.police.uk

Thank you for your cooperation. 

Best regards, 

---
This is an automated message. Please do not reply directly to this email.
"@

# Send Emails action
if ($SendEmails -and $LargeMailboxes.Count -gt 0) {
    
    if ($TestMode) {
        Write-Host "`n--- TEST MODE: Emails will be sent to $TestEmailAddress ---" -ForegroundColor Magenta
    }
    
    Write-Host "`n--- Email Notifications ---" -ForegroundColor Cyan
    
    $emailsSent = 0
    $emailsFailed = 0
    
    foreach ($mbx in $LargeMailboxes) {
        
        # Build personalised email body
        $emailBody = $EmailBodyTemplate -replace '{DisplayName}', $mbx.DisplayName `
                                        -replace '{CurrentSize}', $mbx.CurrentSize `
                                        -replace '{MaxQuota}', $mbx.MaxQuota `
                                        -replace '{ItemCount}', $mbx.ItemCount `
                                        -replace '{DeletedItemCount}', $mbx.DeletedItemCount `
                                        -replace '{DeletedItemSize}', $mbx.DeletedItemSize `
                                        -replace '{UPN}', $mbx.UPN
        
        # Determine recipient - test account or real user
        # Note: For shared mailboxes, you may want to send to the mailbox owner/admin
        # This sends to the shared mailbox address itself - adjust as needed
        $recipient = if ($TestMode) { $TestEmailAddress } else { $mbx.UPN }
        
        # Modify subject in test mode to show intended recipient
        $subject = if ($TestMode) { "[TEST - Intended for: $($mbx.UPN)] $EmailSubject" } else { $EmailSubject }
        
        try {
            $emailParams = @{
                From       = $FromAddress
                To         = $recipient
                Subject    = $subject
                Body       = $emailBody
                SmtpServer = $SMTPServer
            }
            
            Send-MailMessage @emailParams
            Write-Host "Email sent to: $recipient $(if ($TestMode) { "(intended for $($mbx.UPN))" })" -ForegroundColor Green
            $emailsSent++
        }
        catch {
            Write-Host "Failed to send email to: $recipient - $_" -ForegroundColor Red
            $emailsFailed++
        }
    }
    
    Write-Host "`nEmails sent: $emailsSent" -ForegroundColor Green
    Write-Host "Emails failed: $emailsFailed" -ForegroundColor $(if ($emailsFailed -gt 0) { 'Red' } else { 'Green' })
    
    if ($TestMode) {
        Write-Host "`nTEST MODE: All emails sent to $TestEmailAddress" -ForegroundColor Magenta
        Write-Host "Set `$TestMode = `$false to send to actual users" -ForegroundColor Magenta
    }
}
elseif ($LargeMailboxes.Count -eq 0) {
    Write-Host "`nNo shared mailboxes over threshold - no emails to send." -ForegroundColor Green
}
else {
    Write-Host "`nEmail sending is disabled. Set `$SendEmails = `$true to enable." -ForegroundColor Yellow
}
