<# Pull statistics for ALL mailboxes in one bulk call
# Filter down to only those over 90GB
# Get the detailed user info only for those few large mailboxes
# One bulk statistics call instead of thousands of individual calls
# Stores results in $LargeMailboxes for piping to email

# Needed // Logging function // Email output code // Whatif argument // Make it powershell universal ready
#>

# ============================================
# GET MAILBOX SIZES
# ============================================

#Start Stopwatch
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Threshold in GB
$ThresholdGB = 90

# START
Write-Host "Fetching all user mailboxes..." -ForegroundColor Cyan

# Get all user mailboxes and output to a message
$allMailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, UserPrincipalName, DisplayName

Write-Host "Found $($allMailboxes.Count) user mailboxes" -ForegroundColor Green
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
    
    Write-Host "  Found: $($user.FirstName) $($user.LastName) - $([math]::Round($sizeBytes / 1GB, 2)) GB" -ForegroundColor Yellow
}

# Progress Bar - Complete
Write-Progress -Activity "Filtering statistics" -Completed

# Sort and display
$results | Sort-Object SizeBytes -Descending | Select-Object FirstName, Surname, EmailAddress, MaxQuota, CurrentSize, ItemCount, DeletedItemCount, DeletedItemSize | Format-Table -AutoSize

# Stop stopwatch
$stopwatch.Stop()

# List mailboxes over threshold
Write-Host "`nMailboxes over $ThresholdGB GB: $($results.Count)" -ForegroundColor Cyan

# How long did it take
Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green

# Store results for piping to email
$global:LargeMailboxes = $results

# ============================================
# LOG TO FILE SECTION
# ============================================

#region Log Configuration
$EnableLogging = $true
$LogFilePath = "\\ServerName\Share\Logs\MailboxSizeReport.log"  # Update with your server path
#endregion Log Configuration

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
