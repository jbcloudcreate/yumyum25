# Pull statistics for ALL mailboxes in one bulk call
# Filter down to only those over 90GB
# Get the detailed user info only for those few large mailboxes
# One bulk statistics call instead of thousands of individual calls
# Only fetches detailed info for mailboxes that exceed the threshold (likely <100 users)
# Stores results in $LargeMailboxes for piping to email

#Start Stopwatch
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Threshold in GB
$ThresholdGB = 90

Write-Host "Fetching all mailbox statistics..." -ForegroundColor Cyan

# Get all user mailbox statistics in one bulk call (no ResultSize parameter needed)
$allStatsRaw = Get-EXOMailboxStatistics -Properties TotalItemSize, ItemCount, DeletedItemCount, TotalDeletedItemSize

Write-Host "Processing $($allStatsRaw.Count) mailboxes..." -ForegroundColor Cyan

# Filter to mailboxes over threshold with progress
$allStats = [System.Collections.Generic.List[object]]::new()
$processedCount = 0
$totalCount = $allStatsRaw.Count

foreach ($stat in $allStatsRaw) {
    $processedCount++
    
    #region Progress Bar 1 - Filtering Statistics
    if ($processedCount % 500 -eq 0) {
        Write-Progress -Activity "Filtering mailbox statistics" -Status "$processedCount of $totalCount" -PercentComplete (($processedCount / $totalCount) * 100)
    }
    #endregion Progress Bar 1
    
    if ($stat.TotalItemSize -match '\(([0-9,]+) bytes\)') {
        $sizeBytes = [long]($matches[1] -replace ',', '')
        if ($sizeBytes -ge ($ThresholdGB * 1GB)) {
            $allStats.Add($stat)
        }
    }
}

#region Progress Bar 1 - Complete
Write-Progress -Activity "Filtering mailbox statistics" -Completed
#endregion Progress Bar 1 - Complete

Write-Host "Found $($allStats.Count) mailboxes over $ThresholdGB GB" -ForegroundColor Yellow
Write-Host "Fetching mailbox and user details..." -ForegroundColor Cyan

# Now get details only for mailboxes over threshold
$results = [System.Collections.Generic.List[object]]::new()
$processedCount = 0
$totalCount = $allStats.Count

foreach ($stat in $allStats) {
    $processedCount++
    
    #region Progress Bar 2 - Fetching User Details
    Write-Progress -Activity "Fetching user details" -Status "$processedCount of $totalCount - $($stat.DisplayName)" -PercentComplete (($processedCount / $totalCount) * 100)
    #endregion Progress Bar 2
    
    # Get mailbox details
    $mailbox = Get-EXOMailbox -Identity $stat.DisplayName -Properties ProhibitSendReceiveQuota, UserPrincipalName -ErrorAction SilentlyContinue
    if (-not $mailbox) { continue }
    
    # Skip shared mailboxes
    if ($mailbox.RecipientTypeDetails -ne 'UserMailbox') { continue }
    
    # Get user details for name
    $user = Get-User -Identity $mailbox.UserPrincipalName -ErrorAction SilentlyContinue
    if (-not $user -or -not $user.LastName) { continue }
    
    # Parse sizes
    $sizeBytes = 0
    if ($stat.TotalItemSize -match '\(([0-9,]+) bytes\)') {
        $sizeBytes = [long]($matches[1] -replace ',', '')
    }
    
    $deletedSizeGB = "0 GB"
    if ($stat.TotalDeletedItemSize -match '\(([0-9,]+) bytes\)') {
        $deletedBytes = [long]($matches[1] -replace ',', '')
        $deletedSizeGB = "$([math]::Round($deletedBytes / 1GB, 2)) GB"
    }
    
    # Parse quota
    $quotaGB = "Unlimited"
    if ($mailbox.ProhibitSendReceiveQuota -match '\(([0-9,]+) bytes\)') {
        $quotaBytes = [long]($matches[1] -replace ',', '')
        $quotaGB = "$([math]::Round($quotaBytes / 1GB, 2)) GB"
    }
    
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

#region Progress Bar 2 - Complete
Write-Progress -Activity "Fetching user details" -Completed
#endregion Progress Bar 2 - Complete

# Sort and display
$results | Sort-Object SizeBytes -Descending | Select-Object FirstName, Surname, EmailAddress, MaxQuota, CurrentSize, ItemCount, DeletedItemCount, DeletedItemSize | Format-Table -AutoSize

$stopwatch.Stop()
Write-Host "`nMailboxes over $ThresholdGB GB: $($results.Count)" -ForegroundColor Cyan
Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green

# Store results for piping to email
$global:LargeMailboxes = $results
Write-Host "`nResults stored in `$LargeMailboxes for email processing" -ForegroundColor Gray
