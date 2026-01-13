$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Test user - set to $null to process all, or specify a UPN for testing
$TestUser = $null

# Threshold in GB
$ThresholdGB = 20

# Get user mailboxes with quota info
if ($TestUser) {
    $mailboxes = @(Get-EXOMailbox -Identity $TestUser -Properties ProhibitSendReceiveQuota, DisplayName, UserPrincipalName)
    $users = @(Get-User -Identity $TestUser | Select-Object UserPrincipalName, FirstName, LastName)
} else {
    $mailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, DisplayName, UserPrincipalName
    $users = Get-User -ResultSize Unlimited | Select-Object UserPrincipalName, FirstName, LastName
}

# Create lookup for users
$userLookup = @{}
foreach ($user in $users) {
    if ($user.UserPrincipalName) {
        $userLookup[$user.UserPrincipalName.ToLower()] = $user
    }
}

# Filter to surnames A-B and get stats
$results = foreach ($mailbox in $mailboxes) {
    $user = $userLookup[$mailbox.UserPrincipalName.ToLower()]
    
    # Skip if no surname or not A-B (skip filter if testing single user)
    if (-not $user -or -not $user.LastName) { continue }
    if (-not $TestUser) {
        $firstLetter = $user.LastName.Substring(0,1).ToUpper()
        if ($firstLetter -notmatch '^[A-B]$') { continue }
    }
    
    # Get mailbox stats
    $stats = Get-EXOMailboxStatistics -Identity $mailbox.UserPrincipalName -Properties TotalItemSize, ItemCount, DeletedItemCount, TotalDeletedItemSize -ErrorAction SilentlyContinue
    if (-not $stats) { continue }
    
    # Parse current size to bytes for filtering/sorting
    $sizeBytes = 0
    if ($stats.TotalItemSize) {
        if ($stats.TotalItemSize -match '\(([0-9,]+) bytes\)') {
            $sizeBytes = [long]($matches[1] -replace ',', '')
        }
    }
    
    # Skip if under threshold
    $thresholdBytes = $ThresholdGB * 1GB
    if ($sizeBytes -lt $thresholdBytes) { continue }
    
    # Parse quota to GB
    $quotaGB = "Unlimited"
    $quotaValue = $mailbox.ProhibitSendReceiveQuota
    if ($quotaValue) {
        if ($quotaValue -match '\(([0-9,]+) bytes\)') {
            $quotaBytes = [long]($matches[1] -replace ',', '')
            $quotaGB = "$([math]::Round($quotaBytes / 1GB, 2)) GB"
        }
        elseif ($quotaValue -match '^unlimited$') {
            $quotaGB = "Unlimited"
        }
    }
    
    # Parse deleted item size to GB
    $deletedSizeGB = "0 GB"
    if ($stats.TotalDeletedItemSize) {
        if ($stats.TotalDeletedItemSize -match '\(([0-9,]+) bytes\)') {
            $deletedBytes = [long]($matches[1] -replace ',', '')
            $deletedSizeGB = "$([math]::Round($deletedBytes / 1GB, 2)) GB"
        }
    }
    
    # Get username without domain
    $username = ($mailbox.UserPrincipalName -split '@')[0]
    
    [PSCustomObject]@{
        FirstName        = $user.FirstName
        Surname          = $user.LastName
        EmailAddress     = $username
        MaxQuota         = $quotaGB
        CurrentSize      = "$([math]::Round($sizeBytes / 1GB, 2)) GB"
        SizeBytes        = $sizeBytes  # Hidden column for sorting
        ItemCount        = $stats.ItemCount
        DeletedItemCount = $stats.DeletedItemCount
        DeletedItemSize  = $deletedSizeGB
    }
}

# Sort by size descending and display (exclude SizeBytes from output)
$results | Sort-Object SizeBytes -Descending | Select-Object FirstName, Surname, EmailAddress, MaxQuota, CurrentSize, ItemCount, DeletedItemCount, DeletedItemSize | Format-Table -AutoSize

$stopwatch.Stop()
Write-Host "`nMailboxes over $ThresholdGB GB: $(@($results).Count)" -ForegroundColor Cyan
Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green
