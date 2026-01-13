$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Test user - set to $null to process all A-F, or specify a UPN for testing
$TestUser = "Geraint.Morgan@south-wales.police.uk"

# Get user mailboxes with quota info
if ($TestUser) {
    $mailboxes = @(Get-EXOMailbox -Identity $TestUser -Properties ProhibitSendReceiveQuota, DisplayName, UserPrincipalName)
    # Only get the specific user details when testing
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

# Filter to surnames A-F and get stats
$results = foreach ($mailbox in $mailboxes) {
    $user = $userLookup[$mailbox.UserPrincipalName.ToLower()]
    
    # Skip if no surname or not A-F (skip filter if testing single user)
    if (-not $user -or -not $user.LastName) { continue }
    if (-not $TestUser) {
        $firstLetter = $user.LastName.Substring(0,1).ToUpper()
        if ($firstLetter -notmatch '^[A-F]$') { continue }
    }
    
    # Get mailbox stats - include deleted item properties
    $stats = Get-EXOMailboxStatistics -Identity $mailbox.UserPrincipalName -Properties TotalItemSize, ItemCount, DeletedItemCount, TotalDeletedItemSize -ErrorAction SilentlyContinue
    if (-not $stats) { continue }
    
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
    
    # Parse current size to GB
    $sizeGB = "0 GB"
    if ($stats.TotalItemSize) {
        if ($stats.TotalItemSize -match '\(([0-9,]+) bytes\)') {
            $sizeBytes = [long]($matches[1] -replace ',', '')
            $sizeGB = "$([math]::Round($sizeBytes / 1GB, 2)) GB"
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
        CurrentSize      = $sizeGB
        ItemCount        = $stats.ItemCount
        DeletedItemCount = $stats.DeletedItemCount
        DeletedItemSize  = $deletedSizeGB
    }
}

$results | Format-Table -AutoSize

$stopwatch.Stop()
Write-Host "`nExecution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green
