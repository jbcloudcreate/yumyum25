# Get user mailboxes with quota info
$mailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, DisplayName, UserPrincipalName

# Get user details for names
$users = Get-User -ResultSize Unlimited | Select-Object UserPrincipalName, FirstName, LastName

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
    
    # Skip if no surname or not A-F
    if (-not $user -or -not $user.LastName) { continue }
    $firstLetter = $user.LastName.Substring(0,1).ToUpper()
    if ($firstLetter -notmatch '^[A-F]$') { continue }
    
    # Get mailbox stats
    $stats = Get-EXOMailboxStatistics -Identity $mailbox.UserPrincipalName -Properties TotalItemSize -ErrorAction SilentlyContinue
    if (-not $stats) { continue }
    
    [PSCustomObject]@{
        FirstName    = $user.FirstName
        Surname      = $user.LastName
        EmailAddress = $mailbox.UserPrincipalName
        MaxQuota     = $mailbox.ProhibitSendReceiveQuota
        CurrentSize  = $stats.TotalItemSize
    }
}

$results | Format-Table -AutoSize