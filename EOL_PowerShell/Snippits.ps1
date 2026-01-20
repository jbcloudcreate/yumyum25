# Verify the mailbox
Get-Mailbox -Identity "sharedmailbox@domain.com"

# Get All Mailboxes with Size, Quota, and Usage
Get-Mailbox -ResultSize 100 | Get-MailboxStatistics | Select DisplayName, ItemCount, TotalItemSize, StorageLimitStatus | Sort-Object TotalItemSize -Descending

# Find Mailboxes with Forwarding Enabled
Get-Mailbox -ResultSize 100 | Where-Object {$_.ForwardingSmtpAddress -ne $null -or $_.ForwardingAddress -ne $null} | Select Name, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward

# Grant Full Access to a Mailbox
Add-MailboxPermission -Identity "targetuser@domain.com" -User "adminuser@domain.com" -AccessRights FullAccess -InheritanceType All

# Cleanly Disconnect the Session
Disconnect-ExchangeOnline -Confirm:$false

# View Send As Permissions on a Shared Mailbox
Get-RecipientPermission -Identity "sharedmailbox@domain.com" | Where-Object { $_.AccessRights -contains "SendAs" } | Select Trustee, AccessRights, IsInherited

# Grant Send As Permission
Add-RecipientPermission -Identity "sharedmailbox@domain.com" -Trustee "user@domain.com" -AccessRights SendAs -Confirm:$false

# Grant Full Access to a Shared Mailbox
Add-MailboxPermission -Identity "sharedmailbox@domain.com" `-User "user@domain.com" -AccessRights FullAccess -InheritanceType All

# View Users with Full Access to a Shared Mailbox
Get-MailboxPermission -Identity "sharedmailbox@domain.com" | Where-Object { $_.AccessRights -contains "FullAccess" -and -not $_.IsInherited -and $_.User -ne "NT AUTHORITY\SELF" } | Select User, AccessRights

# Rules
Get-InboxRule -Mailbox "user@domain.com" | Select Name, Enabled, Priority, From, SubjectContainsWords, MoveToFolder

Get-InboxRule -Mailbox "user@domain.com" | Format-List Name, Description, Enabled, Priority, From, SentTo, SubjectContainsWords, MoveToFolder, RedirectTo, ForwardTo, DeleteMessage

# Checking permissions accross the estate if a person is or has access to mailboxes and cal's

# Part 1
# Check if connected to Exchange Online
try {
    Get-EXOMailbox -ResultSize 1 -ErrorAction Stop | Out-Null
    Write-Host "Connected to Exchange Online" -ForegroundColor Green
}
catch {
    Write-Host "Not connected to Exchange Online. Connecting..." -ForegroundColor Yellow
    Connect-ExchangeOnline
}

# Get the user email
$UserEmail = Read-Host "Enter the user's email address"

# Validate the user exists
try {
    $User = Get-EXOMailbox -Identity $UserEmail -ErrorAction Stop
    Write-Host "`nFound user: $($User.DisplayName) ($($User.UserPrincipalName))" -ForegroundColor Green
}
catch {
    Write-Host "User not found: $UserEmail" -ForegroundColor Red
    exit
}

Write-Host "`nSearching for permissions... This may take a few minutes.`n" -ForegroundColor Cyan

