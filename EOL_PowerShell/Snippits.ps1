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
