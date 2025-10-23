# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@domain.com

# Variables (modify as needed)
$SharedMailbox = "sharedmailbox@domain.com"
$DelegateUser = "user@domain.com"
$CalendarFolder = "$SharedMailbox:\Calendar"

# Grant 'Editor' (Full Control) access to the calendar
Add-MailboxFolderPermission -Identity $CalendarFolder -User $DelegateUser -AccessRights Editor

# Verify permissions
Get-MailboxFolderPermission -Identity $CalendarFolder
