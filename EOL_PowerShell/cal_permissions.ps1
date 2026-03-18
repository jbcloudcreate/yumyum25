# Define the mailbox whose calendar you're granting access to
$TargetMailbox = "user.a@domain.com"

# Build the calendar folder path
$CalendarPath = "${TargetMailbox}:\Calendar"

# Get current permissions
Get-MailboxFolderPermission -Identity $CalendarPath | 
    Select-Object User, AccessRights, SharingPermissionFlags |
    Format-Table -AutoSize
	
Get-MailboxFolderStatistics -Identity $TargetMailbox -FolderScope Calendar |
    Select-Object Name, FolderPath
