Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Where-Object {$_.DeletedTime -ge "2026-06-03 15:00" -and $_.DeletedTime -le "2026-06-05 15:00"} | Select Subject, FolderDisplayPath, LastParentFolderName, DeletedTime | Sort-Object DeletedTime | Format-Table -AutoSize

Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Where-Object {$_.Subject -like "*Victims Board*"} | Select Subject, FolderDisplayPath, LastParentFolderName, DeletedTime | Sort-Object DeletedTime | Format-Table -AutoSize

Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Where-Object {$_.DeletedTime -ge "2026-06-04 15:14" -and $_.DeletedTime -le "2026-06-04 15:20"} | Measure-Object

Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Measure-Object

Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Where-Object {$_.Subject -like "*25.02.26 SNPT Victims Board*"} | Select Subject, DeletedTime | Format-Table -AutoSize

Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Where-Object {$_.Subject -like "*25.02.26 SNPT Victims Board*"} | Select Subject, LastParentFolderName, FolderDisplayPath | Format-Table -AutoSize

Get-MailboxFolder -Identity "emma.white@south-wales.police.uk:\SNPT Recovery" | Select Name, FolderPath, FolderId

Get-MailboxFolder -Identity "emma.white@south-wales.police.uk:\Inbox\SNPT Recovery" | Select Name, FolderPath, FolderId

Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Where-Object {
        $_.Subject -like "*MRG*" -or
        $_.Subject -like "*Victims*" -or
        $_.Subject -like "*Citizen First*" -or
        $_.Subject -like "*UOPP*" -or
        $_.Subject -like "*Use of Police Powers*" -or
        $_.Subject -like "*SMT*" -or
        $_.Subject -like "*FL1*" -or
        $_.Subject -like "*Peoples Board*" -or
        $_.Subject -like "*Sickness*" -or
        $_.Subject -like "*Resources*" -or
        $_.Subject -like "*Performance*" -or
        $_.Subject -like "*EDI*" -or
        $_.Subject -like "*Future Events*" -or
        $_.Subject -like "*Missing*" -or
        $_.Subject -like "*TAC*" -or
        $_.Subject -like "*Taser*" -or
        $_.Subject -like "*Agenda*" -or
        $_.Subject -like "*Presentation*" -or
        $_.Subject -like "*PowerPoint*" -or
        $_.Subject -like "*Spreadsheet*" -or
        $_.SenderAddress -like "*samantha.lewis*" -or
        $_.SenderAddress -like "*fiona.lewis*" -or
        $_.SenderAddress -like "*caitlin.may*" -or
        $_.SenderAddress -like "*fiona.hide*" -or
        $_.SenderAddress -like "*jay.davies*" -or
        $_.SenderAddress -like "*rhys.gronow*" -or
        $_.SenderAddress -like "*matthew.lewis*"
} | Measure-Object

# Recover
Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Where-Object {
        $_.Subject -like "*MRG*" -or
        $_.Subject -like "*Victims*" -or
        $_.Subject -like "*Citizen First*" -or
        $_.Subject -like "*UOPP*" -or
        $_.Subject -like "*Use of Police Powers*" -or
        $_.Subject -like "*SMT*" -or
        $_.Subject -like "*FL1*" -or
        $_.Subject -like "*Peoples Board*" -or
        $_.Subject -like "*Sickness*" -or
        $_.Subject -like "*Resources*" -or
        $_.Subject -like "*Performance*" -or
        $_.Subject -like "*EDI*" -or
        $_.Subject -like "*Future Events*" -or
        $_.Subject -like "*Missing*" -or
        $_.Subject -like "*TAC*" -or
        $_.Subject -like "*Taser*" -or
        $_.Subject -like "*Agenda*" -or
        $_.Subject -like "*Presentation*" -or
        $_.Subject -like "*PowerPoint*" -or
        $_.Subject -like "*Spreadsheet*" -or
        $_.SenderAddress -like "*samantha.lewis*" -or
        $_.SenderAddress -like "*fiona.lewis*" -or
        $_.SenderAddress -like "*caitlin.may*" -or
        $_.SenderAddress -like "*fiona.hide*" -or
        $_.SenderAddress -like "*jay.davies*" -or
        $_.SenderAddress -like "*rhys.gronow*" -or
        $_.SenderAddress -like "*matthew.lewis*"
} | Restore-RecoverableItems -Identity "emma.white@south-wales.police.uk" -RestoredFolderName "SNPT Recovery"

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

# Part 2
# Initialize results array
$Results = @()

# 1. CHECK FULL ACCESS PERMISSIONS
Write-Host "Checking Full Access permissions..." -ForegroundColor Cyan
$AllMailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties GrantSendOnBehalfTo

foreach ($Mailbox in $AllMailboxes) {
    $FullAccess = Get-EXOMailboxPermission -Identity $Mailbox.UserPrincipalName | 
        Where-Object { $_.User -eq $UserEmail -and $_.AccessRights -contains "FullAccess" }
    
    if ($FullAccess) {
        $Results += [PSCustomObject]@{
            PermissionType = "Full Access"
            TargetMailbox = $Mailbox.DisplayName
            TargetEmail = $Mailbox.UserPrincipalName
            MailboxType = $Mailbox.RecipientTypeDetails
            AccessRights = "FullAccess"
        }
        Write-Host "  Found: Full Access to $($Mailbox.DisplayName)" -ForegroundColor Yellow
    }
}

Write-Host "Full Access check complete.`n" -ForegroundColor Green
