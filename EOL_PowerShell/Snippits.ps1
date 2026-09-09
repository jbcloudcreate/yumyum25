%windir%\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/authentication/anonymousAuthentication

Step 1 — establish current state (all read-only):
# From an Exchange server
Get-DatabaseAvailabilityGroup -Identity <DAGName> -Status | fl Name,Servers,
  WitnessServer,WitnessDirectory,AlternateWitnessServer,
  WitnessShareInUse,OperationalServers,StartedMailboxServers,StoppedMailboxServers

# Cluster view
Get-ClusterResource | ? ResourceType -eq 'File Share Witness' | fl *
Get-ClusterQuorum

Step 2 — connectivity and share:
Test-NetConnection swphq-dagwit1.swp-rest.police.int -Port 445
Resolve-DnsName swphq-dagwit1.swp-rest.police.int
Test-Path "\\swphq-dagwit1.swp-rest.police.int\SWPEX-MBSDAG.swp-rest.police.int"

Step 3 — the usual culprit. Nine times out of ten it's Exchange Trusted Subsystem no longer being in the local Administrators group on the witness server. Rebuilds, hardening baselines, and GPO-restricted-group policies all strip it. Check on swphq-dagwit1:
Get-LocalGroupMember -Group Administrators

Step 4 - Check Reboot on DAGWIT
Get-CimInstance Win32_OperatingSystem | select LastBootUpTime

Witness server SWPHQ-DAGWIT1 rebooted 01/09 22:13–22:15 under scheduled SCCM patching (event 1074, CcmExec then TrustedInstaller, both logged as planned). Cluster briefly lost file share witness arbitration during the reboot window, generating the SCOM alert at 22:14:48. Witness re-arbitrated automatically on the server returning at 22:15:08.

Verified 03/09 — all checks passed, no issues found:

Connectivity to swphq-dagwit1.swp-rest.police.int on TCP 445 from SWPHQ-MBS02 successful (TcpTestSucceeded = True, 10.20.242.39 → 10.20.242.48)
DNS resolution correct
File Share Witness cluster resource State = Online, owner Cluster Group
Quorum type Majority, quorum resource File Share Witness
WitnessShareInUse = Primary
All three DAG nodes (SWPHQ-MBS01/02/03) Up and listed as OperationalServers
Exchange Trusted Subsystem present in local Administrators on the witness server

No remediation required — closing as transient/expected, caused by planned patching.

# Clean shutdown / startup / unexpected
Get-WinEvent -FilterHashtable @{LogName='System'; ID=1074,6005,6006,6008,41} -MaxEvents 20 |
  ft TimeCreated,Id,Message -Wrap

Also check the System and FailoverClustering event logs on MBS02 around 22:14 on 01/09 for events 1562, 1069, or 1564 — those give the underlying failure reason.

Get-ADGroupMember -Identity "SignageFeedUsers" -Server swp.police.int | Select-Object Name, SamAccountName

Add-ADGroupMember -Identity "SignageFeedUsers" -Server swp.police.int -Members "swp59639a"

Get-RecoverableItems -Identity "emma.white@south-wales.police.uk" -FilterItemType IPM.Note -ResultSize Unlimited | Where-Object {$_.DeletedTime -ge "2026-06-03 15:00" -and $_.DeletedTime -le "2026-06-05 15:00"} | Select Subject, FolderDisplayPath, LastParentFolderName, DeletedTime | Sort-Object DeletedTime | Format-Table -AutoSize

Get-MailboxFolderPermission -Identity "sharedmailbox@domain.com:\FolderName" -User "user@domain.com"

Get-MailboxFolderStatistics -Identity "sharedmailbox@domain.com" | Select-Object Name, FolderPath

Get-Service MSExchangeHM, MSExchangeHMRecovery -ComputerName SWPHQ-MBS03

Get-ServerHealth -Identity SWPHQ-MBS03 | Where-Object {$_.AlertValue -eq "Unhealthy"}
Get-HealthReport -Identity SWPHQ-MBS03 | Where-Object {$_.State -ne "Online" -or $_.HealthSetName -like "*HM*"}

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
