Why?
Get-WinEvent -ComputerName SWPHQ-MBS01 -FilterHashtable @{LogName='Application';Level=1,2,3;StartTime=(Get-Date).AddDays(-2)} |
 ? Message -match 'MB1' | select -First 20 TimeCreated,ProviderName,Id,Message | fl

Search-AdminAuditLog -Cmdlets Dismount-Database,Mount-Database,Move-ActiveMailboxDatabase,Set-MailboxDatabase,Suspend-MailboxDatabaseCopy -StartDate (Get-Date).AddDays(-7) |
 select RunDate,Caller,CmdletName,ObjectModified | ft -AutoSize

Get-WinEvent -ComputerName SWPHQ-MBS01 -LogName 'Microsoft-Exchange-HighAvailability/Operational' -MaxEvents 500 |
 ? Message -match 'MB1' | select -First 20 TimeCreated,Id,LevelDisplayName,Message | fl

# 1. Ask Windows Installer about this product (5 = installed, -1 = unknown)
$inst = New-Object -ComObject WindowsInstaller.Installer
$code = '{A33B0230-6095-48B2-A19E-F1979B595BBD}'
$get  = { param($p) $inst.GetType().InvokeMember('ProductInfo','GetProperty',$null,$inst,@($code,$p)) }
[pscustomobject]@{
    State           = $inst.GetType().InvokeMember('ProductState','GetProperty',$null,$inst,@($code))
    InstallLocation = & $get 'InstallLocation'
    InstallSource   = & $get 'InstallSource'
}

# 2. Look for Absolute or NetMotion folders up to 3 levels deep on every fixed drive
Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    Get-ChildItem "$($_.DeviceID)\" -Directory -Recurse -Depth 3 -ErrorAction SilentlyContinue |
      Where-Object Name -match 'NetMotion|Absolute'
} | Select-Object FullName

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object DisplayName -like 'Absolute*' |
  Select-Object DisplayName, DisplayVersion, InstallDate, InstallLocation, UninstallString

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object DisplayName | Select-Object DisplayName, Publisher, InstallLocation | Sort-Object DisplayName

# Services and processes
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'NetMotion|Absolute|Mobility' } |
  Select-Object Name, State, PathName
Get-Process | Where-Object { $_.Path -match 'NetMotion|Absolute|Mobility' } | Select-Object Name, Path

# Install and data folders
Get-ChildItem 'C:\Program Files*', 'C:\ProgramData' -Directory |
  Where-Object Name -match 'NetMotion|Absolute' | Select-Object FullName

# Kernel drivers (the client uses network filter drivers)
Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -match 'nm|NetMotion|Absolute' } |
  Select-Object Name, State, PathName

New-MpPerformanceRecording -RecordTo C:\Temp\nm.etl
# Connect, switch networks (e.g. Wi-Fi to 4G), reconnect, then press Enter to stop
Get-MpPerformanceReport -Path C:\Temp\nm.etl -TopProcesses 10 -TopFiles 10

Get-CimInstance Win32_ComputerSystem | Select-Object Model
Get-CimInstance Win32_VideoController | Select-Object Name

# Corrected: list folders inside Program Files and ProgramData
Get-ChildItem 'C:\Program Files\*', 'C:\Program Files (x86)\*', 'C:\ProgramData\*' -Directory -ErrorAction SilentlyContinue |
  Where-Object Name -match 'NetMotion|Absolute' | Select-Object FullName

# Confirm who made each driver
Get-ChildItem C:\Windows\System32\drivers\nm*.sys, C:\Windows\System32\drivers\winmad.sys -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{
    Name    = $_.Name
    Company = $_.VersionInfo.CompanyName
    Signer  = (Get-AuthenticodeSignature $_.FullName).SignerCertificate.Subject } }

# Check whether locally added exclusions will be honoured (True means local ones are ignored)
(Get-MpPreference).DisableLocalAdminMerge

<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="dotnet" arguments=".\SignageFeedAdmin.dll" stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" hostingModel="inprocess" forwardWindowsAuthToken="true" />
    </system.webServer>
  </location>
  <location path="feeds">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <security>
        <authentication>
          <anonymousAuthentication enabled="true" />
        </authentication>
      </security>
    </system.webServer>
  </location>
</configuration>

Test-Path "C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss\main.xml"
Get-Item "C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss\main.xml" | Select-Object LastWriteTime, Length

%windir%\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/authentication/anonymousAuthentication

& "$env:windir\system32\inetsrv\appcmd.exe" unlock config -section:system.webServer/security/authentication/anonymousAuthentication

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
