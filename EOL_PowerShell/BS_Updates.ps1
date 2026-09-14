# 1. Backup
mkdir C:\temp\deploy-backup-20260914
copy C:\inetpub\SignageFeedAdmin\publish\App_Data\feed.db C:\temp\deploy-backup-20260914\
copy C:\inetpub\SignageFeedAdmin\publish\web.config C:\temp\deploy-backup-20260914\
Get-ChildItem C:\temp\deploy-backup-20260914

# 2. Keys folder (sibling of publish, survives deploys)
mkdir C:\inetpub\SignageFeedAdmin\keys
icacls "C:\inetpub\SignageFeedAdmin\keys" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"

# 3. Stop the pool - the DLL is locked while the worker runs
Stop-WebAppPool -Name "SignageAdminApp"

## Then confirm the backup exists before this next bit, because it deletes the only live copy:

# 4. Replace publish wholesale - not a merge, several files were renamed
Remove-Item C:\inetpub\SignageFeedAdmin\publish -Recurse -Force

## Copy your new publish folder across from the laptop, then:

# 5. Restore the database
mkdir C:\inetpub\SignageFeedAdmin\publish\App_Data
copy C:\temp\deploy-backup-20260914\feed.db C:\inetpub\SignageFeedAdmin\publish\App_Data\

# 6. Pre-create the feed output folder and grant write
mkdir C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss
icacls "C:\inetpub\SignageFeedAdmin\publish\App_Data" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"
icacls "C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"

# 7. Start
Start-WebAppPool -Name "SignageAdminApp"

## First check

## Before touching the browser:

Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='IIS AspNetCore Module V2'} -MaxEvents 5 |
  Format-List TimeCreated, Id, Message

## You want "started successfully". If FeedCatalog rejects the config the app won't start, and the message will say which feed and why.

Get-ChildItem C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss
Get-ChildItem C:\inetpub\SignageFeedAdmin\keys


## Before copying

Import-Module WebAdministration

# Fresh backup - the database lives inside publish, so the delete below destroys it
mkdir C:\temp\deploy-backup-20260914-2 -Force
copy C:\inetpub\SignageFeedAdmin\publish\App_Data\feed.db C:\temp\deploy-backup-20260914-2\
copy C:\inetpub\SignageFeedAdmin\publish\web.config C:\temp\deploy-backup-20260914-2\
Get-ChildItem C:\temp\deploy-backup-20260914-2

## Confirm both files are listed before running the next block.

# The DLL is locked while the worker process is running
Stop-WebAppPool -Name "SignageAdminApp"
Start-Sleep -Seconds 3
Get-WebAppPoolState -Name "SignageAdminApp"   # expect Stopped

Remove-Item C:\inetpub\SignageFeedAdmin\publish -Recurse -Force

## copy your new publish

## After copying

# Restore the database
mkdir C:\inetpub\SignageFeedAdmin\publish\App_Data -Force
copy C:\temp\deploy-backup-20260914-2\feed.db C:\inetpub\SignageFeedAdmin\publish\App_Data\

# Pre-create the feed output folder rather than granting write on wwwroot itself
mkdir C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss -Force

# Grants
icacls "C:\inetpub\SignageFeedAdmin\publish\App_Data" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"
icacls "C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"

Start-WebAppPool -Name "SignageAdminApp"

## Then check

Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='IIS AspNetCore Module V2'} -MaxEvents 3 |
  Format-List TimeCreated, Id, Message

Get-ChildItem C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss

## Make SWPFeedHub only for domain users

## Check Windows Authentication is installed as an IIS feature

Get-WindowsFeature Web-Windows-Auth

Import-Module WebAdministration

# Windows Auth on, anonymous off, for the Hub application
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "Default Web Site/feedhub" `
  -Filter "/system.webServer/security/authentication/windowsAuthentication" `
  -Name enabled -Value $true

Set-WebConfigurationProperty -PSPath "IIS:\" -Location "Default Web Site/feedhub" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Name enabled -Value $false

