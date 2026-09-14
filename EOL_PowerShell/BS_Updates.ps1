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


