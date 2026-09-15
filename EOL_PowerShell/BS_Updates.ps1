# Before Copy

Import-Module WebAdministration

$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$backup = "C:\temp\deploy-backup-$stamp"
mkdir $backup -Force
copy C:\inetpub\SignageFeedAdmin\publish\App_Data\feed.db $backup\
copy C:\inetpub\SignageFeedAdmin\publish\appsettings.json $backup\
copy C:\inetpub\SignageFeedAdmin\publish\web.config $backup\
Get-ChildItem $backup

# Confirm all three files are listed, then:

Stop-WebAppPool -Name "SignageAdminApp"
Start-Sleep -Seconds 3
Get-WebAppPoolState -Name "SignageAdminApp"   # expect Stopped

Remove-Item C:\inetpub\SignageFeedAdmin\publish -Recurse -Force

# Copy the new publish folder across.
# On the server, after copying

# Restore the database
mkdir C:\inetpub\SignageFeedAdmin\publish\App_Data -Force
copy $backup\feed.db C:\inetpub\SignageFeedAdmin\publish\App_Data\

# Confirm the deployed config has the right admin group
Select-String -Path C:\inetpub\SignageFeedAdmin\publish\appsettings.json -Pattern AdminGroup

mkdir C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss -Force
icacls "C:\inetpub\SignageFeedAdmin\publish\App_Data" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"
icacls "C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"

Start-WebAppPool -Name "SignageAdminApp"

# Check
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='IIS AspNetCore Module V2'} -MaxEvents 3 |
  Format-List TimeCreated, Id, Message

Get-ChildItem C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss

# "Started successfully" plus four XML files. Then load a BU page and confirm the nav shows three links rather than four, and that the picker's four tiles sit on one row.
