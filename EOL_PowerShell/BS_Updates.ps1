Stage A — create the applications

Run elevated on the dev server:

Import-Module WebAdministration

# Hub gets its own pool - static content, no managed code
New-WebAppPool -Name "SWPICTHub"
Set-ItemProperty IIS:\AppPools\SWPICTHub -Name managedRuntimeVersion -Value ""

New-WebApplication -Site "Default Web Site" -Name "feedhub" `
  -PhysicalPath "C:\inetpub\SWPICTHub" -ApplicationPool "SWPICTHub"

# Feed Admin keeps its existing pool - the NTFS grants on App_Data
# and the keys folder are tied to IIS AppPool\SignageFeedAdmin
New-WebApplication -Site "Default Web Site" -Name "signageadmin" `
  -PhysicalPath "C:\inetpub\SignageFeedAdmin\publish" -ApplicationPool "SignageFeedAdmin"

Then confirm:

Get-WebApplication -Site "Default Web Site" |
  Where-Object { $_.Path -match 'feedhub|signageadmin' } |
  Format-List Path, PhysicalPath, ApplicationPool

The 8081 and 8082 sites keep running throughout — same folders, served two ways.

Stage B — authentication per application

# Hub: anonymous
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "Default Web Site/feedhub" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Name enabled -Value $true

# Feed Admin: Windows Auth, anonymous off
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "Default Web Site/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Name enabled -Value $false

Set-WebConfigurationProperty -PSPath "IIS:\" -Location "Default Web Site/signageadmin" `
  -Filter "/system.webServer/security/authentication/windowsAuthentication" `
  -Name enabled -Value $true

# Anonymous identity must be the app pool, not IUSR - this is what
# the /feeds carve-out inherits, and getting it wrong is what caused
# the login prompt last time
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "Default Web Site/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Name userName -Value ""

An empty userName means "application pool identity". That's deliberate, not an omission.

One thing that may bite: windowsAuthentication is often locked at server level on a hardened box, same as anonymousAuthentication was. If that line errors with a lock message, stop and tell me rather than unlocking — I want the scoped unlock done properly this time rather than repeating the server-wide mistake.

The /feeds anonymous carve-out needs nothing here. It's already in the app's own web.config and travels with it.

Then stop and test

https://swpdev-ictweb.swp-rest.police.int/feedhub/
https://swpdev-ictweb.swp-rest.police.int/signageadmin

Import-Module WebAdministration
Get-WebAppPoolState -Name "SignageFeedAdmin"
Get-ChildItem IIS:\AppPools\SignageFeedAdmin | Select-Object Name, State

If it reads Stopped, that's the answer.

Then get the reason rather than guessing — the System log records why the pool stopped:

Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WAS'} -MaxEvents 10 |
  Format-List TimeCreated, Id, Message

And the application's own errors:

Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='IIS AspNetCore Module V2'} -MaxEvents 10 |
  Format-List TimeCreated, Id, Message



