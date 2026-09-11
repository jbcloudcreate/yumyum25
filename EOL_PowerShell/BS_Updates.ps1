Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

& "$env:windir\system32\inetsrv\appcmd.exe" set config /section:anonymousAuthentication /overrideMode:Deny
& "$env:windir\system32\inetsrv\appcmd.exe" set config "Default Web Site/signageadmin" /section:anonymousAuthentication /overrideMode:Allow

OR

Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Deny

Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Location "Default Web Site/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Allow

Verify:

Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Location "Default Web Site/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

TEST - Issues (reverse)
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Allow

Stop-Website -Name "Signagefeedadmin"
Stop-Website -Name "SWPICTSignageFeedHub"
