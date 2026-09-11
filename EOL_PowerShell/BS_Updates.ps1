Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

appcmd set config /section:anonymousAuthentication /overrideMode:Deny
appcmd set config "Default Web Site/signageadmin" /section:anonymousAuthentication /overrideMode:Allow

Stop-Website -Name "Signagefeedadmin"
Stop-Website -Name "SWPICTSignageFeedHub"
