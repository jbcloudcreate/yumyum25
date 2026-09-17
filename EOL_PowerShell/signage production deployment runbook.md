# SWP Signage Feed Admin — Production Deployment Runbook

**Target server:** `swpapp-digisign.swp-rest.police.int` (`10.129.242.24`)
**Version:** 3.0 — written against the server as surveyed on 17 September 2026
**Supersedes:** v1.0 (assumed dedicated server), v2.0 (assumed unknown shared server)
**Prepared by:** James Buller, ICT Datacenter Team

---

## Server as found

| | |
|---|---|
| OS | Windows Server 2019 Standard |
| IP | `10.129.242.24` |
| Web root | `E:\inetpub\wwwroot` |
| IIS logs | `E:\inetpub\logs\LogFiles` |
| .NET runtime | **None installed** |
| Existing sites | `Default Web Site` (id 1), `signage` (id 2), `MeetingRoomHowTo` (id 3) |
| HTTPS status | **Broken.** `Default Web Site` holds the only 443 binding, carrying a certificate that expired 3 July 2026 |
| `anonymousAuthentication` lock | `Deny` (correct default) |

**Local conventions to follow:** sites are siblings, not applications under `Default Web Site`. Bindings are IP-specific with a host header (`10.129.242.24:80:name`), not `*`. Everything lives on `E:`.

**The `signage` site (id 2)** is an abandoned prototype from 2021–2022 — no `W3SVC2` log directory exists, so it has never served a request. **Leave it alone.** Removing it is a separate tidy-up, not part of this deployment.

---

## Certificates on this server

| Thumbprint | Valid to | EKU | Use |
|---|---|---|---|
| `E6CB3578…` | **expired 03/07/2026** | Server Auth | Currently bound to 443. Replace in Part 2. |
| `03BD544B…` | 29/06/2029 | Server Auth | **Use this.** Covers 14 hostnames including ours. |
| `C8B70B74…` | 16/05/2029 | Server + Client Auth | Valid alternative, our hostname only |
| `14B60634…` | 16/05/2027 | *SSL Secured Remote Desktop* | **Unusable** — RDP certificate, not for IIS |

---

## How to use this document

Work through in order. Stages marked ⚠ touch shared infrastructure and each ends with a **test gate** — do not proceed past a failed gate.

All commands are PowerShell, run **elevated**, on the target server unless stated.

Use `appcmd` for enumeration on this server; the `WebAdministration` provider returned empty results during the survey. The `Set-WebConfiguration` cmdlets work normally.

---

## Part 1 — ⚠ Prerequisites

### 1.1 Confirm role services

```powershell
Get-WindowsFeature Web-Server, Web-Windows-Auth, Web-Static-Content, Web-Http-Logging |
  Select-Object Name, InstallState
```

If `Web-Windows-Auth` is not installed:

```powershell
Install-WindowsFeature -Name Web-Windows-Auth
```

### 1.2 .NET 10 Hosting Bundle

No .NET runtime is present, so this is required. **This restarts IIS and briefly interrupts all three existing sites.**

Download on your laptop from `https://dotnet.microsoft.com/download/dotnet/10.0` — the **ASP.NET Core Runtime Hosting Bundle**, not the SDK — and copy across.

```powershell
$installer = "C:\temp\dotnet-hosting-10.0.x-win.exe"
Start-Process -FilePath $installer -ArgumentList "/quiet","/norestart" -Wait -NoNewWindow

net stop was /y
net start w3svc
```

### ✅ Test gate 1

```powershell
dotnet --list-runtimes
Get-WebGlobalModule | Where-Object { $_.Name -like "*AspNetCore*" }

& "$env:windir\system32\inetsrv\appcmd.exe" list site

curl.exe -I http://swpapp-digisign.swp-rest.police.int/
curl.exe -I http://meetingroomhowto.swp-rest.police.int/
```

Required: `Microsoft.AspNetCore.App 10.0.x` listed, `AspNetCoreModuleV2` present, all three sites Started, both HTTP requests returning a status line.

If `AspNetCoreModuleV2` is missing, the bundle installed before IIS was ready — re-run the installer with `/repair`.

---

## Part 2 — ⚠ Repair the HTTPS binding

`Default Web Site` serves an expired certificate on 443, so **all HTTPS on this server currently fails**. The valid replacement is already in the store, unused.

This is fixed first, as its own stage, so that adding your binding in Part 6 is not compounded with an existing fault.

### 2.1 Record the fault

```powershell
netsh http show sslcert ipport=0.0.0.0:443

curl.exe -v https://swpapp-digisign.swp-rest.police.int/ 2>&1 |
  Select-String "SEC_E|expired|error"
```

Expect `SEC_E_CERT_EXPIRED`. Keep this output — it evidences that the fault pre-dated your change.

### 2.2 Rebind

```powershell
$new   = "03BD544B9A511AB31445C19B0D8B20179539197D"
$appid = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"   # IIS's own, from the existing binding

netsh http delete sslcert ipport=0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 certhash=$new appid=$appid certstorename=MY
netsh http show sslcert ipport=0.0.0.0:443
```

Reusing the same `appid` preserves IIS ownership of the binding.

### ✅ Test gate 2

```powershell
# What is actually served now
$h = 'swpapp-digisign.swp-rest.police.int'
$c = [Net.Sockets.TcpClient]::new($h, 443)
$s = [Net.Security.SslStream]::new($c.GetStream(), $false, { $true })
$s.AuthenticateAsClient($h)
[Security.Cryptography.X509Certificates.X509Certificate2]::new($s.RemoteCertificate) |
  Format-List Subject, NotAfter, Thumbprint
$s.Dispose(); $c.Dispose()

# Handshake completes without forcing trust
curl.exe -I https://swpapp-digisign.swp-rest.police.int/

# Existing HTTP sites unaffected
curl.exe -I http://swpapp-digisign.swp-rest.police.int/signage
curl.exe -I http://meetingroomhowto.swp-rest.police.int/
```

Required: thumbprint `03BD544B…`, `NotAfter` June 2029, curl returns a status line rather than a handshake error, both HTTP sites still responding.

**Back-out for this stage:**

```powershell
netsh http delete sslcert ipport=0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 `
  certhash=E6CB35781050019F64387955CDA49899ADE6CFA3 `
  appid="{4dc3e181-e14b-4a21-b022-59fc669b0914}" certstorename=MY
```

Restores the previous (broken) state exactly.

> **Note for the change record.** After this fix, the other hostnames on that certificate — `meetingroomhowto`, `vthome`, `vchome`, the virtual tours — will complete a TLS handshake where previously they failed, and then serve `Default Web Site` content because those sites bind HTTP only. Both outcomes are wrong; neither is worse than the other. Those services are unaffected in normal (HTTP) use.

> **Renewal trap.** IIS SSL bindings pin to a thumbprint. Auto-enrolled certificates renew with a *new* thumbprint and the binding does not follow — which is exactly what produced this outage. Record 29 June 2029, or script a rebind.

---

## Part 3 — Folder structure

Following local convention: web content under `E:\inetpub\wwwroot`, and data **outside** the web root so IIS never serves it.

```powershell
# Web content
mkdir E:\inetpub\wwwroot\signageadmin -Force
mkdir E:\inetpub\wwwroot\signageadmin\wwwroot\feeds\rss -Force
mkdir E:\inetpub\wwwroot\icthub\images -Force

# Application data - deliberately outside the web root and outside publish,
# so a deployment never touches it and IIS can never serve it
mkdir E:\SignageFeedAdmin\data -Force
mkdir E:\SignageFeedAdmin\keys -Force

Get-ChildItem E:\inetpub\wwwroot -Directory
Get-ChildItem E:\SignageFeedAdmin -Directory
```

`E:\inetpub\wwwroot\signageadmin` is the publish target — replaced wholesale on every deployment. `E:\SignageFeedAdmin\` holds the database and key ring and is never touched by a deployment.

Permissions follow in Part 6.3, once the application pools exist.

---

## Part 4 — Production configuration

### 4.1 appsettings.json

On your laptop, take the dev project and change five values.

```json
{
  "Feed": {
    "DbPath": "E:\\SignageFeedAdmin\\data\\feed.db",
    "ChannelLink": "https://swpapp-digisign.swp-rest.police.int/",
    "LegacyFeedId": "datacenter"
  },
  "Hub": {
    "Url": "/"
  },
  "Feeds": [ ... four feed definitions unchanged from dev ... ],
  "Auth": {
    "AdminGroup": "SWP-NET\\SignageFeedAdmins"
  },
  "DataProtection": {
    "KeyRingPath": "E:\\SignageFeedAdmin\\keys"
  },
  "Logging": { ... unchanged ... },
  "AllowedHosts": "*"
}
```

| Key | Dev | Production | Why |
|---|---|---|---|
| `Feed:DbPath` | `App_Data/feed.db` | `E:\SignageFeedAdmin\data\feed.db` | Survives deployment; outside web root |
| `DataProtection:KeyRingPath` | empty (derived) | `E:\SignageFeedAdmin\keys` | Explicit, no reliance on relative resolution |
| `Feed:ChannelLink` | dev host `/feedhub/` | production host root | Hub sits at the site root here |
| `Hub:Url` | `/feedhub/` | `/` | Same reason |
| `Auth:AdminGroup` | — | `SWP-NET\SignageFeedAdmins` | Should already match dev |

The four feed definitions and their AD groups are unchanged.

### 4.2 The Hub's index.html

**No change needed.** Its tile links are root-relative (`/signageadmin/...`) and its logo path is relative (`images/swp-logo.png`) — both correct with the Hub at the site root.

### 4.3 Build (on your laptop)

```powershell
cd C:\temp\SignageFeedAdmin

Select-String -Path .\appsettings.json -Pattern 'DbPath|ChannelLink|AdminGroup|KeyRingPath|"Url"'

Remove-Item .\bin, .\obj, .\publish -Recurse -Force -ErrorAction SilentlyContinue
dotnet publish -c Release -o .\publish

Select-String -Path .\publish\web.config -Pattern 'forwardWindowsAuthToken|location path="feeds"'
```

Both `web.config` patterns must match. If either is missing, stop — do not hand-patch the published file.

---

## Part 5 — Copy to the server

| From | To |
|---|---|
| `C:\temp\SignageFeedAdmin\publish\*` | `E:\inetpub\wwwroot\signageadmin\` |
| ICT Hub `index.html` | `E:\inetpub\wwwroot\icthub\` |
| `swp-logo.png` | `E:\inetpub\wwwroot\icthub\images\` |

**Do not copy the dev database.** Production starts empty; the application creates it on first run. Dev content is test data and must not reach live displays.

### ✅ Test gate 5

```powershell
Test-Path E:\inetpub\wwwroot\signageadmin\SignageFeedAdmin.dll
Test-Path E:\inetpub\wwwroot\signageadmin\web.config
Test-Path E:\inetpub\wwwroot\icthub\index.html
Test-Path E:\inetpub\wwwroot\icthub\images\swp-logo.png

Select-String -Path E:\inetpub\wwwroot\signageadmin\appsettings.json -Pattern 'DbPath|KeyRingPath|AdminGroup'
```

All four `True`, and the config showing the production paths.

---

## Part 6 — ⚠ IIS site and application

`Default Web Site` is **not** modified. Your site is a sibling, matching how `signage` and `MeetingRoomHowTo` are set up.

### 6.1 Application pools

```powershell
Import-Module WebAdministration

New-WebAppPool -Name "ICTHub"
Set-ItemProperty IIS:\AppPools\ICTHub -Name managedRuntimeVersion -Value ""

New-WebAppPool -Name "SignageAdminApp"
Set-ItemProperty IIS:\AppPools\SignageAdminApp -Name managedRuntimeVersion -Value ""

& "$env:windir\system32\inetsrv\appcmd.exe" list apppool
```

Separate pools are mandatory: in-process ASP.NET Core hosting permits one application per worker process. Sharing a pool produces HTTP 503 on all requests while the pool reports as Started.

### 6.2 Site, bindings and application

```powershell
$ip   = "10.129.242.24"
$host = "swpapp-digisign.swp-rest.police.int"
$cert = "03BD544B9A511AB31445C19B0D8B20179539197D"

# Site: ICT Hub at the root
New-Website -Name "SWPDigiSign" `
  -PhysicalPath "E:\inetpub\wwwroot\icthub" `
  -ApplicationPool "ICTHub" `
  -IPAddress $ip -Port 80 -HostHeader $host

# HTTPS binding with SNI, so it coexists with Default Web Site's catch-all
New-WebBinding -Name "SWPDigiSign" -Protocol https `
  -IPAddress $ip -Port 443 -HostHeader $host -SslFlags 1

# Attach the certificate to the SNI binding
$c = Get-Item "Cert:\LocalMachine\My\$cert"
New-Item -Path "IIS:\SslBindings\$ip!443!$host" -Value $c -SSLFlags 1

# Feed Admin as an application beneath the site
New-WebApplication -Site "SWPDigiSign" -Name "signageadmin" `
  -PhysicalPath "E:\inetpub\wwwroot\signageadmin" `
  -ApplicationPool "SignageAdminApp"

& "$env:windir\system32\inetsrv\appcmd.exe" list site
& "$env:windir\system32\inetsrv\appcmd.exe" list app
netsh http show sslcert
```

The HTTP binding is required — the BrightSign feed path is served over HTTP under the documented security exception.

### ✅ Test gate 6

```powershell
& "$env:windir\system32\inetsrv\appcmd.exe" list site
curl.exe -I http://meetingroomhowto.swp-rest.police.int/
curl.exe -I http://swpapp-digisign.swp-rest.police.int/signage
curl.exe -I https://swpapp-digisign.swp-rest.police.int/
```

Required: all four sites Started, both existing sites still responding, and the new site answering on both protocols. The application itself will not work yet — permissions and authentication follow.

### 6.3 Permissions

```powershell
icacls "E:\SignageFeedAdmin\data" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"
icacls "E:\SignageFeedAdmin\keys" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"
icacls "E:\inetpub\wwwroot\signageadmin\wwwroot\feeds" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"

icacls "E:\SignageFeedAdmin\data"
icacls "E:\SignageFeedAdmin\keys"
```

---

## Part 7 — Authentication

**Windows Auth on first, anonymous off second.** Reversing the order locks the application out entirely.

```powershell
# ICT Hub (site root)
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "SWPDigiSign" `
  -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value $true
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "SWPDigiSign" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value $false

# Feed Admin
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "SWPDigiSign/signageadmin" `
  -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value $true
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "SWPDigiSign/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value $false

# Anonymous identity must be the application pool, not IUSR.
# This is what the /feeds carve-out inherits.
Set-WebConfigurationProperty -PSPath "IIS:\" -Location "SWPDigiSign/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name userName -Value ""
```

These are scoped to your site, so the other three sites are unaffected.

The `/feeds` anonymous carve-out needs nothing here — it lives in the application's own `web.config` and travels with the deployment.

---

## Part 8 — ⚠ Scoped anonymous unlock

The `<location path="feeds">` block overrides anonymous authentication for the feed path. IIS refuses that override unless the section is unlocked for the application.

The survey found the global lock at `Deny` — the correct default — so this stage only adds a scoped unlock. **Do not unlock server-wide.**

```powershell
# Confirm the global default is still Deny before proceeding
Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

# Unlock for this application only
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Location "SWPDigiSign/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Allow

# Verify: global Deny, application Allow
Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Location "SWPDigiSign/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective
```

If the global setting reads anything other than `Deny`, stop and report it — something changed since the survey.

---

## Part 9 — Start and verify

```powershell
Start-WebAppPool -Name "ICTHub"
Start-WebAppPool -Name "SignageAdminApp"
Start-Website -Name "SWPDigiSign"

& "$env:windir\system32\inetsrv\appcmd.exe" list site
& "$env:windir\system32\inetsrv\appcmd.exe" list apppool
```

### 9.1 Did the application start?

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='IIS AspNetCore Module V2'} -MaxEvents 5 |
  Format-List TimeCreated, Id, Message
```

You want **"started successfully"**. Configuration is validated at startup and the application refuses to start on a bad feed definition — a failure here names the offending feed.

### 9.2 Did it create its files?

```powershell
Get-ChildItem E:\SignageFeedAdmin\data                                    # feed.db
Get-ChildItem E:\SignageFeedAdmin\keys                                    # key-*.xml
Get-ChildItem E:\inetpub\wwwroot\signageadmin\wwwroot\feeds\rss           # 4 XML files
```

Four XML files — `servicedesk`, `systems`, `datacenter`, `news` — valid but empty. An empty `feeds\rss` means the pool cannot write there; recheck Part 6.3.

### 9.3 Browser checks

| Check | Expected |
|---|---|
| `https://swpapp-digisign.swp-rest.police.int/` | Hub renders, logo visible, four tiles, no certificate warning |
| Click a tile | Item list, signed in as you, no prompt |
| Add, edit, delete an item | Works; feed republishes |
| Audit log | Shows your changes |
| `← ICT Hub` link | Returns to the Hub |
| Private window on `http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/datacenter.xml` | Raw XML, **no credential prompt** |

The last is the critical test — the anonymous carve-out the 64 players depend on.

### 9.4 Data Protection

Add an item, then:

```powershell
Restart-WebAppPool -Name "SignageAdminApp"
```

Return to an already-open edit page and save. It must succeed. HTTP 400 means the key ring is not persisting — check `E:\SignageFeedAdmin\keys` and its permissions.

### ✅ Test gate 9 — other sites

```powershell
curl.exe -I http://meetingroomhowto.swp-rest.police.int/
curl.exe -I http://swpapp-digisign.swp-rest.police.int/signage
curl.exe -I http://swpapp-digisign.swp-rest.police.int/
```

Last chance to catch collateral damage while the cause is still obvious.

---

## Part 10 — Repoint the players

Only once Part 9 passes completely.

```
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/servicedesk.xml
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/systems.xml
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/datacenter.xml
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/news.xml
```

**HTTP, not HTTPS** — the documented security exception. The BrightSign feed subsystem cannot validate the internal CA and offers no bypass.

1. Repoint **one** player. Add a distinctive test item and confirm it appears on the display.
2. Allow a full poll cycle; players cache, so an immediate blank is not necessarily failure.
3. Only then roll out to the group in BrightAuthor:connected.
4. Each display takes two feeds: its business unit's, plus `news.xml`.

If a player does not update:

```powershell
Get-ChildItem E:\inetpub\logs\LogFiles\W3SVC4\*.log |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
  Get-Content | Select-String 'rss' | Select-Object -Last 20
```

Your site will be id 4, so `W3SVC4`. No entry from the player's IP means the request never arrived — network or URL, not the application.

---

## Part 11 — After deployment

- [ ] Populate the four AD groups with real business unit editors
- [ ] Confirm isolation with an account in one group only — refused on another unit's URL typed directly, and `?all=true` on its audit page returns only its own feed
- [ ] Add `E:\SignageFeedAdmin\data` to the server backup scope
- [ ] Record certificate renewal (29 June 2029) and the rebinding requirement
- [ ] Update Technical Documentation and User Guide with production URLs
- [ ] Refresh the source backup
- [ ] Raise removal of the abandoned `signage` site (id 2) and `Default Web Site/signage` as a separate tidy-up
- [ ] Decommission the dev instance, or mark it clearly as non-production

---

## Impact on other services (for the change request)

| Step | Impact | Mitigation |
|---|---|---|
| Hosting Bundle install (1.2) | IIS restart — brief outage for all three existing sites | Scheduled window; test gate 1 confirms recovery |
| Certificate rebind (2.2) | Restores HTTPS server-wide. Other hostnames on the certificate move from handshake failure to serving Default Web Site content — both wrong, neither worse. Those sites are HTTP-only and unaffected in normal use. | Test gate 2; single-command back-out |
| New site and SNI binding (6.2) | None expected — SNI coexists with the catch-all | Test gate 6 |
| Application pools (6.1) | None | — |
| Authentication (7) | None — scoped to the new site | — |
| Anonymous unlock (8) | None — scoped to the new application; global lock untouched | Verified before and after |

Everything except the Hosting Bundle install and the certificate rebind is purely additive. No existing site, application, pool or binding is modified or removed.

---

## Back-out

Nothing existing is replaced. Back-out is stopping what was created.

```powershell
# Remove the new site and pools
Stop-Website -Name "SWPDigiSign"
Remove-Website -Name "SWPDigiSign"
Remove-WebAppPool -Name "SignageAdminApp"
Remove-WebAppPool -Name "ICTHub"

# Remove the scoped unlock
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Location "SWPDigiSign/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Deny
```

Certificate rebind back-out is in Part 2.2. The Hosting Bundle can be left installed — it affects nothing that is not using it.

Folders under `E:\inetpub\wwwroot\signageadmin`, `E:\inetpub\wwwroot\icthub` and `E:\SignageFeedAdmin` can then be removed manually.

If players have already been repointed, revert them to the dev URLs in BrightAuthor:connected. The dev instance continues serving until they are.

---

## Things that will catch you out

| Symptom | Cause |
|---|---|
| HTTP 503, pool reports Started | Two ASP.NET Core applications in one pool. Each needs its own. |
| HTTP 500.19 on the feed path | `anonymousAuthentication` not unlocked for the application — Part 8 |
| Credential prompt on the feed URL | Anonymous identity is `IUSR` rather than the application pool — Part 7 |
| HTTP 400 on Save after a recycle | Data Protection key ring not persisting — Part 9.4 |
| Feed 404s but admin pages work | `<location path="feeds">` missing its `<handlers>` block, or path written as `wwwroot/feeds` |
| Application will not start | Configuration validation failed; the Event Log names the feed |
| `WebAdministration` cmdlets return nothing | Known on this server. Use `appcmd` for enumeration. |
| HTTPS fails again in 2029 | Certificate renewed with a new thumbprint; binding still points at the old one |
| Feed works over HTTP but not HTTPS on players | Expected. Documented exception. Do not "fix" by forcing HTTPS. |

**Do not add an HTTP-to-HTTPS redirect to this site.** It would break the feed for all 64 players. If policy later requires one, it must exclude `/signageadmin/feeds`.
