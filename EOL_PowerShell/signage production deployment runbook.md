# SWP Signage Feed Admin — Production Deployment Runbook

**Target server:** `swpapp-digisign.swp-rest.police.int`
**Assumption:** shared IIS server hosting other teams' applications
**Version:** 2.0 (supersedes v1.0, which assumed a dedicated server)
**Prepared:** 16 September 2026
**Prepared by:** James Buller, ICT Datacenter Team

---

## How to use this document

Work through the parts in order. **Part 0 is a hard gate** — its output decides Part 6, and may remove the need for Part 1 entirely.

Commands are PowerShell, run **elevated**, on the target server unless the heading says otherwise.

Because the server is shared, three steps carry risk to **other teams' applications**. They are marked ⚠ and each has a check that the other applications still work afterwards. Do not batch these with anything else.

---

## Part 0 — Discovery (run first, report back)

Nothing here changes anything.

```powershell
# --- Identity and OS ---
$env:COMPUTERNAME
[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version

# --- IIS role services ---
Get-WindowsFeature Web-Server, Web-Windows-Auth, Web-Static-Content, Web-Http-Logging |
  Select-Object Name, InstallState

# --- Is a .NET runtime already present? ---
dotnet --list-runtimes 2>$null
if (-not $?) { "No dotnet runtime on PATH" }
Get-WebGlobalModule | Where-Object { $_.Name -like "*AspNetCore*" }

# --- What else lives here? ---
Import-Module WebAdministration
Get-Website | Select-Object Name, State, PhysicalPath, ID
Get-WebApplication
Get-ChildItem IIS:\AppPools | Select-Object Name, State, ManagedRuntimeVersion

# --- Bindings and certificates in use ---
Get-WebBinding | Select-Object protocol, bindingInformation, ItemXPath
netsh http show sslcert

# --- Certificate for our hostname ---
Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Subject -like "*DIGISIGN*" -or ($_.DnsNameList -join ' ') -like "*digisign*" } |
  Format-List Subject, DnsNameList, NotBefore, NotAfter, Thumbprint, HasPrivateKey, EnhancedKeyUsageList, Issuer

# --- CRITICAL: current lock state of anonymousAuthentication ---
# If this already reads Allow, something else on this server may depend on it.
Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

# --- DNS ---
Resolve-DnsName swpapp-digisign.swp-rest.police.int

# Are we actually elevated?
(New-Object Security.Principal.WindowsPrincipal(
  [Security.Principal.WindowsIdentity]::GetCurrent())
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# IIS state, via appcmd - independent of the PowerShell provider
Get-Service W3SVC, WAS | Select-Object Name, Status, StartType
Test-Path C:\Windows\System32\inetsrv\appcmd.exe
& "$env:windir\system32\inetsrv\appcmd.exe" list site
& "$env:windir\system32\inetsrv\appcmd.exe" list app
& "$env:windir\system32\inetsrv\appcmd.exe" list apppool

# Full SAN lists - I need to know who else depends on these
(Get-Item Cert:\LocalMachine\My\03BD544B9A511AB31445C19B0D8B20179539197D).DnsNameList
(Get-Item Cert:\LocalMachine\My\E6CB35781050019F64387955CDA49899ADE6CFA3).DnsNameList

# What is actually listening
Get-NetTCPConnection -State Listen -LocalPort 80,443 |
  Select-Object LocalAddress, LocalPort, OwningProcess
```

### How to read the output

| Finding | Consequence |
|---|---|
| `AspNetCoreModuleV2` present in global modules | **Hosting Bundle already installed.** Part 1.2 can be skipped — no IIS restart, no change window for it. Verify the version covers .NET 10. |
| No `AspNetCoreModuleV2` | Part 1.2 required, and it restarts IIS. ⚠ Affects every application on this server — schedule a window. |
| `Web-Windows-Auth` not installed | Required. Installing a role service can also restart IIS. ⚠ |
| A binding `*:443:` with no hostname on another site | Your HTTPS binding needs **SNI**. Part 6, Option A. |
| No 443 binding at all | Simpler — a plain hostname binding works. |
| Certificate with `Server Authentication` EKU and our hostname | Good. Use its thumbprint. |
| Certificate EKU shows only *SSL Secured Remote Desktop* | Unusable — that is the RDP certificate. Request a Web Server template certificate from PKI. Lead-time item. |
| `OverrideModeEffective` already `Allow` globally | **Do not simply lock it in Part 8.** Something may depend on it. See Part 8.1. |
| Several `.NET`-looking applications sharing one pool | Informational, but note in-process hosting permits one ASP.NET Core app per pool. |

**Stop here. Send me the output before continuing** — Part 6 has two mutually exclusive routes and this decides which.

---

## Part 1 — Prerequisites

### 1.1 IIS role services

Only if Part 0 showed something missing.

```powershell
Get-WindowsFeature Web-Server, Web-Windows-Auth, Web-Static-Content | Select-Object Name, InstallState
```

⚠ If `Web-Windows-Auth` is missing, installing it may restart IIS:

```powershell
Install-WindowsFeature -Name Web-Windows-Auth
```

Then check the other applications still respond before going further.

### 1.2 .NET 10 Hosting Bundle

**Skip entirely if Part 0 showed `AspNetCoreModuleV2` and a .NET 10 runtime.**

⚠ This installer restarts IIS, interrupting every application on the server. Schedule a window and notify the other application owners.

Download on your laptop from `https://dotnet.microsoft.com/download/dotnet/10.0` — the **ASP.NET Core Runtime Hosting Bundle**, not the SDK — and copy across.

```powershell
$installer = "C:\temp\dotnet-hosting-10.0.x-win.exe"
Start-Process -FilePath $installer -ArgumentList "/quiet","/norestart" -Wait -NoNewWindow

net stop was /y
net start w3svc

dotnet --list-runtimes
Get-WebGlobalModule | Where-Object { $_.Name -like "*AspNetCore*" }
```

**Then immediately confirm the other applications on this server still work.** Browse two or three of them. A failed Hosting Bundle install that breaks an existing app is far easier to unpick within minutes than hours.

---

## Part 2 — Certificate

Confirm all four before using a certificate:

- `DnsNameList` contains `swpapp-digisign.swp-rest.police.int`
- `EnhancedKeyUsageList` includes **Server Authentication**
- `HasPrivateKey` is **True**
- `NotAfter` is comfortably in the future

```powershell
$certThumb = "<thumbprint from Part 0>"
Get-ChildItem Cert:\LocalMachine\My\$certThumb |
  Format-List Subject, DnsNameList, NotAfter, EnhancedKeyUsageList
```

If no suitable certificate exists, raise a PKI request on a **Web Server** template now — it is the longest lead-time item in this deployment.

> **For the runbook:** IIS SSL bindings pin to a *thumbprint*. Auto-enrolled certificates renew with a new thumbprint and the binding does not follow, producing a silent HTTPS outage. Record the renewal date or script a rebind.

---

## Part 3 — Folder structure

Production keeps the database and key ring **outside** the publish folder, so deployments never touch them.

```powershell
mkdir C:\inetpub\SignageFeedAdmin\publish -Force
mkdir C:\inetpub\SignageFeedAdmin\data -Force
mkdir C:\inetpub\SignageFeedAdmin\keys -Force
mkdir C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss -Force
mkdir C:\inetpub\SWPICTHub\images -Force

Get-ChildItem C:\inetpub -Directory
```

Permissions come in Part 6.4, once the application pools exist.

---

## Part 4 — Production configuration

### 4.1 The values depend on Part 6's route

Two of these differ between the two structural options. **Do not build until Part 6 is decided.**

```json
{
  "Feed": {
    "DbPath": "C:\\inetpub\\SignageFeedAdmin\\data\\feed.db",
    "ChannelLink": "<see table below>",
    "LegacyFeedId": "datacenter"
  },
  "Hub": {
    "Url": "<see table below>"
  },
  "Feeds": [ ... unchanged from dev ... ],
  "Auth": {
    "AdminGroup": "SWP-NET\\SignageFeedAdmins"
  },
  "DataProtection": {
    "KeyRingPath": "C:\\inetpub\\SignageFeedAdmin\\keys"
  },
  "Logging": { ... unchanged ... },
  "AllowedHosts": "*"
}
```

| Setting | Option A (own site) | Option B (under Default Web Site) |
|---|---|---|
| `Hub:Url` | `/` | `/feedhub/` |
| `Feed:ChannelLink` | `https://swpapp-digisign.swp-rest.police.int/` | `https://swpapp-digisign.swp-rest.police.int/feedhub/` |

Unchanged from dev in both cases: the four feed definitions and their AD groups.

Changed from dev in both cases: `DbPath` and `KeyRingPath` become absolute paths outside `publish`, and `AdminGroup` is `SignageFeedAdmins`.

### 4.2 The Hub's index.html

No change needed for either option. Its tile links are root-relative (`/signageadmin/...`) and its logo path is relative — both correct whether the Hub sits at the root or under `/feedhub/`.

### 4.3 Build (on your laptop)

```powershell
cd C:\temp\SignageFeedAdmin

Select-String -Path .\appsettings.json -Pattern 'DbPath|ChannelLink|AdminGroup|KeyRingPath|"Url"'

Remove-Item .\bin, .\obj, .\publish -Recurse -Force -ErrorAction SilentlyContinue
dotnet publish -c Release -o .\publish

Select-String -Path .\publish\web.config -Pattern 'forwardWindowsAuthToken|location path="feeds"'
```

Both `web.config` patterns must match. If either is missing, stop — do not hand-patch.

---

## Part 5 — Copy to the server

| From | To |
|---|---|
| `C:\temp\SignageFeedAdmin\publish\*` | `C:\inetpub\SignageFeedAdmin\publish\` |
| ICT Hub `index.html` | `C:\inetpub\SWPICTHub\` |
| `swp-logo.png` | `C:\inetpub\SWPICTHub\images\` |

**Do not copy the dev database.** Production starts empty; the application creates it on first run. Dev content is test data.

```powershell
Test-Path C:\inetpub\SignageFeedAdmin\publish\SignageFeedAdmin.dll
Test-Path C:\inetpub\SignageFeedAdmin\publish\web.config
Test-Path C:\inetpub\SWPICTHub\index.html
Test-Path C:\inetpub\SWPICTHub\images\swp-logo.png
```

All four must be `True`.

---

## Part 6 — IIS structure

**`Default Web Site` is NOT stopped.** Other teams' applications depend on it. The v1.0 instruction to stop it does not apply to a shared server.

### 6.1 Application pools (both options)

```powershell
Import-Module WebAdministration

New-WebAppPool -Name "SWPICTHub"
Set-ItemProperty IIS:\AppPools\SWPICTHub -Name managedRuntimeVersion -Value ""

New-WebAppPool -Name "SignageAdminApp"
Set-ItemProperty IIS:\AppPools\SignageAdminApp -Name managedRuntimeVersion -Value ""

Get-ChildItem IIS:\AppPools | Select-Object Name, State, ManagedRuntimeVersion
```

Separate pools are mandatory, not tidiness: in-process hosting permits one ASP.NET Core application per worker process. Sharing a pool produces HTTP 503 on all requests while the pool reports as Started.

---

### Option A — Own site with an SNI binding (preferred)

Use when the hostname belongs to this application and another site already holds a catch-all 443 binding.

Gives you the Hub at the root, complete separation from `Default Web Site`, and no inherited configuration.

```powershell
# Site: Hub at the root, HTTPS with SNI so it coexists with any catch-all binding
New-Website -Name "SWPDigiSign" `
  -PhysicalPath "C:\inetpub\SWPICTHub" `
  -ApplicationPool "SWPICTHub" `
  -HostHeader "swpapp-digisign.swp-rest.police.int" `
  -Port 443 -Ssl -SslFlags 1

# HTTP binding on the same hostname - required for the BrightSign feed path
New-WebBinding -Name "SWPDigiSign" -Protocol http -Port 80 `
  -HostHeader "swpapp-digisign.swp-rest.police.int"

# Bind the certificate. SNI bindings are registered per hostname:port.
$certThumb = "<thumbprint from Part 2>"
$cert = Get-Item "Cert:\LocalMachine\My\$certThumb"
New-Item -Path "IIS:\SslBindings\!443!swpapp-digisign.swp-rest.police.int" -Value $cert -SSLFlags 1

# Feed Admin as an application beneath the site
New-WebApplication -Site "SWPDigiSign" -Name "signageadmin" `
  -PhysicalPath "C:\inetpub\SignageFeedAdmin\publish" `
  -ApplicationPool "SignageAdminApp"

Get-WebBinding -Name "SWPDigiSign" | Select-Object protocol, bindingInformation
Get-WebApplication -Site "SWPDigiSign" | Format-List Path, PhysicalPath, ApplicationPool
netsh http show sslcert
```

⚠ **Immediately check another team's application still responds.** Adding an SNI binding should not disturb a catch-all, but confirm rather than assume.

Resulting URLs:

| URL | Serves |
|---|---|
| `https://swpapp-digisign.swp-rest.police.int/` | ICT Hub |
| `https://swpapp-digisign.swp-rest.police.int/signageadmin` | Feed picker |
| `http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/<unit>.xml` | Published feed |

---

### Option B — Applications under Default Web Site

Use only if the hostname is shared with other applications, or you are not permitted to add a site.

Same pattern as dev. No binding work, but the Hub cannot sit at the root, and both applications inherit `Default Web Site`'s configuration.

```powershell
# Check what would be inherited BEFORE creating anything
$dwsPath = (Get-Website -Name "Default Web Site").PhysicalPath
$dwsPath
Test-Path "$dwsPath\web.config"
if (Test-Path "$dwsPath\web.config") { Get-Content "$dwsPath\web.config" }
```

If that `web.config` exists and contains anything — rewrite rules, custom headers, authentication settings — **stop and send it to me**. It will apply to your applications too.

```powershell
New-WebApplication -Site "Default Web Site" -Name "feedhub" `
  -PhysicalPath "C:\inetpub\SWPICTHub" -ApplicationPool "SWPICTHub"

New-WebApplication -Site "Default Web Site" -Name "signageadmin" `
  -PhysicalPath "C:\inetpub\SignageFeedAdmin\publish" -ApplicationPool "SignageAdminApp"

Get-WebApplication -Site "Default Web Site" |
  Where-Object { $_.Path -match 'feedhub|signageadmin' } |
  Format-List Path, PhysicalPath, ApplicationPool
```

Confirm `Default Web Site` has an HTTP binding — the feed path needs it. If it is HTTPS only, add one:

```powershell
New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 `
  -HostHeader "swpapp-digisign.swp-rest.police.int"
```

---

### 6.4 Permissions (both options)

```powershell
icacls "C:\inetpub\SignageFeedAdmin\data" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"
icacls "C:\inetpub\SignageFeedAdmin\keys" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"
icacls "C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds" /grant "IIS AppPool\SignageAdminApp:(OI)(CI)(M)"

icacls "C:\inetpub\SignageFeedAdmin\data"
icacls "C:\inetpub\SignageFeedAdmin\keys"
```

---

## Part 7 — Authentication

Substitute `<SITE>` with `SWPDigiSign` (Option A) or `Default Web Site` (Option B), and `<HUB>` with `SWPDigiSign` (Option A — the site root is the Hub) or `Default Web Site/feedhub` (Option B).

**Windows Auth on first, anonymous off second.** Reversing the order locks the application out entirely.

```powershell
$hub   = "<HUB>"
$admin = "<SITE>/signageadmin"

# Hub
Set-WebConfigurationProperty -PSPath "IIS:\" -Location $hub `
  -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value $true
Set-WebConfigurationProperty -PSPath "IIS:\" -Location $hub `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value $false

# Feed Admin
Set-WebConfigurationProperty -PSPath "IIS:\" -Location $admin `
  -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value $true
Set-WebConfigurationProperty -PSPath "IIS:\" -Location $admin `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value $false

# Anonymous identity must be the application pool, not IUSR.
# This is what the /feeds carve-out inherits.
Set-WebConfigurationProperty -PSPath "IIS:\" -Location $admin `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name userName -Value ""
```

Under Option B these are scoped to the applications, so other applications under `Default Web Site` are unaffected.

If a command fails with a lock error, go to Part 8 — but read 8.1 first.

---

## Part 8 — ⚠ Scoped anonymous unlock

The `<location path="feeds">` block in `web.config` overrides anonymous authentication for the feed path. IIS refuses that override unless the section is unlocked for the application.

### 8.1 Check the current state first

```powershell
Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective
```

**If this reads `Deny` (the default):** proceed to 8.2. Add only the scoped unlock; do not touch the global setting.

**If this reads `Allow`:** somebody unlocked it server-wide. Another application may depend on it. **Do not lock it as part of this deployment.** Add your scoped unlock, leave the global setting alone, and raise the server-wide unlock separately as a finding for the server owner. Tightening someone else's configuration during your own change is how an unrelated outage gets attributed to you.

### 8.2 Scoped unlock

```powershell
# Only if 8.1 showed Deny - establishes the correct default explicitly
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Deny

# Always: unlock for this application only
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Location "<SITE>/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Allow

# Verify
Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Location "<SITE>/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective
```

Global `Deny`, application `Allow`.

⚠ **Then check two other teams' applications still work.** If either broke, revert the global setting immediately:

```powershell
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Allow
```

---

## Part 9 — Start and verify

```powershell
Start-WebAppPool -Name "SWPICTHub"
Start-WebAppPool -Name "SignageAdminApp"
# Option A only:
Start-Website -Name "SWPDigiSign"
```

### 9.1 Did the application start?

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='IIS AspNetCore Module V2'} -MaxEvents 5 |
  Format-List TimeCreated, Id, Message
```

You want **"started successfully"**. Configuration is validated at startup — a failure here names the offending feed.

### 9.2 Did it create its files?

```powershell
Get-ChildItem C:\inetpub\SignageFeedAdmin\data      # feed.db
Get-ChildItem C:\inetpub\SignageFeedAdmin\keys      # key-*.xml
Get-ChildItem C:\inetpub\SignageFeedAdmin\publish\wwwroot\feeds\rss   # 4 XML files
```

If `feeds\rss` is empty, the pool cannot write there — recheck Part 6.4.

### 9.3 Browser checks

| Check | Expected |
|---|---|
| Hub URL | Renders, logo visible, four tiles, no certificate warning |
| Click a tile | Item list, signed in as you, no prompt |
| Add, edit, delete an item | Works; feed republishes |
| Audit log | Shows your changes |
| `← ICT Hub` link | Returns to the Hub |
| Private window on the HTTP feed URL | Raw XML, **no credential prompt** |

The last is the critical test — it is the anonymous carve-out the 64 players depend on.

### 9.4 Data Protection

Add an item, then:

```powershell
Restart-WebAppPool -Name "SignageAdminApp"
```

Return to an already-open edit page and save. It must succeed. HTTP 400 means the key ring is not persisting — check the `keys` folder and its permissions.

### 9.5 ⚠ Other applications

Browse two or three other applications on this server. This is the last chance to catch collateral damage while the cause is obvious.

---

## Part 10 — Repoint the players

Only once Part 9 passes completely.

```
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/servicedesk.xml
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/systems.xml
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/datacenter.xml
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/news.xml
```

**HTTP, not HTTPS** — the documented security exception.

1. Repoint **one** player. Add a distinctive test item and confirm it appears.
2. Allow a full poll cycle; players cache, so an immediate blank is not necessarily failure.
3. Only then roll out to the group.
4. Each display takes two feeds: its business unit's, plus `news.xml`.

If a player does not update:

```powershell
Get-ChildItem C:\inetpub\logs\LogFiles\W3SVC*\*.log |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
  Get-Content | Select-String 'rss' | Select-Object -Last 20
```

No entry from the player's IP means the request never arrived — network or URL, not the application.

---

## Part 11 — After deployment

- [ ] Populate the four AD groups with real business unit editors
- [ ] Confirm isolation with an account in one group only — refused on another unit's URL typed directly, and `?all=true` on its audit page returns only its own feed
- [ ] Add `C:\inetpub\SignageFeedAdmin\data` to the server backup scope
- [ ] Record the certificate renewal date and the rebinding requirement
- [ ] If Part 8.1 found a server-wide unlock, raise it with the server owner as a separate finding
- [ ] Update Technical Documentation and User Guide with production URLs
- [ ] Refresh the source backup
- [ ] Decommission the dev instance, or mark it clearly as non-production

---

## Impact on other applications (for the change request)

| Step | Impact | Mitigation |
|---|---|---|
| Hosting Bundle install (Part 1.2) | IIS restart — brief outage for **every** application on the server | Scheduled window; skip entirely if already installed |
| Windows Auth role service (Part 1.1) | May restart IIS | Usually already present; check first |
| New site and SNI binding (Part 6, Option A) | None expected — SNI coexists with catch-all bindings | Verify another application immediately after |
| New applications under Default Web Site (Part 6, Option B) | None — additive only | Verify after |
| Anonymous unlock (Part 8) | Locking globally could break an application relying on a server-wide unlock | Check state first (8.1); do not lock if already unlocked |
| Application pool creation | None | — |

Everything else is additive: new folders, new pools, new applications. Nothing existing is modified or removed.

---

## Back-out plan

Nothing existing is replaced, so back-out is stopping what was created. The dev instance continues serving the players until they are repointed.

```powershell
# Option A
Stop-Website -Name "SWPDigiSign"
Stop-WebAppPool -Name "SignageAdminApp"
Stop-WebAppPool -Name "SWPICTHub"

# Option B
Remove-WebApplication -Site "Default Web Site" -Name "signageadmin"
Remove-WebApplication -Site "Default Web Site" -Name "feedhub"
Stop-WebAppPool -Name "SignageAdminApp"
Stop-WebAppPool -Name "SWPICTHub"
```

If Part 8 broke another application, revert the global lock:

```powershell
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Allow
```

If players have already been repointed, revert them to the dev URLs in BrightAuthor:connected.

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
| HTTPS fails months later | Certificate renewed with a new thumbprint; binding still points at the old one |
| Feed works over HTTP but not HTTPS on players | Expected. Documented exception. Do not "fix" by forcing HTTPS. |
| Another team's app breaks after Part 8 | It relied on the server-wide unlock. Revert and raise separately. |

**Do not add an HTTP-to-HTTPS redirect to this site.** It would break the feed for all 64 players. If policy later requires one, it must exclude `/signageadmin/feeds`.
