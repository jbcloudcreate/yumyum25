# SWP Signage Feed Admin — Production Remediation Runbook

**Server:** `swpapp-digisign.swp-rest.police.int` (`10.129.242.24`)
**Version:** 1.0
**Date:** 17 September 2026
**Prepared by:** James Buller, ICT Datacenter Team
**Follows:** Production Deployment Runbook v3.0, session `prod-deploy-20260917-1218`

---

## Why this runbook exists

The deployment on 17 September completed Parts 1 to 8 of the main runbook. Two issues remain.

### Issue 1 — Site bindings carry an invalid host header

Part 6.2 of the main runbook used `$host` as a variable name. `$host` is a **read-only automatic variable** in PowerShell, so the assignment was rejected and the variable kept its original value — the PowerShell host object. That object was then stringified into both bindings:

```
SITE "SWPDigiSign" (id:4,
  bindings:http/10.129.242.24:80:System.Management.Automation.Internal.Host.InternalHost,
           https/10.129.242.24:443:System.Management.Automation.Internal.Host.InternalHost)
```

The SNI certificate binding carries the same invalid hostname. The site therefore answers only to a hostname no client will ever request, which is why nothing is reachable.

This is a defect in the runbook, not an operator error. The main runbook is corrected in v3.1.

### Issue 2 — URL structure differs from dev

The main runbook placed the ICT Hub at the site root. Dev serves it at `/feedhub`, and that path is already in circulation — bookmarks, the pilot users' Teams message, and the documentation. Production should match.

### What was completed successfully

Confirmed from the deployment transcript — none of this needs repeating:

- .NET 10 Hosting Bundle installed; `AspNetCoreModuleV2` registered
- Certificate rebind on `0.0.0.0:443` to `03BD544B…` — HTTPS repaired server-wide
- Site `SWPDigiSign` (id 4) created with correct physical paths
- Application pools `ICTHub` and `SignageAdminApp` created, No Managed Code
- Application `SWPDigiSign/signageadmin` created and pointed correctly
- Folder structure and `icacls` grants applied
- Authentication configured at site and application scope
- `anonymousAuthentication` unlocked, scoped to `SWPDigiSign/signageadmin`, global lock left at `Deny`

### Target state after this runbook

| URL | Serves |
|---|---|
| `https://swpapp-digisign.swp-rest.police.int/` | Redirect to the Hub |
| `https://swpapp-digisign.swp-rest.police.int/feedhub/` | ICT Hub |
| `https://swpapp-digisign.swp-rest.police.int/signageadmin` | Feed picker |
| `https://swpapp-digisign.swp-rest.police.int/signageadmin/<unit>` | Business unit administration |
| `http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/<unit>.xml` | Published feeds |

---

## Part 0 — Start the transcript

Run first, in the elevated session used for the whole remediation.

```powershell
$deployRoot = "C:\temp\SignageDeploy"
$stamp      = Get-Date -Format 'yyyyMMdd-HHmm'
mkdir "$deployRoot\transcripts" -Force | Out-Null

$transcript = "$deployRoot\transcripts\prod-remediation-$stamp.log"
Start-Transcript -Path $transcript -IncludeInvocationHeader

"=== SWP Signage Feed Admin - production remediation ==="
"Runbook version : Remediation 1.0"
"Follows         : Deployment v3.0, session prod-deploy-20260917-1218"
"Server          : $env:COMPUTERNAME"
"Operator        : $env:USERDOMAIN\$env:USERNAME"
"Started         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"Transcript      : $transcript"
"======================================================="
```

### Stage marker helper

Note the quotes — `Mark "Part 1 - remove invalid bindings"`, not `Mark Part 1 ...`. Without them PowerShell passes only the first word, which is why the previous transcript shows markers reading just `Part`.

```powershell
function Mark([string]$text) {
    ""
    "########## $text  [$(Get-Date -Format 'HH:mm:ss')] ##########"
    ""
}
```

### Shared variables

Defined once here and used throughout. **`$siteHost`, not `$host`** — the latter is read-only and caused the fault this runbook is fixing.

```powershell
$ip       = "10.129.242.24"
$siteHost = "swpapp-digisign.swp-rest.police.int"
$cert     = "03BD544B9A511AB31445C19B0D8B20179539197D"
$bad      = "System.Management.Automation.Internal.Host.InternalHost"

# Confirm the assignments actually took - the previous failure was silent enough to miss
"ip       = $ip"
"siteHost = $siteHost"
"cert     = $cert"
"bad      = $bad"
```

If `siteHost` prints anything other than the hostname, stop.

### If the session drops

```powershell
$transcript = "C:\temp\SignageDeploy\transcripts\prod-remediation-<original stamp>.log"
Start-Transcript -Path $transcript -Append -IncludeInvocationHeader
"=== Resumed $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') at Part <n> ==="
```

Re-declare the shared variables after resuming.

---

## Part 1 — Record the current state

```powershell
Mark "Part 1 - record current state"

Import-Module WebAdministration

& "$env:windir\system32\inetsrv\appcmd.exe" list site
& "$env:windir\system32\inetsrv\appcmd.exe" list app
netsh http show sslcert
Get-WebBinding -Name "SWPDigiSign" | Select-Object protocol, bindingInformation
```

Expected: `SWPDigiSign` showing the `InternalHost` hostname on both bindings, and an SNI certificate binding under the same invalid hostname. This is the "before" evidence.

---

## Part 2 — ⚠ Remove the invalid bindings

Only bindings on site `SWPDigiSign` are touched. `Default Web Site`, `signage` and `MeetingRoomHowTo` are not affected.

```powershell
Mark "Part 2 - remove invalid bindings"

# SNI certificate binding registered under the invalid hostname
netsh http delete sslcert hostnameport="$bad`:443"

# The two site bindings
Remove-WebBinding -Name "SWPDigiSign" -Protocol http  -Port 80  -HostHeader $bad -IPAddress $ip
Remove-WebBinding -Name "SWPDigiSign" -Protocol https -Port 443 -HostHeader $bad -IPAddress $ip

Get-WebBinding -Name "SWPDigiSign"
```

The site now has no bindings and is unreachable — expected and temporary.

### ✅ Test gate 2

```powershell
netsh http show sslcert
curl.exe -I http://meetingroomhowto.swp-rest.police.int/
curl.exe -I http://swpapp-digisign.swp-rest.police.int/signage

Mark "TEST GATE 2 - <PASSED|FAILED>"
```

Required: the `0.0.0.0:443` binding still present with `03bd544b…`, the invalid hostname binding gone, and both existing sites still responding.

**Do not proceed on a failure.** The `0.0.0.0:443` binding is the server-wide HTTPS repair and must remain intact.

---

## Part 3 — Add correct bindings

```powershell
Mark "Part 3 - add correct bindings"

New-WebBinding -Name "SWPDigiSign" -Protocol http `
  -IPAddress $ip -Port 80 -HostHeader $siteHost

New-WebBinding -Name "SWPDigiSign" -Protocol https `
  -IPAddress $ip -Port 443 -HostHeader $siteHost -SslFlags 1

$c = Get-Item "Cert:\LocalMachine\My\$cert"
New-Item -Path "IIS:\SslBindings\$ip!443!$siteHost" -Value $c -SSLFlags 1

& "$env:windir\system32\inetsrv\appcmd.exe" list site
netsh http show sslcert
```

### ✅ Test gate 3

```powershell
Mark "TEST GATE 3"

curl.exe -I http://swpapp-digisign.swp-rest.police.int/
curl.exe -I https://swpapp-digisign.swp-rest.police.int/
```

Required: site listing shows `http/10.129.242.24:80:swpapp-digisign.swp-rest.police.int` and the matching https binding — the real hostname, not `InternalHost`. An SNI certificate binding should appear as `swpapp-digisign.swp-rest.police.int:443`.

A 403 or 404 from curl at this point is fine — it proves the request is reaching the site. A connection failure is not.

---

## Part 4 — Restructure to /feedhub

Matches dev, so existing bookmarks and documentation stay correct.

### 4.1 Site root

The site root becomes a minimal redirect page, so anyone typing the bare hostname still reaches the Hub.

```powershell
Mark "Part 4.1 - site root redirect"

mkdir E:\inetpub\wwwroot\digisign-root -Force

@'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="refresh" content="0; url=/feedhub/" />
<title>SWP ICT Hub</title>
</head>
<body>
<p>Redirecting to the <a href="/feedhub/">SWP ICT Hub</a>&hellip;</p>
</body>
</html>
'@ | Set-Content E:\inetpub\wwwroot\digisign-root\index.html -Encoding UTF8

Get-Content E:\inetpub\wwwroot\digisign-root\index.html
```

A meta-refresh rather than an IIS rewrite rule, because URL Rewrite is not installed on this server and this needs no additional module.

### 4.2 Repoint the site root and add the Hub application

```powershell
Mark "Part 4.2 - hub as an application at /feedhub"

Set-ItemProperty "IIS:\Sites\SWPDigiSign" -Name physicalPath `
  -Value "E:\inetpub\wwwroot\digisign-root"

New-WebApplication -Site "SWPDigiSign" -Name "feedhub" `
  -PhysicalPath "E:\inetpub\wwwroot\icthub" `
  -ApplicationPool "ICTHub"

& "$env:windir\system32\inetsrv\appcmd.exe" list app
& "$env:windir\system32\inetsrv\appcmd.exe" list vdir
```

Expected applications under `SWPDigiSign`: `/` (redirect page), `/feedhub` (ICT Hub), `/signageadmin` (Feed Admin).

The site root and the Hub share the `ICTHub` application pool. Both are static content, so this is fine — the one-application-per-pool rule applies only to in-process ASP.NET Core applications.

### 4.3 Authentication on the new application

Site-level settings from the deployment apply to `/feedhub` by inheritance. Set them explicitly anyway, so the configuration is readable rather than implied.

```powershell
Mark "Part 4.3 - authentication on /feedhub"

Set-WebConfigurationProperty -PSPath "IIS:\" -Location "SWPDigiSign/feedhub" `
  -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value $true

Set-WebConfigurationProperty -PSPath "IIS:\" -Location "SWPDigiSign/feedhub" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value $false
```

The root redirect page inherits the same settings. Authenticating before a redirect is acceptable — every user of this system holds a domain account.

---

## Part 5 — Configuration

Two values return to the dev shape.

### 5.1 On the server

Edit `E:\inetpub\wwwroot\signageadmin\appsettings.json`:

```json
  "Feed": {
    "ChannelLink": "https://swpapp-digisign.swp-rest.police.int/feedhub/",
    ...
  },
  "Hub": {
    "Url": "/feedhub/"
  },
```

```powershell
Mark "Part 5.1 - server config"

Select-String -Path E:\inetpub\wwwroot\signageadmin\appsettings.json `
  -Pattern 'ChannelLink|"Url"|DbPath|KeyRingPath'
```

`DbPath` and `KeyRingPath` must still show the `E:\SignageFeedAdmin\` paths — those do not change.

### 5.2 On the laptop

**Essential.** Without it the next publish reverts the change.

Edit `C:\temp\SignageFeedAdmin_prod\SignageFeedAdmin\appsettings.json` with the same two values.

### 5.3 The Hub's index.html

**No change required.** Its tile links are root-relative (`/signageadmin/...`) and its logo path is relative, so both work wherever the Hub is mounted.

---

## Part 6 — Restart and verify

```powershell
Mark "Part 6 - restart and verify"

Restart-WebAppPool -Name "ICTHub"
Restart-WebAppPool -Name "SignageAdminApp"
Start-Sleep -Seconds 3

Get-ChildItem IIS:\AppPools | Select-Object Name, State
```

### 6.1 Did the application start?

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='IIS AspNetCore Module V2'} -MaxEvents 5 |
  Format-List TimeCreated, Id, Message
```

**"started successfully"** is required. "No events found" means no request has reached the application yet — browse the site first, then re-check.

### 6.2 Did it create its files?

```powershell
Get-ChildItem E:\SignageFeedAdmin\data
Get-ChildItem E:\SignageFeedAdmin\keys
Get-ChildItem E:\inetpub\wwwroot\signageadmin\wwwroot\feeds\rss
```

Expected: `feed.db`, at least one `key-*.xml`, and four XML feed files — valid but empty.

An empty `feeds\rss` means the pool cannot write there; recheck the `icacls` grants.

### 6.3 Browser checks

| Check | Expected |
|---|---|
| `https://swpapp-digisign.swp-rest.police.int/` | Redirects to `/feedhub/` |
| `https://swpapp-digisign.swp-rest.police.int/feedhub/` | Hub renders, logo visible, four tiles |
| Click a tile | Item list, signed in as you, no prompt |
| Add, edit, delete an item | Works; feed republishes |
| Audit log | Shows your changes |
| `← ICT Hub` link | Returns to `/feedhub/` |
| Private window on `http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/datacenter.xml` | Raw XML, **no credential prompt** |

The last is the critical test — the anonymous carve-out the 64 players depend on.

### 6.4 Data Protection

```powershell
Mark "Part 6.4 - data protection"
```

Add an item, then `Restart-WebAppPool -Name "SignageAdminApp"`, then save from the already-open edit page. It must succeed. HTTP 400 means the key ring is not persisting — check `E:\SignageFeedAdmin\keys` and its permissions.

### ✅ Test gate 6 — other sites

```powershell
curl.exe -I http://meetingroomhowto.swp-rest.police.int/
curl.exe -I http://swpapp-digisign.swp-rest.police.int/signage
curl.exe -I http://swpapp-digisign.swp-rest.police.int/

Mark "TEST GATE 6 - <PASSED|FAILED>"
```

---

## Part 7 — Stop the transcript

```powershell
Mark "Remediation session ending"

"--- Final state ---"
& "$env:windir\system32\inetsrv\appcmd.exe" list site
& "$env:windir\system32\inetsrv\appcmd.exe" list app
netsh http show sslcert
Get-ChildItem E:\SignageFeedAdmin\data, E:\SignageFeedAdmin\keys
Get-ChildItem E:\inetpub\wwwroot\signageadmin\wwwroot\feeds\rss

"Outcome: <completed | partially completed | backed out>"
"Notes  : <anything that deviated from this runbook>"
"Ended  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Stop-Transcript
```

```powershell
Get-Item $transcript | Select-Object FullName, Length, LastWriteTime
Select-String -Path $transcript -Pattern '^##########'
```

Attach to the change record and copy off the server — `C:\temp` is not durable.

---

## Back-out

Nothing in this runbook affects the other three sites. Back-out only returns `SWPDigiSign` to its current (non-working) state, which has no value in itself — the realistic position is to fix forward.

If the bindings need removing entirely:

```powershell
Remove-WebBinding -Name "SWPDigiSign" -Protocol http  -Port 80  -HostHeader $siteHost -IPAddress $ip
Remove-WebBinding -Name "SWPDigiSign" -Protocol https -Port 443 -HostHeader $siteHost -IPAddress $ip
netsh http delete sslcert hostnameport="$siteHost`:443"
```

To revert the `/feedhub` restructure and return the Hub to the site root:

```powershell
Remove-WebApplication -Site "SWPDigiSign" -Name "feedhub"
Set-ItemProperty "IIS:\Sites\SWPDigiSign" -Name physicalPath -Value "E:\inetpub\wwwroot\icthub"
```

Then set `Hub:Url` back to `/` and `ChannelLink` to the site root in both copies of `appsettings.json`.

**Do not remove the `0.0.0.0:443` certificate binding.** That is the server-wide HTTPS repair and is unrelated to these faults.

---

## Once complete

Resume the main runbook at **Part 10 — repoint the players**, using:

```
http://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/<unit>.xml
```

One player first, with a distinctive test item, before rolling out to the group.

Then Part 11's post-deployment checklist.

---

## Lessons for the main runbook

Corrected in Deployment Runbook v3.1:

| Issue | Correction |
|---|---|
| `$host` used as a variable name | Renamed `$siteHost`. `$host` is read-only; assignment fails and the variable silently retains the PowerShell host object. |
| Variable assignment failures easy to miss | Echo variables immediately after assignment and check before use. |
| `Mark` called without quotes | Documented — `Mark "Part 2 - text"`, not `Mark Part 2 - text`. |
| Hub placed at the site root | Placed at `/feedhub` to match dev, with a redirect at the root. |
| Hub file source not stated | Identified as the dev server at `C:\inetpub\SWPICTHub\`. |
