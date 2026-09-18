# SWP Signage Feed Admin — Dev Instance Decommissioning

**Server:** `swpdev-ictweb.swp-rest.police.int`
**Version:** 1.0
**Date:** 18 September 2026
**Prepared by:** James Buller, ICT Datacenter Team
**Related:** Production Deployment Runbook v4.0; Technical Documentation (Production)

---

## Purpose

The signage feed system now runs in production on `swpapp-digisign`. This runbook removes the development instance from `swpdev-ictweb`.

## Read this first

**`swpdev-ictweb` is a shared server.** It hosts ten applications belonging to other ICT teams — `quicklinks`, `ucdashboard`, `etsdashboard`, `UserManagement`, `chatbot`, `ADLockoutSD`, `IL3_checks_Dev`, `ud`, `iistest` and `wac`. Nothing in this runbook may disturb them.

Every step is scoped to the signage components. `Default Web Site` is never stopped, and its bindings are never modified.

## Phased approach

This is deliberately split across two sessions with a waiting period between.

| Phase | Action | Reversible |
|---|---|---|
| **Phase 1** | Stop the applications and pools. Archive the data. | Yes — one command |
| *Wait* | Minimum two weeks | — |
| **Phase 2** | Remove applications, pools, configuration and folders | No |

The waiting period exists because decommissioning surprises are rarely immediate. Somebody has a bookmark, a script references a URL, or a player was never repointed. A stopped application produces an obvious error that gets reported; a deleted one produces confusion weeks later with no trail.

## What will be removed

| Item | Detail |
|---|---|
| Applications | `Default Web Site/feedhub`, `Default Web Site/signageadmin` |
| Application pools | `SWPICTHub`, `SignageAdminApp` |
| Legacy sites | `Signagefeedadmin` (port 8081), `SWPICTSignageFeedHub` (port 8082) — already stopped |
| Configuration | The scoped `anonymousAuthentication` unlock at `Default Web Site/signageadmin` |
| Folders | `C:\inetpub\SignageFeedAdmin`, `C:\inetpub\SWPICTHub` |

---

# PHASE 1

## Part 0 — Start the transcript

```powershell
$deployRoot = "C:\temp\SignageDecom"
$stamp      = Get-Date -Format 'yyyyMMdd-HHmm'
mkdir "$deployRoot\transcripts" -Force | Out-Null

$transcript = "$deployRoot\transcripts\dev-decom-phase1-$stamp.log"
Start-Transcript -Path $transcript -IncludeInvocationHeader

"=== SWP Signage Feed Admin - dev decommissioning, phase 1 ==="
"Runbook version : 1.0"
"Server          : $env:COMPUTERNAME"
"Operator        : $env:USERDOMAIN\$env:USERNAME"
"Started         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"============================================================="
```

### Stage marker helper

Quotes around the argument, or only the first word is passed.

```powershell
function Mark([string]$text) {
    ""
    "########## $text  [$(Get-Date -Format 'HH:mm:ss')] ##########"
    ""
}
```

### Shared variables

```powershell
$devRoot  = "C:\inetpub\SignageFeedAdmin"
$hubRoot  = "C:\inetpub\SWPICTHub"
$archive  = "$deployRoot\archive-$stamp"

"devRoot = $devRoot"
"hubRoot = $hubRoot"
"archive = $archive"
```

---

## Part 1 — Record the current state

```powershell
Mark "Part 1 - record current state"

Import-Module WebAdministration

Get-Website | Select-Object Name, State, PhysicalPath, ID
Get-WebApplication
Get-ChildItem IIS:\AppPools | Select-Object Name, State
Get-WebBinding | Select-Object protocol, bindingInformation, ItemXPath

Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Location "Default Web Site/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective
```

This is the "before" record. It also confirms the ten other applications are present and running, which is the baseline every later check compares against.

---

## Part 2 — Confirm nothing is still using dev

**The most important part of this runbook.** Removing a feed that a player is still polling leaves a display showing stale content indefinitely, with no error anywhere.

### 2.1 Has anything fetched a dev feed recently?

```powershell
Mark "Part 2 - confirm nothing still using dev"

# All requests to the feed path across available logs
Get-ChildItem C:\inetpub\logs\LogFiles\W3SVC1\*.log |
  Sort-Object LastWriteTime -Descending | Select-Object -First 14 |
  Get-Content | Select-String 'signageadmin/feeds' |
  Select-Object -Last 40
```

```powershell
# Specifically BrightSign players
Get-ChildItem C:\inetpub\logs\LogFiles\W3SVC1\*.log |
  Sort-Object LastWriteTime -Descending | Select-Object -First 14 |
  Get-Content | Select-String 'BrightSign' |
  Select-Object -Last 40
```

**Any BrightSign user agent in these results means a player is still pointed at dev.** Stop and repoint it before continuing.

### 2.2 Who else has been using the admin pages?

```powershell
Get-ChildItem C:\inetpub\logs\LogFiles\W3SVC1\*.log |
  Sort-Object LastWriteTime -Descending | Select-Object -First 7 |
  Get-Content | Select-String 'signageadmin|feedhub' |
  Select-Object -Last 40
```

Requests from your own account are expected. Anyone else suggests a colleague has bookmarked dev and should be told where production is.

### 2.3 Record the verdict

```powershell
"No BrightSign user agents found in the last 14 days of logs: <yes|no>"
"Other users accessing dev admin pages: <none|list>"

Mark "PART 2 VERDICT - <SAFE TO PROCEED|BLOCKED>"
```

---

## Part 3 — Archive the data

Small files, and the only irreplaceable things here. Keep them until you are certain production has been stable for a reasonable period.

```powershell
Mark "Part 3 - archive"

mkdir $archive -Force | Out-Null

# Database - dev content, but also the schema as it stood
Copy-Item "$devRoot\publish\App_Data\feed.db" "$archive\feed.db" -ErrorAction SilentlyContinue

# Configuration as deployed, including the hand-built web.config
Copy-Item "$devRoot\publish\appsettings.json" "$archive\appsettings.json" -ErrorAction SilentlyContinue
Copy-Item "$devRoot\publish\web.config" "$archive\web.config" -ErrorAction SilentlyContinue

# The Hub page as it was on dev
Copy-Item "$hubRoot\index.html" "$archive\icthub-index.html" -ErrorAction SilentlyContinue

# Data Protection keys - not needed, captured for completeness
Copy-Item "$devRoot\keys\*" $archive -ErrorAction SilentlyContinue

Get-ChildItem $archive | Select-Object Name, Length, LastWriteTime
```

Copy the archive folder off the server. `C:\temp` is not durable.

---

## Part 4 — Stop the applications

Reversible. Nothing is deleted in this phase.

```powershell
Mark "Part 4 - stop application pools"

Stop-WebAppPool -Name "SignageAdminApp"
Stop-WebAppPool -Name "SWPICTHub"
Start-Sleep -Seconds 3

Get-ChildItem IIS:\AppPools | Select-Object Name, State
```

Both should read `Stopped`. Requests to `/signageadmin` and `/feedhub` will now return HTTP 503, which is the visible error that makes any remaining dependency surface.

### ✅ Test gate 4 — other applications unaffected

```powershell
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/quicklinks
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/ucdashboard
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/UserManagement

Get-ChildItem IIS:\AppPools | Select-Object Name, State

Mark "TEST GATE 4 - <PASSED|FAILED>"
```

Required: the three other applications responding normally, and only the two signage pools stopped.

---

## Part 5 — End phase 1

```powershell
Mark "Phase 1 complete"

"--- State at end of phase 1 ---"
Get-WebApplication
Get-ChildItem IIS:\AppPools | Select-Object Name, State

"Archive location : $archive"
"Earliest date for phase 2 : $((Get-Date).AddDays(14).ToString('yyyy-MM-dd'))"
"Outcome: <completed | blocked | backed out>"
"Notes  : <anything that deviated>"
"Ended  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Stop-Transcript
```

### Back-out for phase 1

```powershell
Start-WebAppPool -Name "SignageAdminApp"
Start-WebAppPool -Name "SWPICTHub"
```

Dev is fully working again within seconds.

### During the waiting period

Tell the pilot users and anyone who touched dev that it is now off and production is at `https://swpapp-digisign.swp-rest.police.int/feedhub/`. A stopped instance only surfaces dependencies if somebody notices and says so.

---

# PHASE 2

**Do not start phase 2 until:**

- At least two weeks have passed
- Nobody has reported a problem attributable to the stopped instance
- Production has been stable throughout
- The archive from Part 3 is stored somewhere durable

Everything below is irreversible.

---

## Part 6 — Start the phase 2 transcript

```powershell
$deployRoot = "C:\temp\SignageDecom"
$stamp      = Get-Date -Format 'yyyyMMdd-HHmm'

$transcript = "$deployRoot\transcripts\dev-decom-phase2-$stamp.log"
Start-Transcript -Path $transcript -IncludeInvocationHeader

"=== SWP Signage Feed Admin - dev decommissioning, phase 2 ==="
"Server    : $env:COMPUTERNAME"
"Operator  : $env:USERDOMAIN\$env:USERNAME"
"Started   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"============================================================="

function Mark([string]$text) {
    ""
    "########## $text  [$(Get-Date -Format 'HH:mm:ss')] ##########"
    ""
}

$devRoot = "C:\inetpub\SignageFeedAdmin"
$hubRoot = "C:\inetpub\SWPICTHub"

"devRoot = $devRoot"
"hubRoot = $hubRoot"
```

### Confirm the archive still exists

```powershell
Mark "Part 6 - confirm archive"
Get-ChildItem "$deployRoot\archive-*" -Recurse -File | Select-Object FullName, Length
```

If nothing is returned, stop and re-run Phase 1 Part 3 before continuing.

---

## Part 7 — Remove the scoped configuration

Do this **before** removing the applications. The unlock is scoped to an application path; removing the application first leaves an orphaned configuration entry behind.

```powershell
Mark "Part 7 - remove scoped anonymous unlock"

Import-Module WebAdministration

# Current state, for the record
Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Location "Default Web Site/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

# Return to the inherited default
Set-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Location "Default Web Site/signageadmin" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
  -Metadata overrideMode -Value Inherit

# Confirm the global lock is untouched and still Deny
Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective
```

The global setting must remain `Deny`. If it reads anything else, stop — that is a separate finding for the server owner and not something to change here.

---

## Part 8 — Remove the applications and pools

```powershell
Mark "Part 8 - remove applications and pools"

Remove-WebApplication -Site "Default Web Site" -Name "signageadmin"
Remove-WebApplication -Site "Default Web Site" -Name "feedhub"

Remove-WebAppPool -Name "SignageAdminApp"
Remove-WebAppPool -Name "SWPICTHub"

Get-WebApplication
Get-ChildItem IIS:\AppPools | Select-Object Name, State
```

The remaining applications and pools should be the other teams', untouched.

### ✅ Test gate 8

```powershell
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/quicklinks
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/ucdashboard
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/UserManagement
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/

Mark "TEST GATE 8 - <PASSED|FAILED>"
```

Required: all four responding normally.

---

## Part 9 — Remove the legacy per-port sites

`Signagefeedadmin` (port 8081) and `SWPICTSignageFeedHub` (port 8082) were stopped when the applications moved under `Default Web Site`. They have been inactive since.

```powershell
Mark "Part 9 - remove legacy sites"

# Confirm they are still stopped and nothing has restarted them
Get-Website | Where-Object { $_.Name -match 'Signagefeedadmin|SWPICTSignageFeedHub' } |
  Select-Object Name, State, PhysicalPath, ID

Remove-Website -Name "Signagefeedadmin"
Remove-Website -Name "SWPICTSignageFeedHub"

# Their pools, if they still exist
Remove-WebAppPool -Name "SignageFeedAdmin" -ErrorAction SilentlyContinue
Remove-WebAppPool -Name "SWPICTSignageFeedHub" -ErrorAction SilentlyContinue

Get-Website | Select-Object Name, State, ID
```

Note the pool named `SignageFeedAdmin` is the original one from the per-port deployment, distinct from `SignageAdminApp` removed in Part 8. Both are ours.

---

## Part 10 — Remove the folders

```powershell
Mark "Part 10 - remove folders"

# Final look at what is about to be deleted
Get-ChildItem $devRoot -Recurse -File | Measure-Object -Property Length -Sum |
  Select-Object Count, @{n='MB';e={[math]::Round($_.Sum/1MB,1)}}
Get-ChildItem $hubRoot -Recurse -File | Measure-Object -Property Length -Sum |
  Select-Object Count, @{n='MB';e={[math]::Round($_.Sum/1MB,1)}}
```

Pause here. Confirm the archive is stored off the server before running the next block.

```powershell
Remove-Item $devRoot -Recurse -Force
Remove-Item $hubRoot -Recurse -Force

Test-Path $devRoot
Test-Path $hubRoot
```

Both must return `False`.

---

## Part 11 — Final verification

```powershell
Mark "Part 11 - final verification"

Get-Website | Select-Object Name, State, PhysicalPath, ID
Get-WebApplication
Get-ChildItem IIS:\AppPools | Select-Object Name, State

Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" `
  -Filter "/system.webServer/security/authentication/anonymousAuthentication" |
  Select-Object OverrideMode, OverrideModeEffective

curl.exe -I http://swpdev-ictweb.swp-rest.police.int/quicklinks
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/ucdashboard
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/etsdashboard
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/UserManagement
curl.exe -I http://swpdev-ictweb.swp-rest.police.int/chatbot

Mark "TEST GATE 11 - <PASSED|FAILED>"
```

Required:

- No signage sites, applications, pools or folders remain
- The global `anonymousAuthentication` lock still reads `Deny`
- All other teams' applications responding normally

---

## Part 12 — Stop the transcript

```powershell
Mark "Phase 2 complete - dev instance decommissioned"

"Outcome: <completed | partially completed>"
"Notes  : <anything that deviated>"
"Ended  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Stop-Transcript

Get-Item $transcript | Select-Object FullName, Length
Select-String -Path $transcript -Pattern '^##########'
```

Replace the `<PASSED|FAILED>` placeholders with actual verdicts before filing.

---

## After decommissioning

- [ ] Update the Technical Documentation to remove dev references
- [ ] Update the High Level Design if it references the dev environment
- [ ] Remove dev URLs from any team bookmarks or documentation
- [ ] Confirm the archive is held somewhere durable
- [ ] Note in the change record that the dev instance has been removed
- [ ] Consider whether `appsettings.Development.json` still needs to exist in source — with no dev instance it has no consumer

---

## Back-out

**Phase 1** is fully reversible by starting the two application pools.

**Phase 2 is not reversible.** Rebuilding dev would mean following the Production Deployment Runbook against `swpdev-ictweb`, using the archived database and configuration from Part 3. That is a rebuild, not a restore, and it is the reason for the two-week gap and the archive.

---

## Note for the record

This work is confined to signage components. No other team's application, pool, site, binding or configuration is modified. The global `anonymousAuthentication` lock is left at its correct default of `Deny`, and `Default Web Site` is never stopped or altered.
