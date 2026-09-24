# SWPDEV-ICTWEB — Site Shutdown, QuickLinks Redirect and Scheduled Decommission

**Runbook version:** 1.1 (supersedes 1.0)
**Target server:** `SWPDEV-ICTWEB` (Windows Server 2016, 10.0.14393, PowerShell 5.1)
**Prepared:** 24 September 2026
**Change reference:** _&lt;fill in before resuming&gt;_

---

## What changed since v1.0

The Part 1 survey ran at 13:35 on 24 September and returned findings that alter the plan. This version is rewritten around them. **Do not work from v1.0.**

| # | Finding | Effect |
|---|---|---|
| 1 | QuickLinks is an **application**, not a site | Branch B. `Default Web Site` must stay **Started** |
| 2 | The only two other sites are **already Stopped** | "Turn them all off" means stopping sibling *application pools* |
| 3 | Three applications share `DefaultAppPool` | Stopping it takes `/`, `/wac` and `/ADLockoutsSD/ADLockout` together — needs a decision |
| 4 | `uctools` returned **401**, not 200 | Not a pass. Retest authenticated before relying on it |
| 5 | Host is **PowerShell 5.1** | Redirect test rewritten; `-SkipHttpErrorCheck` is unavailable |
| 6 | Redirect at application scope writes to the app's **web.config** | v1.0's backup would not have covered rollback. Now committed to `applicationHost.config` instead |

Already completed on 24 Sep and **not to be repeated**:

- Part 0 — transcript, server guard, elevation check ✓
- Part 1 — survey ✓
- `Install-WindowsFeature Web-Http-Redirect` ✓ (was `Available`, now `Installed`, no restart needed)

> That feature install landed *before* the Part 2 backup. Harmless — the backup you take now includes the redirect module, so a restore will not remove it. A module present with redirect disabled does nothing.

---

## Confirmed state of SWPDEV-ICTWEB

### Sites

| Site | Id | State | Bindings | Action |
|---|---|---|---|---|
| `Default Web Site` | 1 | **Started** | `http/*:80:`, `https/*:443:` | **Leave started** — carries QuickLinks |
| `Signagefeedadmin` | 2 | Stopped | `http/*:8081:` | Already down, nothing to do |
| `SWPICTSignageFeedHub` | 3 | Stopped | `http/*:8082:` | Already down, nothing to do |

**Only one site is active.** That is the answer to "list what websites are active in IIS" for the change record.

### Applications under Default Web Site

| Application | App pool | Disposition |
|---|---|---|
| `/` | `DefaultAppPool` | ⚠ shared — see decision below |
| `/ud` | `ud` | Stop pool |
| **`/quicklinks`** | **`quicklinks`** | **KEEP RUNNING + redirect** |
| `/ucdashboard` | `ucdashboard` | Stop pool |
| `/etsdashboard` | `etsdashboard` | Stop pool |
| `/UserManagement` | `UserManagement` | Stop pool |
| `/chatbot` | `chatbot` | Stop pool |
| `/iistest` | `iistest` | Stop pool |
| `/wac` | `DefaultAppPool` | ⚠ shared |
| `/ADLockoutsSD/ADLockout` | `DefaultAppPool` | ⚠ shared |
| `/IL3_checks_Dev` | `IL3_Checks_Dev` | Stop pool |
| `/feedhub` | `SWPICTHub` | Pool already Stopped |
| `/signageadmin` | `SignageAdminApp` | Pool already Stopped |

### ⚠ Decision required before Part 4 — DefaultAppPool

`DefaultAppPool` serves three applications at once. There is no way to stop one without stopping all three.

- **`/`** — the site root. Stopping it means `http://swpdev-ictweb/` returns **HTTP 503**, not a friendly page.
- **`/wac`** — name suggests Windows Admin Center. If anyone administers servers through this, it stops.
- **`/ADLockoutsSD/ADLockout`** — an AD lockout tool. If the service desk uses this, it stops.

The last two do not read like dev-only workloads despite living on a dev box. **Confirm ownership of `/wac` and `/ADLockoutsSD/ADLockout` before choosing.**

| Option | Effect | Use when |
|---|---|---|
| **A — Stop DefaultAppPool** | Root, `/wac` and `/ADLockout` all return 503. Cleanest decommission posture | Nobody depends on those three |
| **B — Leave DefaultAppPool running** | Those three keep working. Only the seven named pools stop | `/wac` or `/ADLockout` still has users |

Option B is the safer default for the two-week window; DefaultAppPool can be stopped later once ownership is settled. **Whichever you pick, record it in the transcript.**

### Environment facts already proven

- **No redirect loop.** `uctools.swp-rest.police.int` → `10.20.243.195`. This server is `10.20.253.127`. Different hosts.
- **The short-name certificate is valid.** The HTTPS request to `https://uctools/` completed its TLS handshake and returned an application-layer 401. That means the certificate presented for the short name `uctools` validated from this server — an unflagged risk in v1.0 that is now closed.

---

## Part 0R — Resume the transcript

The original session ended at 13:39:09. **Append to the same file** rather than starting a second one.

```powershell
$workRoot   = "C:\temp\ICTWebDecomm"
$stamp      = '20260924-1335'          # the ORIGINAL stamp - do not regenerate
$transcript = "$workRoot\transcripts\ictweb-decomm-$stamp.log"

Start-Transcript -Path $transcript -Append -IncludeInvocationHeader

"=== Resumed $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - runbook v1.1, at Part 1R ==="
"Change ref : <fill in>"
"Operator   : $env:USERDOMAIN\$env:USERNAME"
"NOTE: Part 0 and Part 1 completed in the first session. Web-Http-Redirect already installed."
```

### Re-define everything — none of it survived the session

```powershell
function Mark([string]$text) {
    ""
    "########## $text  [$(Get-Date -Format 'HH:mm:ss')] ##########"
    ""
}

$appcmd     = "$env:windir\system32\inetsrv\appcmd.exe"
$redirectTo = 'https://uctools/quicklinks/'
$qlApp      = 'Default Web Site/quicklinks'
```

### Redirect test helper

`Invoke-WebRequest -MaximumRedirection 0` behaves inconsistently on PowerShell 5.1 — sometimes it returns the 302, sometimes it throws. This helper goes straight to `HttpWebRequest` so the result is deterministic, and sends your credentials so Windows-auth sites answer properly.

```powershell
function Test-Redirect([string]$Url) {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.AllowAutoRedirect     = $false
    $req.UseDefaultCredentials = $true
    $req.Timeout               = 15000
    $resp = $null
    try   { $resp = $req.GetResponse() }
    catch [System.Net.WebException] { $resp = $_.Exception.Response }
    if ($resp) {
        [pscustomobject]@{
            Url      = $Url
            Status   = [int]$resp.StatusCode
            Location = $resp.Headers['Location']
        }
        $resp.Close()
    } else {
        [pscustomobject]@{ Url = $Url; Status = 'no response'; Location = $null }
    }
}
```

### Re-assert the server guard

```powershell
Mark "Part 0R - resume guard"
if ($env:COMPUTERNAME -ne 'SWPDEV-ICTWEB') { throw "WRONG SERVER: $env:COMPUTERNAME" }
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Not elevated." }
"Guards passed - $env:COMPUTERNAME, $env:USERNAME"
```

---

## Part 1R — Close the two open questions

### 1R.a — Does `/quicklinks/` actually exist on uctools?

The 401 from the first session proves only that a web server answered. IIS with Windows Authentication returns 401 **before** it resolves the path, so a 401 is equally what you would get for a URL that does not exist there.

```powershell
Mark "Part 1R - uctools authenticated check"

try {
    $r = Invoke-WebRequest -Uri 'https://uctools/quicklinks/' `
            -UseBasicParsing -UseDefaultCredentials -TimeoutSec 15 -ErrorAction Stop
    "uctools/quicklinks/ returned HTTP $($r.StatusCode), $($r.RawContentLength) bytes"
    "Title: $(([regex]::Match($r.Content,'(?is)<title>(.*?)</title>')).Groups[1].Value.Trim())"
} catch {
    "FAILED: $($_.Exception.Message)"
    if ($_.Exception.Response) { "Status: $([int]$_.Exception.Response.StatusCode)" }
}
```

**Expected: HTTP 200 and a page title that looks like QuickLinks.**

A 401 even with credentials means your account is not permitted there — plausible, but then it is not proven for anyone. A 404 means the path is wrong and the redirect target must change.

> **If this does not return 200, stop.** Get someone who uses QuickLinks daily to open `https://uctools/quicklinks/` in a browser and confirm it is the real thing. Redirecting users to a URL that 404s is worse than leaving the old site up.

### 1R.b — Where does QuickLinks live, and does it already have a web.config?

```powershell
Mark "Part 1R - quicklinks application detail"

Import-Module WebAdministration
Get-WebApplication -Site 'Default Web Site' -Name 'quicklinks' |
    Select-Object Path, PhysicalPath, ApplicationPool, EnabledProtocols | Format-List

$qlPhysical = (Get-WebApplication -Site 'Default Web Site' -Name 'quicklinks').PhysicalPath
$qlPhysical = [Environment]::ExpandEnvironmentVariables($qlPhysical)
"Physical path : $qlPhysical"
"Path exists   : $(Test-Path $qlPhysical)"

$qlWebConfig = Join-Path $qlPhysical 'web.config'
"web.config    : $(Test-Path $qlWebConfig)"
if (Test-Path $qlWebConfig) {
    "--- existing web.config ---"
    Get-Content $qlWebConfig -Raw
}
```

Read the output. If that `web.config` already contains a `<httpRedirect>` element, it will **override** anything set at `applicationHost.config` scope, and Part 3 will appear to succeed while changing nothing. If one is there, say so before continuing — the approach changes.

---

### ▣ TEST GATE 1R

```powershell
Mark "TEST GATE 1R - findings"

"uctools/quicklinks/ authenticated status : <200 | other>"
"QuickLinks physical path                 : <path>"
"Existing web.config has httpRedirect     : <yes | no | no web.config>"
"DefaultAppPool decision                  : <Option A stop | Option B leave running>"
"Owner confirmed for /wac                 : <name | not needed, Option B>"
"Owner confirmed for /ADLockoutsSD        : <name | not needed, Option B>"
"TEST GATE 1R - PASSED"
```

---

## Part 2 — Back up before touching anything

```powershell
Mark "Part 2 - backup"

mkdir "$workRoot\backup" -Force | Out-Null
mkdir "$workRoot\state"  -Force | Out-Null

# IIS global configuration
Copy-Item "$env:windir\system32\inetsrv\config\applicationHost.config" `
          "$workRoot\backup\applicationHost.config.$stamp.bak" -Force

# The QuickLinks app's own web.config, if it has one
if (Test-Path $qlWebConfig) {
    Copy-Item $qlWebConfig "$workRoot\backup\quicklinks-web.config.$stamp.bak" -Force
}

# Native IIS backup set
& $appcmd add backup "predecomm-$stamp"

# Machine-readable pre-change state
Get-Website | Select-Object Name, Id, State, PhysicalPath, applicationPool, serverAutoStart |
    Export-Csv "$workRoot\state\sites-before-$stamp.csv" -NoTypeInformation

Get-ChildItem IIS:\AppPools | ForEach-Object {
    [pscustomobject]@{
        Name  = $_.Name
        State = (Get-WebAppPoolState -Name $_.Name -ErrorAction SilentlyContinue).Value
    }
} | Export-Csv "$workRoot\state\apppools-before-$stamp.csv" -NoTypeInformation

Get-WebApplication | Select-Object Path, PhysicalPath, ApplicationPool |
    Export-Csv "$workRoot\state\apps-before-$stamp.csv" -NoTypeInformation

"--- Backup contents ---"
Get-ChildItem "$workRoot\backup", "$workRoot\state"
& $appcmd list backup
```

The `WebAdministration` provider returned results normally in the first session, so the CSVs will populate. Use them for rollback.

---

### ▣ TEST GATE 2

```powershell
Mark "TEST GATE 2 - backup verified"
$bk = "$workRoot\backup\applicationHost.config.$stamp.bak"
"Exists : $(Test-Path $bk)"                    # must be True
"Bytes  : $((Get-Item $bk).Length)"            # must be > 0
Import-Csv "$workRoot\state\apppools-before-$stamp.csv" | Measure-Object | Select-Object Count
"TEST GATE 2 - PASSED"
```

---

## Part 3 — Apply the QuickLinks redirect

### Scope — this is the correction from v1.0

`httpRedirect` is a **delegated** section. Running `Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\quicklinks"` writes into the application's own `web.config` **on disk**, not `applicationHost.config`. v1.0 backed up only `applicationHost.config`, so restoring it would not have removed the redirect.

v1.1 commits to `applicationHost.config` instead, using a `Location` path. Rollback is then covered by the backup you just took, and no file inside the application is modified.

### Redirect type

`Found` (302) is **not cached**. `Permanent` (301) **is cached by browsers, often indefinitely**, and cannot be reliably undone — users who hit a 301 may keep redirecting even after rollback.

Use `Found` for the two-week window. Switch to `Permanent` only once the decommission is committed and you have decided not to roll back.

```powershell
Mark "Part 3 - QuickLinks redirect"

$apphost = 'MACHINE/WEBROOT/APPHOST'
$filter  = '/system.webServer/httpRedirect'
$status  = 'Found'          # 'Found' = 302 | 'Permanent' = 301

Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name enabled            -Value $true
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name destination        -Value $redirectTo
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name exactDestination   -Value $true
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name childOnly          -Value $false
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name httpResponseStatus -Value $status

"--- Redirect configuration now reads ---"
Get-WebConfiguration -PSPath $apphost -Location $qlApp -Filter $filter |
    Select-Object enabled, destination, exactDestination, childOnly, httpResponseStatus

"--- Confirm nothing was written into the application folder ---"
if (Test-Path $qlWebConfig) {
    "web.config last modified: $((Get-Item $qlWebConfig).LastWriteTime)"
} else {
    "No web.config in the application folder - correct, nothing was created"
}
```

`exactDestination = $true` sends every request under `/quicklinks` to that one URL. To preserve sub-path and query string instead — so `/quicklinks/reports?x=1` lands on `https://uctools/quicklinks/reports?x=1`:

```powershell
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name exactDestination -Value $false
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name destination      -Value 'https://uctools/quicklinks$S$Q'
```

### appcmd equivalent

```powershell
& $appcmd set config "Default Web Site/quicklinks" /section:httpRedirect `
    /enabled:true `
    /destination:"https://uctools/quicklinks/" `
    /exactDestination:true `
    /childOnly:false `
    /httpResponseStatus:Found `
    /commit:apphost
```

> The `quicklinks` application pool must stay **Started**. HTTP Redirect is a native module but still runs inside the worker process — stop that pool and the redirect returns 503 instead of 302.

---

### ▣ TEST GATE 3 — prove the redirect works

The site has both an HTTP and an HTTPS binding, so test both.

```powershell
Mark "TEST GATE 3 - redirect verification"

Test-Redirect 'http://swpdev-ictweb/quicklinks/'
Test-Redirect 'https://swpdev-ictweb/quicklinks/'
Test-Redirect 'http://swpdev-ictweb/quicklinks'      # no trailing slash
```

Expected on every line: `Status` **302**, `Location` **https://uctools/quicklinks/**.

If HTTPS fails on a certificate error, that is a pre-existing condition of this server's own 443 binding and does not block the change — note it and carry on, provided the HTTP test passes.

**Then test from a client machine, in a browser, as a normal user.** Confirm you land on a working QuickLinks page, not a 404 or a login loop.

```powershell
Mark "TEST GATE 3 - PASSED"
```

---

## Part 4 — Stop everything except QuickLinks

Nothing here touches the `Default Web Site` site object — it stays **Started** throughout, because QuickLinks lives inside it.

```powershell
Mark "Part 4 - stop sibling application pools"

# Seven pools, one per sibling application. quicklinks is deliberately absent.
$poolsToStop = @(
    'ud'
    'ucdashboard'
    'etsdashboard'
    'UserManagement'
    'chatbot'
    'iistest'
    'IL3_Checks_Dev'
)

# Pools whose SITES are already stopped - stopping these is tidying, not a change in service
$poolsIdle = @(
    'Signagefeedadmin'
    'SWPICTSignageFeedHub'
)

"Will STOP          : $($poolsToStop -join ', ')"
"Will STOP (idle)   : $($poolsIdle -join ', ')"
"Will KEEP RUNNING  : quicklinks"
"DefaultAppPool     : <Option A - stopping | Option B - leaving running>"
```

### Dry run — changes nothing

```powershell
foreach ($p in ($poolsToStop + $poolsIdle)) {
    $state = (Get-WebAppPoolState -Name $p -ErrorAction SilentlyContinue).Value
    "{0,-26} currentState={1}" -f $p, $state
}
```

Every line should read `Started`. A pool that reports blank does not exist under that name — fix the list before continuing.

### Stop them

```powershell
foreach ($p in ($poolsToStop + $poolsIdle)) {
    if ($p -eq 'quicklinks') { "REFUSING to stop quicklinks"; continue }
    "Stopping pool $p ..."
    Stop-WebAppPool -Name $p -ErrorAction Continue
}
Start-Sleep -Seconds 3
```

### Option A only — stop DefaultAppPool

Skip this block entirely if you chose Option B.

```powershell
Mark "Part 4 - Option A - stopping DefaultAppPool"
"This stops: / (site root), /wac, /ADLockoutsSD/ADLockout"
Stop-WebAppPool -Name 'DefaultAppPool' -ErrorAction Continue
Start-Sleep -Seconds 2
```

### Stop pools surviving a restart

`Stop-WebAppPool` does not persist across a service restart the way `Stop-Website` does. Set `autoStart` to false so they stay down.

```powershell
foreach ($p in ($poolsToStop + $poolsIdle)) {
    Set-ItemProperty "IIS:\AppPools\$p" -Name autoStart -Value $false
}
# Option A only:
# Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name autoStart -Value $false

"--- Final pool states ---"
Get-ChildItem IIS:\AppPools | ForEach-Object {
    "{0,-26} {1,-9} autoStart={2}" -f `
        $_.Name, (Get-WebAppPoolState -Name $_.Name).Value, $_.autoStart
}
```

---

### ▣ TEST GATE 4 — QuickLinks still redirects, everything else is down

```powershell
Mark "TEST GATE 4 - post-stop verification"

"--- Site states (Default Web Site MUST still be Started) ---"
Get-Website | Select-Object Name, State | Format-Table -AutoSize

"--- Pool states ---"
Get-ChildItem IIS:\AppPools | ForEach-Object {
    "{0,-26} {1}" -f $_.Name, (Get-WebAppPoolState -Name $_.Name).Value
}

"--- QuickLinks still redirects ---"
Test-Redirect 'http://swpdev-ictweb/quicklinks/'

"--- A stopped sibling should now return 503 ---"
Test-Redirect 'http://swpdev-ictweb/ucdashboard/'
```

Expected:

- `Default Web Site` → **Started**
- `quicklinks` pool → **Started**
- the seven named pools → **Stopped**
- `/quicklinks/` → **302** to uctools
- `/ucdashboard/` → **503**

```powershell
Mark "TEST GATE 4 - PASSED"
```

**Phase 1 is complete.** Leave it here for a day or two before Phase 2, so anyone who depended on a stopped application has a chance to notice and speak up. That pause is worth more on this box than it would be on ICTWEB1/2/3 — ten applications just stopped, and at least two of them do not read as dev-only.

---

## Part 5 — Phase 2: schedule the shutdown

Two weeks out is **Wednesday 8 October 2026**. Midweek and mid-evening means someone is around the next morning if it causes surprises. Adjust to your change window.

```powershell
Mark "Part 5 - schedule decommission shutdown"

$shutdownAt = Get-Date '2026-10-08 20:00:00'
$taskName   = 'Decommission - Scheduled Shutdown'
$taskPath   = '\SWP-Decomm\'
$changeRef  = '<CHG reference>'

"Shutdown scheduled for: $($shutdownAt.ToString('dddd dd MMMM yyyy HH:mm'))"
"That is $([math]::Round(($shutdownAt - (Get-Date)).TotalDays,1)) days from now"
```

```powershell
$action = New-ScheduledTaskAction -Execute 'shutdown.exe' `
    -Argument "/s /t 300 /c `"Planned decommissioning shutdown - $changeRef`" /d p:2:4"

$trigger = New-ScheduledTaskTrigger -Once -At $shutdownAt

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "Powers off $env:COMPUTERNAME as part of planned decommissioning. Raised under $changeRef. Remove this task if the decommission is cancelled."
```

Notes on the arguments:

- `/s` powers the machine **off**; it does not restart it
- `/t 300` gives a five-minute warning, so anyone logged on sees a notice and the event log records intent before the power goes
- `/d p:2:4` stamps it as **planned, operating system, reconfiguration** in the event log — this is what makes it obvious afterwards that the outage was deliberate
- `-StartWhenAvailable` fires the task at the next opportunity if the server happens to be off at 20:00 on the 8th, rather than skipping it

### Optional — a warning notice 24 hours ahead

```powershell
$warnAt = $shutdownAt.AddDays(-1)
$warnAction = New-ScheduledTaskAction -Execute 'msg.exe' `
    -Argument "* /TIME:3600 This server is scheduled for permanent shutdown at $($shutdownAt.ToString('HH:mm on dd MMM yyyy')). Contact ICT Datacenter if this is unexpected."

Register-ScheduledTask -TaskName 'Decommission - 24h Warning' -TaskPath $taskPath `
    -Action $warnAction -Trigger (New-ScheduledTaskTrigger -Once -At $warnAt) `
    -Principal $principal -Settings $settings `
    -Description "Advance notice before scheduled decommissioning shutdown. $changeRef"
```

---

### ▣ TEST GATE 5 — the task is registered and will actually fire

```powershell
Mark "TEST GATE 5 - scheduled task verification"

Get-ScheduledTask -TaskPath $taskPath | Select-Object TaskName, State | Format-Table -AutoSize

$t = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
$i = $t | Get-ScheduledTaskInfo

"Task     : $($t.TaskName)"
"State    : $($t.State)"                 # must be Ready, not Disabled
"Runs as  : $($t.Principal.UserId)"
"Next run : $($i.NextRunTime)"           # must be 08/10/2026 20:00
"Action   : $($t.Actions.Execute) $($t.Actions.Arguments)"
```

A `NextRunTime` that is blank or in the past means the trigger did not take.

```powershell
Mark "TEST GATE 5 - PASSED"
```

> **Do not test this task by running it.** `Start-ScheduledTask` on this one powers the server off.

---

## Part 6 — Tell the platform, not just the server

The scheduled task powers the guest off. It does not stop anything else powering it back on.

- [ ] Virtualisation team notified — VM must not auto-start; HA/DRS restart policy checked
- [ ] Monitoring suppressed, or the host removed from the monitored set, so the planned outage does not page anyone
- [ ] Backup schedule reviewed — decide whether the final backup is retained, and for how long
- [ ] Owners of `/wac` and `/ADLockoutsSD/ADLockout` informed, whichever option you chose
- [ ] Change record updated with the shutdown date, the active-sites list above, and the transcript attached

---

## Part 7 — Stop the transcript

```powershell
Mark "Session ending"

"--- Final state ---"
& $appcmd list site
& $appcmd list app
& $appcmd list apppool
Get-ScheduledTask -TaskPath '\SWP-Decomm\' -ErrorAction SilentlyContinue |
    Select-Object TaskName, State
Get-ScheduledTask -TaskName 'Decommission - Scheduled Shutdown' -TaskPath '\SWP-Decomm\' -ErrorAction SilentlyContinue |
    Get-ScheduledTaskInfo | Select-Object NextRunTime
Test-Redirect 'http://swpdev-ictweb/quicklinks/'

"Phase 1 outcome    : <completed | partially completed | backed out>"
"Phase 2 outcome    : <completed | not attempted>"
"DefaultAppPool     : <Option A stopped | Option B left running>"
"Shutdown set for   : <date/time, or n/a>"
"Notes              : <anything that deviated from the runbook>"
"Ended              : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Stop-Transcript
```

Fill in the outcome lines **before** running `Stop-Transcript` — they are the first thing anyone reads. File the transcript with the change record.

---

## Part 8 — Rollback

### Cancel the shutdown (do this first if anything is wrong)

```powershell
Unregister-ScheduledTask -TaskName 'Decommission - Scheduled Shutdown' -TaskPath '\SWP-Decomm\' -Confirm:$false
Unregister-ScheduledTask -TaskName 'Decommission - 24h Warning'        -TaskPath '\SWP-Decomm\' -Confirm:$false -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskPath '\SWP-Decomm\' -ErrorAction SilentlyContinue
```

If the shutdown has already fired, power the VM back on from vCenter — nothing was deleted.

### Remove the redirect

```powershell
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/quicklinks' `
    -Filter '/system.webServer/httpRedirect' -Name enabled -Value $false

Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/quicklinks' `
    -Filter '/system.webServer/httpRedirect' | Select-Object enabled, destination

Test-Redirect 'http://swpdev-ictweb/quicklinks/'    # should no longer be 302
```

If you switched to `Permanent` (301), browsers that already hit it keep redirecting until their cache clears. Affected users must clear their browser cache. This is why Part 3 defaults to 302.

### Restart the stopped pools

```powershell
Import-Csv "$workRoot\state\apppools-before-$stamp.csv" |
    Where-Object { $_.State -eq 'Started' } |
    ForEach-Object {
        "Starting pool $($_.Name) ..."
        Set-ItemProperty "IIS:\AppPools\$($_.Name)" -Name autoStart -Value $true
        Start-WebAppPool -Name $_.Name -ErrorAction Continue
    }

Start-Sleep -Seconds 3
Get-ChildItem IIS:\AppPools | ForEach-Object {
    "{0,-26} {1}" -f $_.Name, (Get-WebAppPoolState -Name $_.Name).Value
}

Test-Redirect 'http://swpdev-ictweb/ucdashboard/'   # should no longer be 503
```

The CSV captures the state as it was before Part 4, so `SWPICTHub` and `SignageAdminApp` correctly stay stopped — they were already stopped when it was taken.

### Full configuration restore (last resort)

```powershell
& $appcmd list backup
& $appcmd restore backup "predecomm-20260924-1335"
iisreset
```

Or manually — stop IIS first:

```powershell
iisreset /stop
Copy-Item "$workRoot\backup\applicationHost.config.$stamp.bak" `
          "$env:windir\system32\inetsrv\config\applicationHost.config" -Force
iisreset /start
```

---

## Quick reference

| Item | Value |
|---|---|
| Server | `SWPDEV-ICTWEB` (10.20.253.127) |
| PowerShell | 5.1.14393 — `-SkipHttpErrorCheck` unavailable |
| Working folder | `C:\temp\ICTWebDecomm` |
| Transcript | `C:\temp\ICTWebDecomm\transcripts\ictweb-decomm-20260924-1335.log` (append) |
| IIS backup name | `predecomm-20260924-1335` |
| Active sites | `Default Web Site` only — other two already stopped |
| QuickLinks | Application `Default Web Site/quicklinks`, pool `quicklinks` |
| Redirect target | `https://uctools/quicklinks/` (10.20.243.195) |
| Redirect scope | `applicationHost.config`, Location `Default Web Site/quicklinks` |
| Redirect type | 302 Found (switch to 301 only after confirmation) |
| Pools to stop | ud, ucdashboard, etsdashboard, UserManagement, chatbot, iistest, IL3_Checks_Dev |
| Pools to leave | **quicklinks** (required for the redirect) |
| Shared pool ⚠ | DefaultAppPool serves `/`, `/wac`, `/ADLockoutsSD/ADLockout` |
| Shutdown task | `\SWP-Decomm\Decommission - Scheduled Shutdown` |
| Shutdown time | Wednesday 8 October 2026, 20:00 |
| Cancel shutdown | `Unregister-ScheduledTask -TaskName 'Decommission - Scheduled Shutdown' -TaskPath '\SWP-Decomm\' -Confirm:$false` |
