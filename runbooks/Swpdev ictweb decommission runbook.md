# SWPDEV-ICTWEB — Site Shutdown, QuickLinks Redirect and Scheduled Decommission

**Runbook version:** 1.0
**Target server:** `SWPDEV-ICTWEB`
**Prepared:** 24 September 2026
**Change reference:** _&lt;fill in before starting&gt;_

---

## Purpose

| Phase | Outcome |
|---|---|
| **Phase 1** | Survey all IIS sites, stop everything except QuickLinks, and redirect QuickLinks to `https://uctools/quicklinks/` |
| **Phase 2** | Register a scheduled task to power the server off in two weeks |

All commands are PowerShell, run **elevated**, on the target server unless stated otherwise.

### Before you start

- [ ] Change record raised and approved
- [ ] You know who owns each site you are about to stop, or have accepted the risk in the change
- [ ] `https://uctools/quicklinks/` has been confirmed working by someone other than you
- [ ] You have a console / vCenter route to the server, not just RDP — Phase 2 powers it off
- [ ] The virtualisation team know the VM will go down and should **not** auto-restart it

### What this runbook does NOT do

It does not delete sites, remove application pools, uninstall software, or remove DNS records. Everything here is reversible until the shutdown task fires. Rollback is in Part 8.

---

## Part 0 — Start the transcript

Run this first, in the same elevated session you will use for the whole change.

```powershell
$workRoot = "C:\temp\ICTWebDecomm"
$stamp    = Get-Date -Format 'yyyyMMdd-HHmm'
mkdir "$workRoot\transcripts" -Force | Out-Null
mkdir "$workRoot\backup"      -Force | Out-Null
mkdir "$workRoot\state"       -Force | Out-Null

$transcript = "$workRoot\transcripts\ictweb-decomm-$stamp.log"
Start-Transcript -Path $transcript -IncludeInvocationHeader

"=== SWPDEV-ICTWEB - site shutdown and scheduled decommission ==="
"Runbook version : 1.0"
"Change ref      : <fill in>"
"Server          : $env:COMPUTERNAME"
"Operator        : $env:USERDOMAIN\$env:USERNAME"
"Started         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"Transcript      : $transcript"
"==============================================================="
```

Keep this session open for the whole change. `$workRoot`, `$stamp` and `$transcript` are referenced later.

### Stage marker helper

Define this now so the transcript has searchable headings.

**Note the quotes** — `Mark "Part 1 - survey"`, not `Mark Part 1 - survey`. Without them PowerShell passes only the first word.

```powershell
function Mark([string]$text) {
    ""
    "########## $text  [$(Get-Date -Format 'HH:mm:ss')] ##########"
    ""
}
```

### Server guard

Running Phase 1 on the wrong server would stop production sites. Run this and stop if it objects.

```powershell
Mark "Part 0 - server guard"

$expected = 'SWPDEV-ICTWEB'
if ($env:COMPUTERNAME -ne $expected) {
    throw "WRONG SERVER. Expected $expected, this is $env:COMPUTERNAME. Stop here."
}
"Server guard passed: $env:COMPUTERNAME"

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Not elevated. Reopen PowerShell as Administrator." }
"Elevation check passed"
```

### Shared variables

```powershell
$appcmd     = "$env:windir\system32\inetsrv\appcmd.exe"
$redirectTo = 'https://uctools/quicklinks/'
```

---

## Part 1 — Survey what is actually there

Do not skip this. The rest of the runbook depends on knowing whether QuickLinks is a **site** or an **application under another site** — the answer changes which objects you stop.

```powershell
Mark "Part 1 - survey"

Import-Module WebAdministration -ErrorAction SilentlyContinue

"--- Sites (appcmd) ---"
& $appcmd list site

"--- Applications (appcmd) ---"
& $appcmd list app

"--- App pools (appcmd) ---"
& $appcmd list apppool

"--- Sites (WebAdministration provider) ---"
Get-Website | Select-Object Name, Id, State, PhysicalPath,
    @{n='Bindings';e={ ($_.bindings.Collection | ForEach-Object { "$($_.protocol)/$($_.bindingInformation)" }) -join '; ' }},
    applicationPool | Format-Table -AutoSize
```

> **If the provider returns nothing but `appcmd` lists sites**, use `appcmd` for enumeration throughout and the `Set-WebConfiguration*` cmdlets for changes. This happened on `swpapp-digisign` and is a known behaviour on these builds, not a fault.

### Identify the QuickLinks object

```powershell
& $appcmd list site  | Select-String -Pattern 'quicklink' -SimpleMatch
& $appcmd list app   | Select-String -Pattern 'quicklink' -SimpleMatch
```

### Check the HTTP Redirection feature is present

The redirect in Part 3 silently fails without it.

```powershell
Get-WindowsFeature Web-Http-Redirect | Select-Object Name, InstallState
```

If `InstallState` is not `Installed`:

```powershell
Install-WindowsFeature Web-Http-Redirect
```

No reboot required, but it does briefly recycle the web service.

### Check the redirect target does not point back here

A redirect to a hostname that resolves to this server creates a loop.

```powershell
Resolve-DnsName uctools -ErrorAction SilentlyContinue | Select-Object Name, IPAddress
Get-NetIPAddress | Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object IPAddress
```

```powershell
# Does the new home actually answer?
try {
    $r = Invoke-WebRequest -Uri 'https://uctools/quicklinks/' -UseBasicParsing -TimeoutSec 15
    "uctools returned HTTP $($r.StatusCode)"
} catch {
    "uctools did NOT respond cleanly: $($_.Exception.Message)"
}
```

---

### ▣ TEST GATE 1 — record the decision before changing anything

Write the answers into the transcript. You need them in Parts 3 and 4.

```powershell
Mark "TEST GATE 1 - survey findings"

"QuickLinks is a: <SITE named ... | APPLICATION under site ...>"
"Sites to STOP  : <comma separated list>"
"Sites to LEAVE : <the one carrying QuickLinks>"
"Web-Http-Redirect installed: <yes/no>"
"uctools reachable and not this server: <yes/no>"
"TEST GATE 1 - PASSED"
```

**Branch A — QuickLinks is its own site.** Stop every other site. Straightforward.

**Branch B — QuickLinks is an application under `Default Web Site`.** `Default Web Site` must stay **started**, or QuickLinks dies with it. Stop the other sites, and stop the *application pools* belonging to the sibling applications rather than the parent site. Apply the redirect at application scope, not site scope.

Do not proceed until you know which branch you are on.

---

## Part 2 — Back up before touching anything

```powershell
Mark "Part 2 - backup"

# IIS configuration
Copy-Item "$env:windir\system32\inetsrv\config\applicationHost.config" `
          "$workRoot\backup\applicationHost.config.$stamp.bak" -Force

# Native IIS backup set - restorable with appcmd restore backup
& $appcmd add backup "predecomm-$stamp"

# Machine-readable pre-change state, for rollback and the change record
Get-Website | Select-Object Name, Id, State, PhysicalPath, applicationPool, serverAutoStart |
    Export-Csv "$workRoot\state\sites-before-$stamp.csv" -NoTypeInformation

Get-ChildItem IIS:\AppPools | ForEach-Object {
    [pscustomobject]@{
        Name  = $_.Name
        State = (Get-WebAppPoolState -Name $_.Name -ErrorAction SilentlyContinue).Value
    }
} | Export-Csv "$workRoot\state\apppools-before-$stamp.csv" -NoTypeInformation

"--- Backup contents ---"
Get-ChildItem "$workRoot\backup", "$workRoot\state"
& $appcmd list backup
```

> If the `Get-Website` calls returned nothing in Part 1, capture state with `& $appcmd list site > "$workRoot\state\sites-before-$stamp.txt"` instead. The CSVs are for convenience; the `applicationHost.config` copy and the `appcmd` backup are the real rollback assets.

---

### ▣ TEST GATE 2

```powershell
Mark "TEST GATE 2 - backup verified"
Test-Path "$workRoot\backup\applicationHost.config.$stamp.bak"          # must be True
(Get-Item "$workRoot\backup\applicationHost.config.$stamp.bak").Length  # must be > 0
"TEST GATE 2 - PASSED"
```

---

## Part 3 — Apply the QuickLinks redirect

Do the redirect **before** stopping the other sites, so that if it misbehaves you are troubleshooting one change rather than two.

Set `$qlPath` from your Test Gate 1 answer:

```powershell
Mark "Part 3 - QuickLinks redirect"

# Branch A - QuickLinks is its own site:
$qlPath = "IIS:\Sites\QuickLinks"           # use the exact name from Part 1

# Branch B - QuickLinks is an application:
# $qlPath = "IIS:\Sites\Default Web Site\quicklinks"
```

### Redirect type — read this before running

`Found` (302) tells clients the move is temporary and is **not cached**. `Permanent` (301) **is cached by browsers, sometimes indefinitely**, and cannot be reliably undone — users who hit a 301 may keep being redirected even after you roll back.

Use `Found` for the two-week window. Switch to `Permanent` only once the new home is confirmed and you have decided not to roll back.

```powershell
$status = 'Found'          # 'Found' = 302 temporary | 'Permanent' = 301

Set-WebConfigurationProperty -PSPath $qlPath -Filter '/system.webServer/httpRedirect' -Name enabled            -Value $true
Set-WebConfigurationProperty -PSPath $qlPath -Filter '/system.webServer/httpRedirect' -Name destination        -Value $redirectTo
Set-WebConfigurationProperty -PSPath $qlPath -Filter '/system.webServer/httpRedirect' -Name exactDestination   -Value $true
Set-WebConfigurationProperty -PSPath $qlPath -Filter '/system.webServer/httpRedirect' -Name childOnly          -Value $false
Set-WebConfigurationProperty -PSPath $qlPath -Filter '/system.webServer/httpRedirect' -Name httpResponseStatus -Value $status

"--- Redirect configuration now reads ---"
Get-WebConfiguration -PSPath $qlPath -Filter '/system.webServer/httpRedirect' |
    Select-Object enabled, destination, exactDestination, childOnly, httpResponseStatus
```

`exactDestination = $true` sends every request to the single URL above. If you would rather preserve the sub-path and query string — so `/quicklinks/reports?x=1` lands on `https://uctools/quicklinks/reports?x=1` — use this instead:

```powershell
Set-WebConfigurationProperty -PSPath $qlPath -Filter '/system.webServer/httpRedirect' -Name exactDestination -Value $false
Set-WebConfigurationProperty -PSPath $qlPath -Filter '/system.webServer/httpRedirect' -Name destination      -Value 'https://uctools/quicklinks$S$Q'
```

### appcmd equivalent

If the provider cmdlets fail, the same change via `appcmd` (site scope shown):

```powershell
& $appcmd set config "QuickLinks/" /section:httpRedirect `
    /enabled:true `
    /destination:"https://uctools/quicklinks/" `
    /exactDestination:true `
    /childOnly:false `
    /httpResponseStatus:Found `
    /commit:apphost
```

---

### ▣ TEST GATE 3 — prove the redirect works

```powershell
Mark "TEST GATE 3 - redirect verification"

# Replace with the real hostname/port from the site's binding
$testUrl = 'http://swpdev-ictweb/quicklinks/'
```

PowerShell 7:

```powershell
$resp = Invoke-WebRequest -Uri $testUrl -MaximumRedirection 0 -UseBasicParsing -SkipHttpErrorCheck
"Status  : $($resp.StatusCode)"       # expect 302 (or 301 if you chose Permanent)
"Location: $($resp.Headers.Location)" # expect https://uctools/quicklinks/
```

Windows PowerShell 5.1 has no `-SkipHttpErrorCheck`:

```powershell
try   { Invoke-WebRequest -Uri $testUrl -MaximumRedirection 0 -UseBasicParsing }
catch { "Status  : $($_.Exception.Response.StatusCode.value__)"
        "Location: $($_.Exception.Response.Headers['Location'])" }
```

**Do not continue until the Location header is correct.** Then test from a client machine, in a browser, as a normal user.

```powershell
Mark "TEST GATE 3 - PASSED"
```

---

## Part 4 — Stop all other sites

Populate `$sitesToStop` from your Test Gate 1 list. Type the names explicitly rather than filtering programmatically — an exclusion filter that misfires stops the wrong thing.

```powershell
Mark "Part 4 - stop non-QuickLinks sites"

$keepSite    = 'QuickLinks'                       # Branch B: 'Default Web Site'
$sitesToStop = @('SiteOne','SiteTwo','SiteThree') # from Test Gate 1

"Will KEEP RUNNING : $keepSite"
"Will STOP         : $($sitesToStop -join ', ')"
```

Dry run first — this changes nothing:

```powershell
foreach ($s in $sitesToStop) {
    $exists = Get-Website -Name $s -ErrorAction SilentlyContinue
    "{0,-30} exists={1} currentState={2}" -f $s, [bool]$exists, $exists.State
}
```

If every line looks right, stop them:

```powershell
foreach ($s in $sitesToStop) {
    if ($s -eq $keepSite) { "SKIPPING $s - this is the site being kept"; continue }
    "Stopping $s ..."
    Stop-Website -Name $s
    Start-Sleep -Milliseconds 500
    "  state now: $((Get-Website -Name $s).State)"
}
```

`Stop-Website` sets `serverAutoStart="false"` in `applicationHost.config`, so stopped sites stay stopped across a reboot or an IIS restart. Confirm that explicitly rather than assuming:

```powershell
foreach ($s in $sitesToStop) {
    $autostart = Get-ItemProperty "IIS:\Sites\$s" -Name serverAutoStart -ErrorAction SilentlyContinue
    "{0,-30} serverAutoStart={1}" -f $s, $autostart.Value
}
```

Any that still read `True`:

```powershell
Set-ItemProperty "IIS:\Sites\<name>" -Name serverAutoStart -Value $false
```

### Application pools

Stopping a site leaves its pool running. Stop the pools that serve only stopped sites — but **not** any pool QuickLinks depends on.

```powershell
$poolsToStop = @('PoolOne','PoolTwo')    # confirm against Part 1 output first

foreach ($p in $poolsToStop) {
    $state = (Get-WebAppPoolState -Name $p -ErrorAction SilentlyContinue).Value
    "{0,-30} currentState={1}" -f $p, $state
}
```

```powershell
foreach ($p in $poolsToStop) {
    "Stopping pool $p ..."
    Stop-WebAppPool -Name $p -ErrorAction Continue
}
Start-Sleep -Seconds 2
Get-ChildItem IIS:\AppPools | ForEach-Object {
    "{0,-30} {1}" -f $_.Name, (Get-WebAppPoolState -Name $_.Name).Value
}
```

---

### ▣ TEST GATE 4 — QuickLinks still works, everything else does not

```powershell
Mark "TEST GATE 4 - post-stop verification"

"--- Site states ---"
Get-Website | Select-Object Name, State, serverAutoStart | Format-Table -AutoSize

"--- QuickLinks still redirects ---"
try   { Invoke-WebRequest -Uri $testUrl -MaximumRedirection 0 -UseBasicParsing }
catch { "Status  : $($_.Exception.Response.StatusCode.value__)"
        "Location: $($_.Exception.Response.Headers['Location'])" }
```

Expected: exactly one site `Started` (Branch A), everything else `Stopped`, and the redirect still returning its 302.

```powershell
Mark "TEST GATE 4 - PASSED"
```

**Phase 1 is complete.** Consider pausing here for a day or two to let anyone who depended on a stopped site notice and speak up, before committing to Phase 2.

---

## Part 5 — Phase 2: schedule the shutdown

Two weeks from 24 September 2026 is **Wednesday 8 October 2026**. A midweek, mid-evening slot means someone is around the next morning if it causes surprises. Adjust if your change window says otherwise.

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

- `/s` powers the machine **off**, it does not restart it
- `/t 300` gives a five-minute warning window, so anyone logged on sees a notice and the event log records intent before the power goes
- `/d p:2:4` stamps the shutdown as **planned, operating system, reconfiguration** in the event log — this is what makes it obvious afterwards that the outage was deliberate
- `-StartWhenAvailable` means that if the server happens to be off at 20:00 on the 8th, the task fires at the next opportunity instead of being skipped

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

Confirm `State` is `Ready` and `NextRunTime` is the date you expect. A `NextRunTime` that is blank or in the past means the trigger did not take.

```powershell
Mark "TEST GATE 5 - PASSED"
```

> **Do not test this task by running it.** `Start-ScheduledTask` on this one powers the server off.

---

## Part 6 — Tell the platform, not just the server

The scheduled task powers the guest off. It does not stop anything else powering it back on.

- [ ] Virtualisation team notified — VM must not auto-start, HA/DRS restart policy checked
- [ ] Monitoring suppressed, or the host removed from the monitored set, so the planned outage does not page anyone
- [ ] Backup schedule reviewed — decide whether the final backup is retained and for how long
- [ ] Change record updated with the shutdown date, and the transcript attached

---

## Part 7 — Stop the transcript

```powershell
Mark "Session ending"

"--- Final state ---"
& $appcmd list site
& $appcmd list apppool
Get-ScheduledTask -TaskPath '\SWP-Decomm\' | Select-Object TaskName, State
Get-ScheduledTask -TaskName 'Decommission - Scheduled Shutdown' -TaskPath '\SWP-Decomm\' |
    Get-ScheduledTaskInfo | Select-Object NextRunTime

"Phase 1 outcome : <completed | partially completed | backed out>"
"Phase 2 outcome : <completed | not attempted>"
"Shutdown set for: <date/time, or n/a>"
"Notes           : <anything that deviated from the runbook>"
"Ended           : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Stop-Transcript
```

Fill in the outcome lines **before** running `Stop-Transcript` — they are the first thing anyone reads. File the transcript with the change record.

### If the session drops or you need to stop partway

```powershell
Stop-Transcript          # if the session is still alive
```

To resume in a new session, append to the same file rather than starting a second one:

```powershell
$transcript = "C:\temp\ICTWebDecomm\transcripts\ictweb-decomm-<original stamp>.log"
Start-Transcript -Path $transcript -Append -IncludeInvocationHeader
"=== Resumed $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') at Part <n> ==="
```

Re-define `Mark`, `$workRoot`, `$stamp`, `$appcmd` and `$qlPath` in the new session — none of them survive.

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
Set-WebConfigurationProperty -PSPath $qlPath -Filter '/system.webServer/httpRedirect' -Name enabled -Value $false
Get-WebConfiguration -PSPath $qlPath -Filter '/system.webServer/httpRedirect' | Select-Object enabled, destination
```

If you used `Permanent` (301), browsers that already hit it keep redirecting until their cache clears. Users must clear their browser cache. This is why Part 3 defaults to 302.

### Restart the stopped sites

```powershell
Import-Csv "$workRoot\state\sites-before-$stamp.csv" |
    Where-Object { $_.State -eq 'Started' } |
    ForEach-Object {
        "Starting $($_.Name) ..."
        Set-ItemProperty "IIS:\Sites\$($_.Name)" -Name serverAutoStart -Value $true
        Start-Website -Name $_.Name -ErrorAction Continue
    }

Import-Csv "$workRoot\state\apppools-before-$stamp.csv" |
    Where-Object { $_.State -eq 'Started' } |
    ForEach-Object { Start-WebAppPool -Name $_.Name -ErrorAction Continue }

Get-Website | Select-Object Name, State | Format-Table -AutoSize
```

### Full configuration restore (last resort)

```powershell
& $appcmd list backup
& $appcmd restore backup "predecomm-<stamp>"
iisreset
```

Or manually — stop IIS first:

```powershell
iisreset /stop
Copy-Item "$workRoot\backup\applicationHost.config.<stamp>.bak" `
          "$env:windir\system32\inetsrv\config\applicationHost.config" -Force
iisreset /start
```

---

## Quick reference

| Item | Value |
|---|---|
| Server | `SWPDEV-ICTWEB` |
| Working folder | `C:\temp\ICTWebDecomm` |
| Transcript | `C:\temp\ICTWebDecomm\transcripts\ictweb-decomm-<stamp>.log` |
| IIS backup name | `predecomm-<stamp>` |
| Redirect target | `https://uctools/quicklinks/` |
| Redirect type | 302 Found (switch to 301 only after confirmation) |
| Shutdown task | `\SWP-Decomm\Decommission - Scheduled Shutdown` |
| Shutdown time | Wednesday 8 October 2026, 20:00 |
| Cancel shutdown | `Unregister-ScheduledTask -TaskName 'Decommission - Scheduled Shutdown' -TaskPath '\SWP-Decomm\' -Confirm:$false` |
