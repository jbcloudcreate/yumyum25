# SWPDEV-ICTWEB — Phase 1 Completion

**Follows:** Runbook v1.1 + Redirect Remediation v1.0
**Session:** `ictweb-decomm-20260924-1335`, last closed 14:21:27
**Status:** Redirect complete and verified. Application shutdown **incomplete**.

---

## Where things actually stand

| Item | State | Correct? |
|---|---|---|
| QuickLinks redirect | 302 → `https://uctools/quicklinks/`, end-to-end 200 | ✅ |
| `quicklinks` pool | Started, autoStart True | ✅ |
| `Default Web Site` | Started | ✅ |
| `applicationHost.config` scope | Confirmed — app web.config untouched since 02/07/2020 | ✅ |
| `DefaultAppPool` | **Stopped, but autoStart = True** | ⚠️ comes back on restart |
| Seven sibling pools | **Still Started** (autoStart False) | ❌ still serving |
| Two idle pools | **Still Started** (autoStart False) | ❌ |
| Scheduled shutdown task | Not created | — Phase 2 |
| Transcript closing record | Missing | ❌ |

**`/ucdashboard/` returned 200 at Test Gate 4, not 503.** Every sibling application is still live and serving right now.

---

## What did not run, and why

### 1. The stop loop was skipped

The dry run at 14:18:22 executed and showed all nine pools `Started`. The `autoStart` loop at 14:19:24 executed. **The block between them — the one that actually calls `Stop-WebAppPool` — never ran.** It does not appear anywhere in the transcript, and the final pool states confirm it.

The net effect is that `autoStart = False` was applied to running pools. They would stop at the next IIS restart, but they are serving now. That is an accidental route to the right end state and not one to rely on.

### 2. DefaultAppPool autoStart stayed True

You chose Option A and stopped it at 14:19:11. But v1.1 put the matching `autoStart` line behind a comment marker:

```powershell
# Option A only:
# Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name autoStart -Value $false
```

Pasting the block leaves it commented. **That is a defect in my runbook** — a load-bearing step should never depend on the operator un-commenting a line mid-paste. `DefaultAppPool` is currently stopped but will restart on the next `iisreset` or reboot, taking `/`, `/wac` and `/ADLockoutsSD/ADLockout` back up with it.

### 3. The closing record never made it into the transcript

The `Session ending` block captured the `appcmd` output and then stopped. The `Test-Redirect` result and all six outcome lines are absent, and the transcript ended one second later.

`Stop-Transcript` was in the same pasted block as the final state capture. Native command output (`appcmd`) writes straight through, but PowerShell's object formatter buffers — so `Stop-Transcript` closed the file before the tail flushed. **Also my defect.** `Stop-Transcript` belongs in a separate command, entered only after you can see the final state output on screen.

The outcome lines were also still placeholders. Those are the first thing anyone reads on the change record.

---

## Part 4C — Complete the application shutdown

Resume the transcript first.

```powershell
$workRoot   = "C:\temp\ICTWebDecomm"
$stamp      = '20260924-1335'
$transcript = "$workRoot\transcripts\ictweb-decomm-$stamp.log"

Start-Transcript -Path $transcript -Append -IncludeInvocationHeader

"=== Resumed $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Phase 1 Completion ==="
"Change ref : <fill in>"
"Operator   : $env:USERDOMAIN\$env:USERNAME"
"NOTE: Redirect complete and verified at 14:17. Completing the pool shutdown missed at 14:19."
```

Re-declare — none of it survived the session close:

```powershell
function Mark([string]$text) {
    ""
    "########## $text  [$(Get-Date -Format 'HH:mm:ss')] ##########"
    ""
}

function Test-Redirect([string]$Url) {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.AllowAutoRedirect     = $false
    $req.UseDefaultCredentials = $true
    $req.Timeout               = 15000
    $resp = $null; $err = $null
    try   { $resp = $req.GetResponse() }
    catch [System.Net.WebException] { $err = $_.Exception.Status; $resp = $_.Exception.Response }
    if ($resp) {
        [pscustomobject]@{ Url=$Url; Status=[int]$resp.StatusCode; Location=$resp.Headers['Location']; Note=$err }
        $resp.Close()
    } else {
        [pscustomobject]@{ Url=$Url; Status='ERROR'; Location=$null; Note=$err }
    }
}

$appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
Import-Module WebAdministration

if ($env:COMPUTERNAME -ne 'SWPDEV-ICTWEB') { throw "WRONG SERVER: $env:COMPUTERNAME" }
"Guard passed - $env:COMPUTERNAME"
```

### Stop the pools

```powershell
Mark "Part 4C - stopping sibling application pools"

$poolsToStop = @('ud','ucdashboard','etsdashboard','UserManagement','chatbot','iistest','IL3_Checks_Dev')
$poolsIdle   = @('Signagefeedadmin','SWPICTSignageFeedHub')

foreach ($p in ($poolsToStop + $poolsIdle)) {
    if ($p -eq 'quicklinks') { "REFUSING to stop quicklinks"; continue }
    $before = (Get-WebAppPoolState -Name $p -ErrorAction SilentlyContinue).Value
    if ($before -eq 'Stopped') { "{0,-26} already Stopped" -f $p; continue }
    Stop-WebAppPool -Name $p -ErrorAction Continue
    Start-Sleep -Milliseconds 400
    $after = (Get-WebAppPoolState -Name $p -ErrorAction SilentlyContinue).Value
    "{0,-26} {1} -> {2}" -f $p, $before, $after
}
```

Every line must end `Started -> Stopped`. This version reports the transition per pool rather than running silently, so a skipped or failed stop is visible in the transcript as it happens.

### Fix DefaultAppPool autoStart

You chose Option A, so this is required:

```powershell
Mark "Part 4C - DefaultAppPool autoStart"

Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name autoStart -Value $false

"DefaultAppPool state     : $((Get-WebAppPoolState -Name 'DefaultAppPool').Value)"
"DefaultAppPool autoStart : $((Get-Item 'IIS:\AppPools\DefaultAppPool').autoStart)"
```

Must read `Stopped` / `False`.

### Full pool state

```powershell
Mark "Part 4C - final pool states"

Get-ChildItem IIS:\AppPools | Sort-Object Name | ForEach-Object {
    "{0,-26} {1,-9} autoStart={2}" -f $_.Name, (Get-WebAppPoolState -Name $_.Name).Value, $_.autoStart
}
```

Expected: **`quicklinks` is the only pool reading `Started` / `autoStart=True`.**

The four unused IIS defaults (`.NET v2.0`, `.NET v2.0 Classic`, `.NET v4.5`, `.NET v4.5 Classic`) and `Classic .NET AppPool` will still read Started. No application references them, so they serve nothing. Leave them — stopping them is cosmetic and adds rollback surface for no benefit.

---

## ▣ TEST GATE 4C

```powershell
Mark "TEST GATE 4C - post-stop verification"

"--- Sites: Default Web Site MUST still be Started ---"
Get-Website | Select-Object Name, State | Format-Table -AutoSize

"--- QuickLinks must still redirect ---"
Test-Redirect 'http://swpdev-ictweb/quicklinks/'

"--- Stopped siblings must now return 503 ---"
@(
    'http://swpdev-ictweb/ucdashboard/'
    'http://swpdev-ictweb/etsdashboard/'
    'http://swpdev-ictweb/chatbot/'
    'http://swpdev-ictweb/UserManagement/'
    'http://swpdev-ictweb/'
) | ForEach-Object { Test-Redirect $_ } | Format-Table -AutoSize
```

| Check | Required |
|---|---|
| `Default Web Site` | Started |
| `/quicklinks/` | **302** → `https://uctools/quicklinks` |
| `/ucdashboard/`, `/etsdashboard/`, `/chatbot/`, `/UserManagement/` | **503** |
| `/` (site root, DefaultAppPool) | **503** |

A 200 on any of the bottom five means that pool did not stop. Do not mark the gate passed.

```powershell
Mark "TEST GATE 4C - PASSED"
```

Then confirm in a browser from a client machine that `http://swpdev-ictweb/quicklinks/` still lands on working QuickLinks.

---

## Corrected session close

**Run this as one block, read the output, then run `Stop-Transcript` as a separate command.** That ordering is the fix for the lost tail.

```powershell
Mark "Session ending"

"--- Final state ---"
& $appcmd list site
& $appcmd list apppool
Get-ChildItem IIS:\AppPools | Sort-Object Name | ForEach-Object {
    "{0,-26} {1,-9} autoStart={2}" -f $_.Name, (Get-WebAppPoolState -Name $_.Name).Value, $_.autoStart
} | Out-String
Test-Redirect 'http://swpdev-ictweb/quicklinks/' | Format-Table -AutoSize | Out-String
Get-ScheduledTask -TaskPath '\SWP-Decomm\' -ErrorAction SilentlyContinue |
    Select-Object TaskName, State | Format-Table -AutoSize | Out-String

"Phase 1 outcome    : completed - redirect live, all sibling pools stopped"
"Phase 2 outcome    : <completed | not attempted>"
"DefaultAppPool     : Option A - stopped, autoStart False"
"Redirect config    : Config A fixed destination - uctools does not serve sub-paths"
"Deviations         : Test Gate 3 failed on first attempt (v1.1 exactDestination defect, remediated). Pool stop loop missed on first attempt at 14:19, completed at <time>."
"Ended              : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
```

The `| Out-String` on each formatted command forces the formatter to flush before the next line runs, so nothing is lost at the close.

Check all of that appeared on screen. **Then**, separately:

```powershell
Stop-Transcript
```

---

## Phase 2 — when you are ready

Runbook v1.1 Part 5 is unchanged and still correct. Nothing in today's faults touches it.

Worth taking the pause v1.1 suggested before scheduling the shutdown. Ten applications only actually stop serving when you run Part 4C above — the clock on "has anyone complained" starts then, not at 14:19. If you want the full two weeks of observation, 8 October still works.

Two items to fill in before Phase 2:

- **Change reference** — still `<fill in>` in all three resume headers
- **`/wac` and `/ADLockoutsSD/ADLockout`** — recorded as "not needed" at Test Gate 1R. Once Part 4C runs they genuinely stop, so if that was a quick judgement rather than a checked one, now is the moment

---

## Minor observation, no action

The `Location` header reads `https://uctools/quicklinks` without a trailing slash, though the configured destination has one. The end-to-end test returned 200 with 1158 bytes — byte-identical to the direct fetch of `https://uctools/quicklinks/` — so uctools normalises it. Cosmetic only.

The `TrustFailure` on `https://swpdev-ictweb/quicklinks/` is confirmed: certificate `953A0CC0…` is bound at `0.0.0.0:443`, but the diagnostic returned no matching certificate from `Cert:\LocalMachine\My`, so the binding points at a thumbprint that is no longer in the store. Pre-existing, unrelated to this change, and it disappears with the server. Worth one line in the change record so nobody thinks the decommission caused it.

---

## Runbook defects to fold into v1.2

For when this gets reused on the next box:

1. **Part 3 optional block** — `exactDestination = $false` combined with `$S` doubles the sub-path. Never both.
2. **Test Gate 3** — tested root paths only. Must test a sub-path and a query string, and must follow the redirect end-to-end to a 200.
3. **Part 4 Option A** — the `DefaultAppPool` `autoStart` line was behind a comment marker and got missed. Make it a real conditional.
4. **Part 4 stop loop** — ran silently with no per-pool confirmation, so skipping it left no trace. Report `before -> after` per pool.
5. **Part 7** — `Stop-Transcript` in the same block as the final state capture truncates the closing record. Separate command, and `| Out-String` on formatted output.
6. **Part 1** — add a check for sub-path handling at the redirect target before choosing the redirect configuration.
