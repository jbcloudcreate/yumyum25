# SWPDEV-ICTWEB — Redirect Remediation

**Remediation version:** 1.0
**Follows:** Runbook v1.1, session `ictweb-decomm-20260924-1335`, failed at Test Gate 3 (14:04)
**Corrects:** A defect in Runbook v1.1 Part 3, not an operator error

---

## Immediate state

The redirect is **live and misconfigured** on `Default Web Site/quicklinks` right now. Every request with a sub-path doubles it. If you are not fixing it straight away, disable it first:

```powershell
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/quicklinks' `
    -Filter '/system.webServer/httpRedirect' -Name enabled -Value $false
```

Impact is limited — this is a dev box and QuickLinks is moving anyway — but a broken redirect is worse than no redirect, because users land on a 404 instead of the old working site.

---

## What went wrong

`exactDestination` and the `$S` variable **both** append the request's sub-path. Setting `exactDestination = false` *and* using `$S` in the destination applies it twice.

The optional block in Runbook v1.1 Part 3 told you to do exactly that:

```powershell
# v1.1 - WRONG. Both lines append the suffix.
Set-WebConfigurationProperty ... -Name exactDestination -Value $false
Set-WebConfigurationProperty ... -Name destination      -Value 'https://uctools/quicklinks$S$Q'
```

Working through the failure with `destination = https://uctools/quicklinks$S$Q` and `exactDestination = false`:

| Request | `$S` resolves to | After substitution | IIS then appends | Final |
|---|---|---|---|---|
| `/quicklinks` | *(empty)* | `…/quicklinks` | *(nothing)* | `…/quicklinks` ✓ |
| `/quicklinks/` | `/` | `…/quicklinks/` | `/` | `…/quicklinks//` ✗ |
| `/quicklinks/home` | `/home` | `…/quicklinks/home` | `/home` | `…/quicklinks/home/home` ✗ |

That matches all three observed results exactly, including the double slash in Test Gate 3 that I should have caught as the same symptom at lower severity.

### The rule

- `exactDestination = true` → IIS uses the destination **verbatim**. Variables (`$S`, `$Q`, `$V`, `$P`) are still substituted.
- `exactDestination = false` → IIS **appends** the requested relative path to the destination.

Use variables, or use auto-append. Never both.

### Two defects in v1.1, for the record

1. The optional block combined `exactDestination = false` with `$S` — the fault above.
2. Test Gate 3 tested three variants of the **root path only**. A sub-path test would have caught this before you went to a browser. Corrected below.

---

## Part 3R.a — Does uctools handle sub-paths at all?

This decides which configuration to apply, so run it first.

The old QuickLinks is a PowerShell Universal Dashboard app — its `web.config` routes `path="*"` to `universaldashboard.server.exe`, so *every* path under `/quicklinks` returns the app shell and routing happens client-side. Whether the new home behaves the same way is unknown and worth two minutes to establish.

```powershell
Mark "Part 3R.a - does uctools handle sub-paths"

foreach ($p in @('/quicklinks/', '/quicklinks/home', '/quicklinks/nonsense-path-test')) {
    $u = "https://uctools$p"
    try {
        $r = Invoke-WebRequest -Uri $u -UseBasicParsing -UseDefaultCredentials -TimeoutSec 15 -ErrorAction Stop
        "{0,-45} {1}  ({2} bytes)" -f $u, $r.StatusCode, $r.RawContentLength
    } catch {
        $sc = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 'no response' }
        "{0,-45} {1}" -f $u, $sc
    }
}
```

Read the result:

| `/quicklinks/home` | `/quicklinks/nonsense-path-test` | Meaning | Use |
|---|---|---|---|
| 200 | 200 | SPA — every path returns the shell | **Config B** |
| 200 | 404 | Real server-side routes, `/home` exists | **Config B** |
| 404 | 404 | Sub-paths are not served | **Config A** |

If `/quicklinks/home` returns 404, preserving sub-paths sends people to a page that does not exist. Send everyone to the QuickLinks landing page instead and let them re-navigate.

---

## Part 3R.b — Apply the corrected redirect

### Config A — fixed destination

Every request under `/quicklinks` lands on the QuickLinks home page at uctools, whatever path or query string it carried.

```powershell
Mark "Part 3R.b - applying Config A (fixed destination)"

$apphost = 'MACHINE/WEBROOT/APPHOST'
$filter  = '/system.webServer/httpRedirect'

Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name destination        -Value 'https://uctools/quicklinks/'
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name exactDestination   -Value $true
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name childOnly          -Value $false
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name httpResponseStatus -Value 'Found'
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name enabled            -Value $true
```

### Config B — preserve sub-path and query string

The single change from what is on the server now is `exactDestination` → **`$true`**.

```powershell
Mark "Part 3R.b - applying Config B (preserve sub-path)"

$apphost = 'MACHINE/WEBROOT/APPHOST'
$filter  = '/system.webServer/httpRedirect'

Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name destination        -Value 'https://uctools/quicklinks$S$Q'
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name exactDestination   -Value $true
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name childOnly          -Value $false
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name httpResponseStatus -Value 'Found'
Set-WebConfigurationProperty -PSPath $apphost -Location $qlApp -Filter $filter -Name enabled            -Value $true
```

> There is an equivalent form — `destination = 'https://uctools/quicklinks'` with `exactDestination = $false`, letting IIS append. It produces the same result, but the behaviour is invisible in the config. Config B above states the intent on the face of it, which is better for whoever reads this in six months.

### Confirm what landed

```powershell
Get-WebConfiguration -PSPath $apphost -Location $qlApp -Filter $filter |
    Select-Object enabled, destination, exactDestination, childOnly, httpResponseStatus

"web.config last modified: $((Get-Item $qlWebConfig).LastWriteTime)"   # must still read 02/07/2020
```

That timestamp check matters — it confirms the change went to `applicationHost.config` and not into `E:\webroot\quicklinks\web.config`, which is what your rollback backup covers.

---

## Part 3R.c — Improved test helper

The v1.1 helper reported `no response` for the HTTPS test without saying why. This version surfaces the underlying `WebExceptionStatus`.

```powershell
function Test-Redirect([string]$Url) {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.AllowAutoRedirect     = $false
    $req.UseDefaultCredentials = $true
    $req.Timeout               = 15000
    $resp = $null; $err = $null
    try   { $resp = $req.GetResponse() }
    catch [System.Net.WebException] {
        $err  = $_.Exception.Status
        $resp = $_.Exception.Response
    }
    if ($resp) {
        [pscustomobject]@{
            Url      = $Url
            Status   = [int]$resp.StatusCode
            Location = $resp.Headers['Location']
            Note     = $err
        }
        $resp.Close()
    } else {
        [pscustomobject]@{ Url = $Url; Status = 'ERROR'; Location = $null; Note = $err }
    }
}
```

---

## ▣ TEST GATE 3R — replaces Test Gate 3

**This now tests sub-paths and query strings, which is what v1.1 missed.**

```powershell
Mark "TEST GATE 3R - redirect verification"

@(
    'http://swpdev-ictweb/quicklinks'
    'http://swpdev-ictweb/quicklinks/'
    'http://swpdev-ictweb/quicklinks/home'
    'http://swpdev-ictweb/quicklinks/home?tab=1'
    'https://swpdev-ictweb/quicklinks/'
) | ForEach-Object { Test-Redirect $_ } | Format-Table -AutoSize
```

### Expected — Config A

| Request | Location |
|---|---|
| `/quicklinks` | `https://uctools/quicklinks/` |
| `/quicklinks/` | `https://uctools/quicklinks/` |
| `/quicklinks/home` | `https://uctools/quicklinks/` |
| `/quicklinks/home?tab=1` | `https://uctools/quicklinks/` |

### Expected — Config B

| Request | Location |
|---|---|
| `/quicklinks` | `https://uctools/quicklinks` |
| `/quicklinks/` | `https://uctools/quicklinks/` |
| `/quicklinks/home` | `https://uctools/quicklinks/home` |
| `/quicklinks/home?tab=1` | `https://uctools/quicklinks/home?tab=1` |

**No doubled segments. No `//` anywhere after the hostname.**

### Then follow the redirect end to end

A correct `Location` header is necessary but not sufficient — v1.1 stopped here and that is how the fault reached a browser.

```powershell
Mark "TEST GATE 3R - end-to-end follow"

foreach ($u in @('http://swpdev-ictweb/quicklinks/', 'http://swpdev-ictweb/quicklinks/home')) {
    try {
        $r = Invoke-WebRequest -Uri $u -UseBasicParsing -UseDefaultCredentials -TimeoutSec 20 -ErrorAction Stop
        "{0,-42} final HTTP {1}, {2} bytes" -f $u, $r.StatusCode, $r.RawContentLength
    } catch {
        $sc = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 'no response' }
        "{0,-42} FAILED: {1}" -f $u, $sc
    }
}
```

Both lines must end in **HTTP 200**. `Invoke-WebRequest` follows redirects by default, so this walks the whole chain the way a browser does.

**Finally, in a browser, as a normal user**, from a client machine — not from the server:

- `http://swpdev-ictweb/quicklinks/` → working QuickLinks page
- `http://swpdev-ictweb/quicklinks/home` → working page, correct URL in the address bar, no doubled path

```powershell
Mark "TEST GATE 3R - PASSED"
```

---

## Part 3R.d — The HTTPS result (record, do not block on)

`https://swpdev-ictweb/quicklinks/` returned no response at 14:02. The re-run above will now name the reason. Diagnose and record it:

```powershell
Mark "Part 3R.d - HTTPS binding diagnostic"

netsh http show sslcert ipport=0.0.0.0:443
Get-WebBinding -Name 'Default Web Site' -Protocol https | Select-Object protocol, bindingInformation, certificateHash

$thumb = (Get-WebBinding -Name 'Default Web Site' -Protocol https).certificateHash
if ($thumb) {
    Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumb } |
        Select-Object Subject, NotAfter, @{n='Expired';e={$_.NotAfter -lt (Get-Date)}}, DnsNameList
} else {
    "No certificate hash on the https binding"
}
```

Likely `TrustFailure` — a self-signed or expired certificate on a dev server, or one whose name does not cover `swpdev-ictweb`.

**This does not block the decommission.** The redirect target is HTTPS on *uctools*, which already tested clean. But note it in the change record, because anyone who bookmarked the `https://` form of the QuickLinks URL gets a certificate warning before they reach the redirect. If that turns out to be common, the 24-hour notice in Part 5 is the place to mention it.

---

## What carries forward unchanged

Runbook v1.1 Parts 4 through 8 need no amendment. In particular:

- **Part 4** — stop the seven sibling pools, leave `quicklinks` running. You recorded **Option A** at Test Gate 1R, so `DefaultAppPool` also stops, taking `/`, `/wac` and `/ADLockoutsSD/ADLockout` with it.
- **Part 5–7** — scheduled shutdown, platform notifications, transcript close.
- **Part 8** — rollback. The `applicationHost.config` backup taken at 14:01 (87,859 bytes) covers the redirect, because it was committed to apphost scope rather than the application's `web.config`. That part of v1.1 held up.

Resume at v1.1 Part 4 once Test Gate 3R passes.

---

## Quick reference — corrected

| Setting | Config A (fixed) | Config B (preserve path) |
|---|---|---|
| `destination` | `https://uctools/quicklinks/` | `https://uctools/quicklinks$S$Q` |
| `exactDestination` | `True` | **`True`** |
| `childOnly` | `False` | `False` |
| `httpResponseStatus` | `Found` (302) | `Found` (302) |
| `enabled` | `True` | `True` |

**Never** set `exactDestination = False` while the destination contains `$S` or `$V`.
