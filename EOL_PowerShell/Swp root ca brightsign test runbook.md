# SWP Internal Root CA — Export and Test on a BrightSign Player

**Purpose:** Export the SWP internal certificate authority chain and install it on a single test BrightSign player, to establish whether the player's data-feed subsystem can then validate an internally-issued HTTPS certificate.
**Version:** 1.0
**Date:** 18 September 2026
**Prepared by:** James Buller, ICT Datacenter Team
**Related:** Technical Documentation (Production) §7.4; Security Exception Request

---

## Why this exists

The signage feeds are currently served over HTTP. The reason is documented and evidenced: the BrightSign data-feed subsystem could not validate a certificate issued by `SWP IL3 Local Server Issuing CA`, and — unlike the player's browser component — it exposes no option to bypass validation.

Player diagnostics confirmed the underlying cause. The device's configuration showed:

```
"internalCAFiles":[], "internalCAPackages":[]
```

No internal certificate authority is installed on the player. Its trust store holds only the public CAs shipped in firmware, which is why `bbc.co.uk` works and an internal hostname does not.

Those two fields are device settings, which means installing an internal CA is a supported operation rather than a hack. This runbook finds out whether doing so makes the feed subsystem work.

## Scope and status

**This is exploratory work on one test player.** It changes nothing in production, does not alter any feed URL, and is fully reversible.

If it succeeds it opens a route to removing the HTTP carve-out — but that would be a separate piece of work with its own assessment, because a CA push across 64 players carries ongoing operational cost that was deliberately rejected once already.

## What you are proving

| Question | How this runbook answers it |
|---|---|
| Can the root CA be installed on a player at all? | The device configuration shows `internalCAFiles` populated |
| Does the feed subsystem then trust internally-issued certificates? | The player renders a feed fetched over HTTPS |
| Is the browser component separate from the feed component? | Already established — the browser has validation disabled entirely |

---

## Part 0 — Start the transcript

Run on a domain-joined machine with access to the certificate store. Your own workstation is fine — this part does not need to run on a server.

```powershell
$workRoot = "C:\temp\SWP-RootCA"
$stamp    = Get-Date -Format 'yyyyMMdd-HHmm'
mkdir "$workRoot\transcripts" -Force | Out-Null

$transcript = "$workRoot\transcripts\rootca-export-$stamp.log"
Start-Transcript -Path $transcript -IncludeInvocationHeader

"=== SWP internal root CA - export for BrightSign test ==="
"Runbook version : 1.0"
"Machine         : $env:COMPUTERNAME"
"Operator        : $env:USERDOMAIN\$env:USERNAME"
"Started         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"========================================================="
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
$exportDir = "$workRoot\export-$stamp"
mkdir $exportDir -Force | Out-Null

"workRoot  = $workRoot"
"exportDir = $exportDir"
```

---

## Part 1 — Identify the certificate chain

You need every certificate **above** the server certificate, not the server certificate itself. If SWP runs a two-tier PKI — a root with an issuing CA beneath it — the player needs both, or the chain cannot be completed.

Build the chain from the production server certificate.

```powershell
Mark "Part 1 - identify the chain"

# The production certificate. Run this on the server, or use any cert
# issued by the same CA from your local machine store.
$serverCertThumb = "03BD544B9A511AB31445C19B0D8B20179539197D"

$leaf = Get-ChildItem Cert:\LocalMachine\My\$serverCertThumb -ErrorAction SilentlyContinue
if (-not $leaf) {
    $leaf = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
            Where-Object { $_.Issuer -like "*SWP IL3*" } | Select-Object -First 1
}

$leaf | Format-List Subject, Issuer, Thumbprint

$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$null = $chain.Build($leaf)

$chain.ChainElements | ForEach-Object { $_.Certificate } |
  Format-List Subject, Issuer, NotAfter, Thumbprint
```

The output is ordered leaf first, root last. Expect either:

- **Two entries** — server certificate, then a self-signed root (issuer equals subject)
- **Three entries** — server certificate, issuing CA, then the root

Anything above the leaf needs exporting.

```powershell
# Everything except the leaf
$caCerts = $chain.ChainElements | ForEach-Object { $_.Certificate } | Select-Object -Skip 1
$caCerts | Format-List Subject, Thumbprint
"CA certificates to export: " + $caCerts.Count
```

If `$chain.Build()` returned any status other than `NoError`, note it — an incomplete chain locally would mean the exported files are incomplete too.

```powershell
$chain.ChainStatus
```

---

## Part 2 — Export as Base64 PEM

Embedded Linux devices generally require PEM (Base64) rather than DER (binary). BrightSign runs Linux, so export accordingly.

```powershell
Mark "Part 2 - export as PEM"

$index = 0
foreach ($c in $caCerts) {
    $index++

    # Readable filename from the subject common name
    $cn = ($c.Subject -split ',' | Where-Object { $_.Trim() -like 'CN=*' } |
           Select-Object -First 1) -replace '^\s*CN=', ''
    $safe = ($cn -replace '[^A-Za-z0-9\-]', '-') -replace '-+', '-'
    $file = Join-Path $exportDir ("{0:d2}-{1}.cer" -f $index, $safe)

    $b64 = [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks')
    $pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"

    # LF line endings, no BOM - safest for a Linux-based device
    $pem = $pem -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($file, $pem, (New-Object System.Text.UTF8Encoding($false)))

    "$file"
}

Get-ChildItem $exportDir | Select-Object Name, Length
```

### 2.1 Also produce a combined bundle

Some devices accept a single file containing the whole chain. Producing both costs nothing.

```powershell
$bundle = Join-Path $exportDir "swp-ca-bundle.pem"
Get-ChildItem $exportDir -Filter "*.cer" | Sort-Object Name | ForEach-Object {
    [System.IO.File]::ReadAllText($_.FullName)
} | Set-Content -Path $bundle -Encoding Ascii -NoNewline

Get-Content $bundle | Select-String "BEGIN CERTIFICATE" | Measure-Object | Select-Object Count
```

The count should match the number of CA certificates exported.

---

## Part 3 — Verify the exported files

Do not take the export on trust. A malformed or truncated certificate file produces a device that silently fails to trust anything, which is indistinguishable from not having installed it.

```powershell
Mark "Part 3 - verify exports"

foreach ($f in Get-ChildItem $exportDir -Filter "*.cer") {
    "--- $($f.Name) ---"
    certutil -dump $f.FullName | Select-String "Subject:|Issuer:|NotAfter:|Cert Hash"
}
```

Each file should report a subject, an issuer, a future expiry date, and a hash matching what Part 1 listed.

```powershell
# Confirm the file really is PEM and not DER
foreach ($f in Get-ChildItem $exportDir -Filter "*.cer") {
    $first = (Get-Content $f.FullName -First 1)
    "{0,-45} {1}" -f $f.Name, $first
}
```

Every line must begin `-----BEGIN CERTIFICATE-----`.

### 3.1 Identify which is the root

The root is the certificate whose subject and issuer are identical.

```powershell
foreach ($c in $caCerts) {
    $isRoot = ($c.Subject -eq $c.Issuer)
    "{0,-60} root={1}" -f $c.Subject, $isRoot
}
```

If the player will only accept one certificate, the root is the one it needs — but a two-tier PKI generally requires both for the chain to complete.

---

## Part 4 — Stop the transcript

```powershell
Mark "Export complete"

Get-ChildItem $exportDir | Select-Object Name, Length
"Export folder : $exportDir"
"Ended         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Stop-Transcript
```

Copy the export folder somewhere you can reach from the machine running BrightAuthor:connected.

> These files are public certificates, not private keys. There is nothing secret in them — a root CA certificate is designed to be distributed widely. They still identify internal infrastructure, so handle them as internal material rather than publishing them anywhere.

---

## Part 5 — Prepare the test player

**Use one player, and one that is not showing anything anyone depends on.**

### 5.1 Fix time synchronisation first

Diagnostics from the earlier player log showed repeated failures:

```
NetworkTime: Failed: gnutls_handshake() failed: Error in protocol version
```

Certificate validation depends on an accurate clock. A player whose time has drifted will reject a perfectly valid certificate as not-yet-valid or expired, and you will spend the afternoon debugging the wrong thing.

Confirm the player's clock is correct before installing anything. If time sync is failing, that is worth resolving in its own right regardless of this exercise.

### 5.2 Capture the starting state

Pull a diagnostic log from the player and confirm:

```
"internalCAFiles":[], "internalCAPackages":[]
```

Both empty. This is the "before" evidence.

---

## Part 6 — Install the CA on the player

**This part needs verifying against BrightSign's own documentation rather than taken from this runbook.** The BrightAuthor:connected interface has changed across versions, and the estate's firmware is 9.1.151 on XT244 hardware. A confidently wrong click path wastes more time than an honest gap.

What is known from the device configuration:

- The relevant settings are `internalCAFiles` and `internalCAPackages`
- They sit in the device settings block alongside network configuration, not in the presentation
- That implies they are applied through a device setup or configuration profile, pushed to a device or group, and take effect when the player next pulls its configuration — so expect a reboot or forced sync rather than an immediate change

Search BrightSign's documentation for `internalCAFiles` — it is an exact field name and should lead straight to the right page for your BSN.cloud version.

Apply to **one device only**, not a group.

---

## Part 7 — Confirm the CA actually installed

The step people skip, and the reason failures at Part 8 become ambiguous.

Pull a fresh diagnostic log from the player after it has resynchronised, and check the same fields:

```
"internalCAFiles":["..."], "internalCAPackages":[...]
```

**If these are still empty, stop.** The certificate did not install, and nothing at Part 8 will tell you anything useful. Go back to Part 6.

---

## Part 8 — Test

Production serves the feed files over both HTTP and HTTPS — the site has both bindings, and the feed path is anonymous on each. So you can test the HTTPS URL directly without changing anything in production.

### 8.1 Test URL

```
https://swpapp-digisign.swp-rest.police.int/signageadmin/feeds/rss/datacenter.xml
```

### 8.2 Method

1. Add a distinctive test item through the admin interface — something you will recognise at a glance
2. Point the test player's feed at the **HTTPS** URL above
3. Allow a full poll cycle. Players cache, so an immediate blank is not necessarily failure
4. Watch for your specific text, not merely "is the ticker moving"

### 8.3 Confirm from the server side

```powershell
Get-ChildItem E:\inetpub\logs\LogFiles\W3SVC4\*.log |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
  Get-Content | Select-String '<player IP>' | Select-Object -Last 20
```

This distinguishes the two failure modes, which look identical on screen:

| Server log | Meaning |
|---|---|
| A request with status 200 | The fetch succeeded. Any display problem is presentation-side. |
| No entry at all from the player's IP | The request never arrived — TLS failed before HTTP. The CA is still not trusted. |
| A request with 401, 403 or 404 | It connected but was refused. A different problem — path or permissions, not trust. |

---

## Part 9 — Interpreting the result

### It worked

The feed subsystem can validate internally-issued certificates once the CA is installed. That is a genuinely useful finding, and it means the HTTP carve-out is a choice rather than a necessity.

It does **not** mean you should immediately roll the CA to all 64 players. The reasons that option was rejected still apply:

- A permanent provisioning step for all future signage hardware
- Silent failure for any device that misses the push or is later reset
- A single root expiry date capable of taking the whole estate stale at once

What it does mean is that the option is real and tested, so the decision can be revisited on evidence rather than assumption. Record the result either way.

### It did not work — no request reached the server

The CA installed but the feed subsystem still does not use it. That would mean the feed component has a trust configuration separate even from the device-level CA store. Worth capturing a full player log and raising with BrightSign support, since at that point the behaviour is arguably a defect.

### It did not work — the CA would not install

Either the firmware does not support it or the mechanism differs on this version. Check firmware release notes for changes to certificate handling in data feeds before concluding.

---

## Part 10 — Reverting

Nothing in production changed, so reverting is confined to the test player.

1. Point the player's feed back at the HTTP URL
2. Remove the CA from the device configuration if you want a clean state — though leaving an internal root CA installed is harmless and may be useful later
3. Reboot or force a sync

If the player was borrowed from live service, confirm it is rendering its original content before putting it back.

---

## Record the outcome

Whatever happens, write it down. This question has now come up twice, and an evidenced answer stops it being re-litigated from memory a third time.

| Field | |
|---|---|
| Date tested | |
| Player serial and firmware | |
| CA installed successfully | yes / no |
| Feed fetched over HTTPS | yes / no |
| Server log showed the request | yes / no |
| Conclusion | |

Add the result to the Technical Documentation alongside the existing §7.4 exception rationale.
