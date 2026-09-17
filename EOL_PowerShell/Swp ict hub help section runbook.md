# SWP ICT Hub — Add Help and Support Section

**Server:** `swpapp-digisign.swp-rest.police.int`
**Target:** `E:\inetpub\wwwroot\icthub`
**Version:** 1.0
**Date:** 17 September 2026
**Prepared by:** James Buller, ICT Datacenter Team

---

## What this does

Adds a "Help and support" section beneath the four team tiles on the ICT Hub, containing:

| Card | Links to | Status |
|---|---|---|
| User guide | `docs/SWP-Signage-User-Guide.pdf` | Live |
| Request access | Service Desk | Placeholder (`#`) |
| Report a problem | Service Desk | Placeholder (`#`) |

The two placeholders render faded, so it is visually obvious they are not yet wired up.

## Why this is low risk

The ICT Hub is static HTML. There is no build step, no application pool to recycle, and no service interruption — saving the file is the deployment. The Feed Admin application is not touched.

The Hub sits behind Windows Authentication, so anything placed in its folder is automatically restricted to domain users.

## Note on file transfer

The PowerShell in this runbook **generates the HTML and CSS itself**. Nothing needs transferring except the PDF documents, so the whole change can be made by pasting commands into a remote session.

---

## Part 0 — Start the transcript

```powershell
$deployRoot = "C:\temp\SignageDeploy"
$stamp      = Get-Date -Format 'yyyyMMdd-HHmm'
mkdir "$deployRoot\transcripts" -Force | Out-Null

$transcript = "$deployRoot\transcripts\hub-help-section-$stamp.log"
Start-Transcript -Path $transcript -IncludeInvocationHeader

"=== SWP ICT Hub - add help and support section ==="
"Runbook version : 1.0"
"Server          : $env:COMPUTERNAME"
"Operator        : $env:USERDOMAIN\$env:USERNAME"
"Started         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"=================================================="
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
$hubRoot  = "E:\inetpub\wwwroot\icthub"
$hubPage  = "$hubRoot\index.html"
$docsDir  = "$hubRoot\docs"

"hubRoot = $hubRoot"
"hubPage = $hubPage"
"docsDir = $docsDir"
```

---

## Part 1 — Back up the current page

The Hub has been edited by hand since deployment. Back it up before anything else.

```powershell
Mark "Part 1 - backup"

mkdir "$deployRoot\hub-backup" -Force | Out-Null
$backup = "$deployRoot\hub-backup\index.html.$stamp"
Copy-Item $hubPage $backup
Get-Item $backup | Select-Object FullName, Length, LastWriteTime
```

Confirm the backup exists and is a sensible size before proceeding.

---

## Part 2 — Create the docs folder and add the PDFs

```powershell
Mark "Part 2 - docs folder"

mkdir $docsDir -Force | Out-Null
Get-ChildItem $hubRoot -Directory
```

Copy the user guide PDF into `E:\inetpub\wwwroot\icthub\docs\` as:

```
SWP-Signage-User-Guide.pdf
```

**Export to PDF rather than copying the .docx.** A PDF opens in the browser tab, which is what people expect from a help link. A .docx prompts a download and opens Word — and on a hardened IIS build the `.docx` MIME type is sometimes absent, producing a 404.

```powershell
Get-ChildItem $docsDir | Select-Object Name, Length, LastWriteTime
```

The filename must match exactly, including case. Windows will not care; the link in the page will.

---

## Part 3 — Confirm the insertion points

The script edits the live page, so check the anchors exist first.

```powershell
Mark "Part 3 - check anchors"

$html = Get-Content $hubPage -Raw

"style close tag : " + ([regex]::Matches($html, '</style>').Count)
"main close tag  : " + ([regex]::Matches($html, '</main>').Count)
"already applied : " + ([regex]::Matches($html, 'help-section').Count)
```

Required:

- `</style>` exactly **1**
- `</main>` exactly **1**
- `help-section` exactly **0**

If `help-section` is anything other than 0, the change has already been applied — stop and skip to Part 6.

If either tag count is not 1, stop. The page has diverged from what this runbook expects and the automated insertion is not safe.

---

## Part 4 — Insert the CSS

Inserted immediately before `</style>`, so it inherits the existing brand variables.

```powershell
Mark "Part 4 - insert CSS"

$css = @'
    .help-section {
        margin-top: 3rem;
        padding-top: 1.75rem;
        border-top: 1px solid #ddd;
    }
    .help-section h2 {
        font-size: 1.05rem;
        margin: 0 0 0.25rem;
        color: var(--brand-bg);
    }
    .help-section p.help-intro {
        color: #555;
        margin: 0 0 1.25rem;
        font-size: 0.95rem;
    }
    .help-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 0.9rem;
    }
    .help-card {
        flex: 1 1 210px;
        max-width: 280px;
        display: flex;
        align-items: flex-start;
        gap: 0.7rem;
        padding: 0.9rem 1rem;
        border: 1px solid #ddd;
        border-left: 3px solid var(--brand-bg);
        border-radius: 3px;
        background: #fff;
        text-decoration: none;
        color: inherit;
        transition: background 0.15s ease, border-color 0.15s ease;
    }
    .help-card:hover, .help-card:focus {
        background: #f5f8fc;
        border-color: var(--brand-bg);
    }
    .help-card svg { flex: 0 0 auto; margin-top: 2px; color: var(--brand-bg); }
    .help-card .help-title { font-weight: 600; font-size: 0.95rem; display: block; }
    .help-card .help-sub { color: #666; font-size: 0.82rem; display: block; margin-top: 0.15rem; }
    .help-card.pending { opacity: 0.6; }
'@

$html = Get-Content $hubPage -Raw
$html = $html -replace '(?=</style>)', ($css + "`r`n")
Set-Content -Path $hubPage -Value $html -Encoding UTF8 -NoNewline

([regex]::Matches((Get-Content $hubPage -Raw), 'help-card')).Count
```

Should report a non-zero count.

---

## Part 5 — Insert the HTML

Inserted immediately before `</main>`, so it sits beneath the tile grid regardless of how the tiles have been edited.

```powershell
Mark "Part 5 - insert HTML"

$section = @'
        <section class="help-section">
            <h2>Help and support</h2>
            <p class="help-intro">Guides and where to go if something isn't working.</p>

            <div class="help-grid">
                <a class="help-card" href="docs/SWP-Signage-User-Guide.pdf" target="_blank" rel="noopener">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                        <line x1="8" y1="13" x2="16" y2="13" />
                        <line x1="8" y1="17" x2="13" y2="17" />
                    </svg>
                    <span>
                        <span class="help-title">User guide</span>
                        <span class="help-sub">How to add, edit and remove messages</span>
                    </span>
                </a>

                <a class="help-card pending" href="#">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="9" />
                        <path d="M9.1 9a3 3 0 1 1 4.2 2.8c-.8.4-1.3 1-1.3 1.9v.3" />
                        <line x1="12" y1="17.5" x2="12" y2="17.51" />
                    </svg>
                    <span>
                        <span class="help-title">Request access</span>
                        <span class="help-sub">Ask the Service Desk to add you to your team's group</span>
                    </span>
                </a>

                <a class="help-card pending" href="#">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M10.3 3.6 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z" />
                        <line x1="12" y1="9" x2="12" y2="13" />
                        <line x1="12" y1="17" x2="12" y2="17.01" />
                    </svg>
                    <span>
                        <span class="help-title">Report a problem</span>
                        <span class="help-sub">Raise a ticket with the ICT Service Desk</span>
                    </span>
                </a>
            </div>
        </section>

'@

$html = Get-Content $hubPage -Raw
$html = $html -replace '(?=</main>)', $section
Set-Content -Path $hubPage -Value $html -Encoding UTF8 -NoNewline

([regex]::Matches((Get-Content $hubPage -Raw), 'help-section')).Count
```

Should report **3** — one in the CSS, one in the opening tag, one in the closing tag.

---

## Part 6 — Verify

```powershell
Mark "Part 6 - verify"

# Structure still intact
$html = Get-Content $hubPage -Raw
"</style> : " + ([regex]::Matches($html, '</style>').Count)
"</main>  : " + ([regex]::Matches($html, '</main>').Count)
"</body>  : " + ([regex]::Matches($html, '</body>').Count)
"tiles    : " + ([regex]::Matches($html, 'class="tile"').Count)

# The PDF is reachable
curl.exe -I https://swpapp-digisign.swp-rest.police.int/feedhub/docs/SWP-Signage-User-Guide.pdf
```

Required: each closing tag count **1**, four tiles still present, and the PDF returning `200`.

A **404** on the PDF means the filename does not match. A **500.19** or a MIME error means the file type is not in the IIS MIME map — see Part 7.

### Browser checks

| Check | Expected |
|---|---|
| `https://swpapp-digisign.swp-rest.police.int/feedhub/` | Four tiles unchanged, help section beneath them |
| The two placeholder cards | Visibly faded |
| Click "User guide" | PDF opens in a new tab |
| Narrow the browser window | Cards wrap rather than overflowing |

---

## Part 7 — If the PDF does not serve

Only needed if Part 6 returned a MIME error. PDF is usually present by default.

```powershell
Get-WebConfiguration -PSPath "IIS:\Sites\SWPDigiSign" `
  -Filter "/system.webServer/staticContent/mimeMap[@fileExtension='.pdf']"
```

If nothing is returned, add it scoped to this site only — not server-wide:

```powershell
Add-WebConfigurationProperty -PSPath "IIS:\" -Location "SWPDigiSign" `
  -Filter "/system.webServer/staticContent" -Name "." `
  -Value @{fileExtension='.pdf'; mimeType='application/pdf'}
```

---

## Part 8 — Stop the transcript

```powershell
Mark "Change complete"

"--- Final state ---"
Get-ChildItem $hubRoot -Recurse -File | Select-Object FullName, Length, LastWriteTime

"Outcome: <completed | backed out>"
"Notes  : <anything that deviated>"
"Ended  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Stop-Transcript
```

---

## Back-out

Restore the backup. No recycle, no restart.

```powershell
Copy-Item "$deployRoot\hub-backup\index.html.$stamp" $hubPage -Force
Get-Item $hubPage | Select-Object LastWriteTime, Length
```

Refresh the browser to confirm. The `docs` folder can be left in place; it is unreachable from the page once the section is gone.

---

## Wiring up the placeholders later

When you have the Service Desk URLs, edit `index.html` directly:

1. Find the card — search for `Request access` or `Report a problem`
2. Replace `href="#"` with the real URL
3. Remove ` pending` from the `class` attribute so it stops rendering faded

Saving the file is the deployment. Nothing else to do.

---

## Adding another document later

1. Put the PDF in `E:\inetpub\wwwroot\icthub\docs\`
2. Copy an existing `<a class="help-card">` block in `index.html`
3. Change the `href`, the title and the subtitle

Keep documents intended for a technical audience — the Technical Documentation, the runbooks — off this page. The Hub is the users' front door, and a link to a deployment runbook invites questions nobody wants to field.

---

## Note for the record

This change is additive and confined to one static page and one new folder. No application, application pool, binding or configuration is modified, and no other site on the server is affected.
