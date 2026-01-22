# AI Prompt: PowerShell Script (Exchange Online Admin 365) — Read/Write

Use this prompt to generate a **new PowerShell 5.1 compatible** script for **Microsoft 365 Exchange Online** administration that supports **read + write** operations safely and efficiently.

---

## Objective

Create a **new PowerShell script** (Version **0.1**) intended for an Exchange Admin to run against **Exchange Online (Microsoft 365)**. The script must be optimized for performance and safe change handling, and structured so it’s easy to maintain with minimal complexity.

The main purpose of the script is to:
> **[INSERT YOUR PURPOSE HERE — e.g., “audit and update mailbox settings in bulk with delta processing and a change report”]**

---

## Mandatory Requirements

### Documentation Header (Required Sections)
The script MUST include comment-based help with these headings:

- **SYNOPSIS**
- **DESCRIPTION**
- **OUTPUTS**
- **NOTES**
- **EXAMPLE**
- **CHANGELOG**

---

## Technical + Design Requirements

### Performance + Data Handling
- MUST use **hashtables** to speed up lookups and data handling.
- MUST use **ExchangeGuid** as the primary identifier wherever possible for speed and accuracy (not SMTP address as the primary key unless unavoidable).
- MUST implement **delta processing**:
  - Only process objects that have changed since the last run (or compared to a previous state).
  - Store and reuse state in a local file (e.g., JSON/CSV) to detect changes.
- MUST avoid heavy repeated calls:
  - Pull data once into memory, then work from the in-memory dataset.

### Exchange Online Connection / Commands
- Must only use **relative commands** and **load/import them upon connecting** to Exchange.
  - Connect using `Connect-ExchangeOnline`.
  - Import/ensure required cmdlets are available after connection (do not assume the session is already loaded).

### Timing + Output
- Must start a **Stopwatch** at the beginning and stop at the end.
- Output duration at completion in **minutes and seconds** (e.g., `03m 12s`).

### Compatibility + Formatting
- Must be **PowerShell 5.1 compatible** (no PS7-only syntax/features).
- Must use **UK date format** (`dd/MM/yyyy`) in any logs and file names where dates appear.
- Must keep **minimal use/creation of functions** (prefer inline logic, but remain readable).

### Maintainability
- Must use **comment regions** for quick edits, such as:
  - Configuration
  - Input / Filters
  - Exchange Connection
  - Data Collection
  - Delta Logic
  - Write Actions
  - Reporting / Export
  - Cleanup

### Safety + Write Controls (Read/Write Script)
- Include a clear **WhatIf/Dry Run mode** option (default to safe/dry-run unless explicitly turned off).
- Include confirm prompts or a “requires explicit switch to commit” pattern.
- Include robust error handling and clear status output.

---

## Outputs

The script MUST output at minimum:
- Summary counts (total objects read, changed objects, updated objects, skipped objects, failed objects).
- A timestamped run log line using UK date format.

---

## Example Usage (Required)
Provide at least one **EXAMPLE** showing how to run:
- Default safe mode
- Explicit commit mode

---

## Changelog (Required)
Include a simple changelog section starting with:

- **0.1** — Initial version

---

## Implementation Guidance

When generating the script:
- Prefer `Get-EXOMailbox` for mailbox inventory (or relevant EXO cmdlets depending on the main purpose).
- Use `-ResultSize Unlimited` only when necessary; otherwise filter early.
- Use a hashtable keyed on **ExchangeGuid** for lookups.
- Keep the script readable without building a full module.
- Avoid excessive functions; if any are used, keep them very small and essential.

---

## Deliverable

Return:
1) A single PowerShell script file content (ready to paste into `*.ps1`)
2) With comment-based help at the top including the required sections
3) Following every requirement above exactly

---
