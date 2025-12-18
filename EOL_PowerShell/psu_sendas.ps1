<#
.SYNOPSIS
  Grant Send As permission in Exchange Online and capture "before/after" evidence
  for Full Access and Send As permissions in PowerShell Universal job output.

.NOTES
  - Fill in $exoSplat with your Connect-ExchangeOnline settings (cert/app, etc.)
  - In PSU, prefer storing secrets in $Secret:* and building $exoSplat from those
#>

param(
  [Parameter(Mandatory)]
  [string]$MailboxUPN,

  [Parameter(Mandatory)]
  [string]$TrusteeUPN,

  [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-FullAccessEvidence {
  param([Parameter(Mandatory)][string]$Identity)

  Get-MailboxPermission -Identity $Identity |
    Where-Object {
      $_.AccessRights -contains "FullAccess" -and
      -not $_.IsInherited -and
      $_.User -notlike "NT AUTHORITY\SELF"
    } |
    Select-Object Identity, User, AccessRights, Deny, IsInherited
}

function Get-SendAsEvidence {
  param([Parameter(Mandatory)][string]$Identity)

  Get-RecipientPermission -Identity $Identity |
    Where-Object {
      $_.AccessRights -contains "SendAs" -and
      $_.Trustee -notlike "NT AUTHORITY\SELF"
    } |
    Select-Object Identity, Trustee, AccessRights, Deny, IsInherited
}

Write-Information "=== Starting Send As grant (PSU) ===" -InformationAction Continue
Write-Information "Mailbox: $MailboxUPN" -InformationAction Continue
Write-Information "Trustee: $TrusteeUPN" -InformationAction Continue
Write-Information "WhatIf : $WhatIf" -InformationAction Continue

# --- Connect to EXO (fill in your splat) ---
$exoSplat = @{
  # e.g.
  # AppId                 = $Secret:EXO_AppId
  # Organization          = $Secret:EXO_Org
  # CertificateThumbprint = $Secret:EXO_CertThumb
  # ShowBanner            = $false
}

Connect-ExchangeOnline @exoSplat

try {
  # --- BEFORE evidence ---
  Write-Information "=== BEFORE: Full Access ===" -InformationAction Continue
  $beforeFullAccess = Get-FullAccessEvidence -Identity $MailboxUPN
  $beforeFullAccess   # Output objects (PSU will render as table)

  Write-Information "=== BEFORE: Send As ===" -InformationAction Continue
  $beforeSendAs = Get-SendAsEvidence -Identity $MailboxUPN
  $beforeSendAs     # Output objects

  # --- Grant Send As ---
  Write-Information "=== ACTION: Add Send As ===" -InformationAction Continue

  # If it's already present, Add-RecipientPermission can error.
  $already = $beforeSendAs | Where-Object { $_.Trustee -eq $TrusteeUPN }
  if ($already) {
    Write-Information "Send As already present for $TrusteeUPN on $MailboxUPN. No change made." -InformationAction Continue
  }
  else {
    Add-RecipientPermission -Identity $MailboxUPN -Trustee $TrusteeUPN -AccessRights SendAs -Confirm:$false -WhatIf:$WhatIf
    Write-Information "Add-RecipientPermission executed." -InformationAction Continue
  }

  # --- AFTER evidence ---
  Write-Information "=== AFTER: Full Access ===" -InformationAction Continue
  $afterFullAccess = Get-FullAccessEvidence -Identity $MailboxUPN
  $afterFullAccess

  Write-Information "=== AFTER: Send As ===" -InformationAction Continue
  $afterSendAs = Get-SendAsEvidence -Identity $MailboxUPN
  $afterSendAs

  # --- Summary object for quick audit ---
  [pscustomobject]@{
    MailboxUPN               = $MailboxUPN
    TrusteeUPN               = $TrusteeUPN
    WhatIf                   = [bool]$WhatIf
    FullAccess_Before_Count  = @($beforeFullAccess).Count
    FullAccess_After_Count   = @($afterFullAccess).Count
    SendAs_Before_Count      = @($beforeSendAs).Count
    SendAs_After_Count       = @($afterSendAs).Count
    SendAs_Trustee_Present_After = [bool](@($afterSendAs | Where-Object Trustee -eq $TrusteeUPN).Count)
  }
}
finally {
  Disconnect-ExchangeOnline -Confirm:$false
  Write-Information "=== Finished ===" -InformationAction Continue
}
