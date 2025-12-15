<# 
.SYNOPSIS
    Disable a shared mailbox in Exchange Online with friendly prompts.

.DESCRIPTION
    - Prompts for mailbox identifier.
    - Appends a baked-in default domain if only local-part is entered.
    - Connects to EXO (installs module if missing).
    - Shows existing Full Access delegates BEFORE proceeding (sense check).
    - Hides mailbox from Global Address List.

.NOTES
    Author: James Buller
#>

#region Config
#-----------------------------------------
# CONFIGURATION - UPDATE THIS VALUE
#-----------------------------------------
$DefaultDomain = "yourdomain.com"   # <-- bake in your domain here (without @)
#-----------------------------------------
#endregion

function Ensure-EXOModule {
    if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
        Write-Host "Installing ExchangeOnlineManagement module..." -ForegroundColor Yellow
        try {
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to install ExchangeOnlineManagement: $($_.Exception.Message)"
            exit 1
        }
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
}

function Ensure-EXOConnection {
    try {
        Get-EXORecipient -ResultSize 1 -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
        Connect-ExchangeOnline -ShowProgress $true
    }
}

function Resolve-UPN {
    param(
        [Parameter(Mandatory)]
        [string]$InputValue,
        [Parameter(Mandatory)]
        [string]$DefaultDomain
    )
    if ($InputValue -match '@') { return $InputValue.Trim() }
    return "$($InputValue.Trim())@$DefaultDomain"
}

# -------------------- MAIN --------------------

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Disable Shared Mailbox (Exchange Online)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Default domain: $DefaultDomain" -ForegroundColor DarkCyan

# Prompt for mailbox
do {
    $mbxInput = Read-Host "`nEnter the mailbox to disable (local-part or full UPN)"
    if ([string]::IsNullOrWhiteSpace($mbxInput)) {
        Write-Warning "Mailbox cannot be empty. Please try again."
    }
} while ([string]::IsNullOrWhiteSpace($mbxInput))

# Expand to UPN using default domain if no '@' entered
$MailboxUPN = Resolve-UPN -InputValue $mbxInput -DefaultDomain $DefaultDomain

Write-Host "`nMailbox: $MailboxUPN" -ForegroundColor Green

# Ensure module + connection
Ensure-EXOModule
Ensure-EXOConnection

# Validate mailbox exists
try {
    $mbx = Get-Mailbox -Identity $MailboxUPN -ErrorAction Stop
    Write-Host "`n[OK] Mailbox found: $($mbx.DisplayName)" -ForegroundColor Green
    Write-Host "     Type: $($mbx.RecipientTypeDetails)"
    Write-Host "     Primary SMTP: $($mbx.PrimarySmtpAddress)"
}
catch {
    Write-Error "Mailbox not found: $MailboxUPN"
    exit 1
}

# --- Show current Full Access delegates (sense check) ---
Write-Host "`n----------------------------------------" -ForegroundColor Gray
Write-Host "Full Access Delegates on ${MailboxUPN}:" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Gray
try {
    $fullAccess = Get-MailboxPermission -Identity $MailboxUPN -ErrorAction Stop |
        Where-Object {
            $_.AccessRights -contains 'FullAccess' -and
            -not $_.IsInherited -and
            -not $_.Deny -and
            $_.User -ne 'NT AUTHORITY\SELF'
        } |
        Select-Object @{n='Delegate';e={$_.User}}, AccessRights |
        Sort-Object Delegate

    if ($fullAccess -and @($fullAccess).Count -gt 0) {
        $fullAccess | Format-Table -AutoSize
    }
    else {
        Write-Host "No explicit Full Access delegates found.`n" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Could not read Full Access permissions: $($_.Exception.Message)"
}

# Confirm proceed
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  SENSE CHECK COMPLETE" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Review the delegates above before proceeding.`n"

$Confirm = Read-Host "Proceed to DISABLE mailbox ${MailboxUPN}? (Y/N)"
if ($Confirm -notmatch '^[Yy]') {
    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
    exit 0
}

# Hide from GAL
Write-Host "`nDisabling mailbox..." -ForegroundColor Yellow
try {
    Set-Mailbox -Identity $MailboxUPN -HiddenFromAddressListsEnabled $true -ErrorAction Stop
    Write-Host "[OK] Mailbox hidden from Global Address List" -ForegroundColor Green
}
catch {
    Write-Error "Failed to disable mailbox: $($_.Exception.Message)"
    exit 1
}

# Final status
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  MAILBOX DISABLE COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$mbxFinal = Get-Mailbox -Identity $MailboxUPN
Write-Host "Mailbox:         $($mbxFinal.DisplayName)"
Write-Host "Type:            $($mbxFinal.RecipientTypeDetails)"
Write-Host "Hidden from GAL: $($mbxFinal.HiddenFromAddressListsEnabled)"
Write-Host "========================================`n" -ForegroundColor Green

# Ask if user wants to process another
$Another = Read-Host "Process another mailbox? (Y/N)"
if ($Another -match '^[Yy]') {
    & $PSCommandPath
}

Write-Host "Done." -ForegroundColor Green
