<# 
.SYNOPSIS
    Grant "Full Access" (mailbox owner) permission in Exchange Online with friendly prompts.

.DESCRIPTION
    - Prompts for mailbox and user identifiers.
    - Appends a baked-in default domain if only local-parts are entered.
    - Connects to EXO (installs module if missing).
    - Shows existing Full Access delegates BEFORE proceeding (sense check).
    - Validates objects exist.
    - Skips if Full Access already present.
    - Adds Full Access and shows final state.

.NOTES
    Author: PowerShell Script
#>

#region Config
$DefaultDomain = "yourdomain.com"   # <-- bake in your domain here (without @)
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

function Get-FullAccessEntry {
    param(
        [Parameter(Mandatory)][string]$MailboxUPN,
        [Parameter(Mandatory)][string]$TrusteeIdentity
    )

    $trusteeObj = Get-Recipient -Identity $TrusteeIdentity -ErrorAction SilentlyContinue
    $trusteeCandidates = @()
    if ($trusteeObj) {
        $trusteeCandidates += $trusteeObj.DisplayName
        $trusteeCandidates += $trusteeObj.Name
        $trusteeCandidates += $trusteeObj.Identity
        if ($trusteeObj.PrimarySmtpAddress) { $trusteeCandidates += $trusteeObj.PrimarySmtpAddress.ToString() }
        if ($trusteeObj.Alias) { $trusteeCandidates += $trusteeObj.Alias }
    }
    $trusteeCandidates = $trusteeCandidates | Where-Object { $_ } | Select-Object -Unique

    $perms = Get-MailboxPermission -Identity $MailboxUPN -ErrorAction SilentlyContinue |
             Where-Object { 
                 $_.AccessRights -contains 'FullAccess' -and
                 -not $_.IsInherited -and
                 -not $_.Deny
             }

    if (-not $perms) { return $null }

    if ($trusteeCandidates.Count -gt 0) {
        return $perms | Where-Object { $trusteeCandidates -contains $_.User }
    } else {
        return $perms | Where-Object { $_.User -eq $TrusteeIdentity }
    }
}

# -------------------- MAIN --------------------

Write-Host "`n=== Grant 'Full Access' Permission (Exchange Online) ===" -ForegroundColor Cyan
Write-Host "Default domain for local-parts: $DefaultDomain" -ForegroundColor DarkCyan

# Prompts
do {
    $mbxInput = Read-Host "`nEnter the mailbox (local-part or full UPN)"
    if ([string]::IsNullOrWhiteSpace($mbxInput)) {
        Write-Warning "Mailbox cannot be empty. Please try again."
    }
} while ([string]::IsNullOrWhiteSpace($mbxInput))

do {
    $userInput = Read-Host "Enter the user to grant Full Access (local-part or full UPN)"
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        Write-Warning "User cannot be empty. Please try again."
    }
} while ([string]::IsNullOrWhiteSpace($userInput))

# Expand to UPNs using default domain if no '@' entered
$MailboxUPN = Resolve-UPN -InputValue $mbxInput -DefaultDomain $DefaultDomain
$UserUPN    = Resolve-UPN -InputValue $userInput -DefaultDomain $DefaultDomain

Write-Host ""
Write-Host "Mailbox:  $MailboxUPN" -ForegroundColor Green
Write-Host "Grant to: $UserUPN" -ForegroundColor Green

# Ensure module + connection
Ensure-EXOModule
Ensure-EXOConnection

# Validate mailbox
try {
    $mbx = Get-Mailbox -Identity $MailboxUPN -ErrorAction Stop
    Write-Host "`n[OK] Mailbox found: $($mbx.DisplayName)" -ForegroundColor Green
} catch {
    Write-Error "Mailbox not found: $MailboxUPN"
    exit 1
}

# Validate user
try {
    $usr = Get-Recipient -Identity $UserUPN -ErrorAction Stop
    Write-Host "[OK] User found: $($usr.DisplayName)" -ForegroundColor Green
} catch {
    Write-Error "User recipient not found: $UserUPN"
    exit 1
}

# --- Show current Full Access delegates (sense check) ---
Write-Host ""
Write-Host "Current Full Access delegates on ${MailboxUPN}:" -ForegroundColor Cyan
try {
    $fullAccess = Get-MailboxPermission -Identity $MailboxUPN -ErrorAction Stop |
        Where-Object {
            $_.AccessRights -contains 'FullAccess' -and
            -not $_.IsInherited -and
            -not $_.Deny -and
            $_.User -ne 'NT AUTHORITY\SELF'
        } |
        Select-Object @{n='Mailbox';e={$MailboxUPN}}, @{n='Delegate';e={$_.User}}, AccessRights |
        Sort-Object Delegate

    if ($fullAccess -and $fullAccess.Count -gt 0) {
        $fullAccess | Format-Table -AutoSize
    } else {
        Write-Host "No explicit Full Access delegates found.`n" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Could not read mailbox permissions for ${MailboxUPN}: $($_.Exception.Message)"
}

# Confirm proceed
$confirm = Read-Host "Proceed to grant Full Access to ${UserUPN} on ${MailboxUPN}? (Y/N)"
if ($confirm -notmatch '^[Yy]') { 
    Write-Host "Aborted." -ForegroundColor Yellow
    exit 0
}

# Check if Full Access already exists
$existing = Get-FullAccessEntry -MailboxUPN $MailboxUPN -TrusteeIdentity $UserUPN
if ($existing) {
    Write-Host "`n'Full Access' already granted to $UserUPN on $MailboxUPN. No changes made." -ForegroundColor Yellow
} else {
    Write-Host "`nGranting 'Full Access' to $UserUPN on $MailboxUPN ..." -ForegroundColor Cyan
    try {
        Add-MailboxPermission -Identity $MailboxUPN -User $UserUPN -AccessRights FullAccess -InheritanceType All -AutoMapping $true -ErrorAction Stop | Out-Null
        Write-Host "Success" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to add Full Access permission: $($_.Exception.Message)"
        exit 1
    }
}

# Show current Full Access permissions for the mailbox
Write-Host ""
Write-Host "Current Full Access entries on ${MailboxUPN}:" -ForegroundColor Cyan
try {
    Get-MailboxPermission -Identity $MailboxUPN -ErrorAction Stop |
        Where-Object {
            $_.AccessRights -contains 'FullAccess' -and
            -not $_.IsInherited -and
            -not $_.Deny -and
            $_.User -ne 'NT AUTHORITY\SELF'
        } |
        Select-Object @{n='Mailbox';e={$MailboxUPN}}, @{n='Delegate';e={$_.User}}, AccessRights |
        Sort-Object Delegate |
        Format-Table -AutoSize
}
catch {
    Write-Error "Could not read mailbox permissions for ${MailboxUPN}: $($_.Exception.Message)"
}

# Ask if user wants to process another
$Another = Read-Host "Process another? (Y/N)"
if ($Another -match '^[Yy]') {
    & $PSCommandPath
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
