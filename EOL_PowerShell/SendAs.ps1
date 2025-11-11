<# 
.SYNOPSIS
    Grant "Send As" permission in Exchange Online with prompts.

.DESCRIPTION
    - Prompts for mailbox and user identifiers.
    - If local-parts are entered, appends the default domain (configurable).
    - Connects to EXO (installs module if missing).
    - Validates both objects exist.
    - Skips if permission already present.
    - Displays resulting Send As permissions.

.NOTES
    Author: PowerShell 🔨🤖🔧
#>

#region Config
$DefaultDomain = "test.com"   # <-- bake in your domain here
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
        # Try a benign cmdlet to see if we're connected
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

function Get-SendAsEntry {
    param(
        [Parameter(Mandatory)][string]$MailboxUPN,
        [Parameter(Mandatory)][string]$TrusteeIdentity
    )
    # Normalize trustee text for comparison after lookup
    $trusteeObj = Get-Recipient -Identity $TrusteeIdentity -ErrorAction SilentlyContinue
    $trusteeCandidates = @()
    if ($trusteeObj) {
        # Trustee often appears as DisplayName or canonical identity in Get-RecipientPermission
        $trusteeCandidates += $trusteeObj.DisplayName
        $trusteeCandidates += $trusteeObj.Name
        $trusteeCandidates += $trusteeObj.Identity
        if ($trusteeObj.PrimarySmtpAddress) { $trusteeCandidates += $trusteeObj.PrimarySmtpAddress.ToString() }
        if ($trusteeObj.Alias) { $trusteeCandidates += $trusteeObj.Alias }
    }
    $trusteeCandidates = $trusteeCandidates | Where-Object { $_ } | Select-Object -Unique

    $perms = Get-RecipientPermission -Identity $MailboxUPN -ErrorAction SilentlyContinue |
             Where-Object { $_.AccessRights -contains 'SendAs' }

    if (-not $perms) { return $null }

    if ($trusteeCandidates.Count -gt 0) {
        return $perms | Where-Object { $trusteeCandidates -contains $_.Trustee }
    } else {
        # Fallback: try direct match on provided string
        return $perms | Where-Object { $_.Trustee -eq $TrusteeIdentity }
    }
}

# -------------------- MAIN --------------------

Write-Host "=== Grant 'Send As' Permission (Exchange Online) ===" -ForegroundColor Cyan
Write-Host "Default domain for local-parts: $DefaultDomain" -ForegroundColor DarkCyan

# Prompts
$mbxInput  = Read-Host "Enter the mailbox (local-part or full UPN)"
$userInput = Read-Host "Enter the user to grant (local-part or full UPN)"

# Expand to UPNs using default domain if no '@' entered
$MailboxUPN = Resolve-UPN -InputValue $mbxInput -DefaultDomain $DefaultDomain
$UserUPN    = Resolve-UPN -InputValue $userInput -DefaultDomain $DefaultDomain

Write-Host ""
Write-Host "Mailbox: $MailboxUPN" -ForegroundColor Green
Write-Host "Grant to: $UserUPN"   -ForegroundColor Green
$confirm = Read-Host "Proceed to grant Send As? (Y/N)"
if ($confirm -notin @('Y','y','Yes','yes')) { Write-Host "Aborted." -ForegroundColor Yellow; exit }

# Ensure module + connection
Ensure-EXOModule
Ensure-EXOConnection

# Validate mailbox and user
try {
    $mbx = Get-Recipient -Identity $MailboxUPN -ErrorAction Stop
} catch {
    Write-Error "Mailbox recipient not found: $MailboxUPN"
    exit 1
}

try {
    $usr = Get-Recipient -Identity $UserUPN -ErrorAction Stop
} catch {
    Write-Error "User recipient not found: $UserUPN"
    exit 1
}

# Check if permission already exists
$existing = Get-SendAsEntry -MailboxUPN $MailboxUPN -TrusteeIdentity $UserUPN
if ($existing) {
    Write-Host "'Send As' already granted to $UserUPN on $MailboxUPN. No changes made." -ForegroundColor Yellow
} else {
    Write-Host "Granting 'Send As' to $UserUPN on $MailboxUPN ..." -ForegroundColor Cyan
    try {
        Add-RecipientPermission -Identity $MailboxUPN -Trustee $UserUPN -AccessRights SendAs -Confirm:$false -ErrorAction Stop
        Write-Host "Success ✔️" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to add Send As permission: $($_.Exception.Message)"
        exit 1
    }
}

# Show current Send As permissions for the mailbox
Write-Host ""
Write-Host "Current Send As entries on $MailboxUPN:" -ForegroundColor Cyan
try {
    Get-RecipientPermission -Identity $MailboxUPN -ErrorAction Stop |
        Where-Object { $_.AccessRights -contains 'SendAs' } |
        Select-Object @{n='Mailbox';e={$MailboxUPN}}, Trustee, AccessRights, IsInherited |
        Sort-Object Trustee |
        Format-Table -AutoSize
}
catch {
    Write-Error "Could not read recipient permissions for $MailboxUPN: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
