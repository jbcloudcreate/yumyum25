<#
.SYNOPSIS
    Decommissions a user mailbox by moving to deactivated OU and updating AD attributes.

.DESCRIPTION
    This script performs the AD-side tasks for mailbox decommissioning:
    - Prompts for user identity and helpdesk reference
    - Moves user to the specified Deactivated OU
    - Appends "(Deactivated)" to the display name and CN (name shown in OU)
    - Updates telephone notes (info attribute) with deactivation details

.EXAMPLE
    .\Invoke-MailboxDecommission.ps1
#>

#-----------------------------------------
# CONFIGURATION - UPDATE THIS PATH
#-----------------------------------------
$DeactivatedOU = "OU=Deactivated Users,OU=Users,DC=yourdomain,DC=int"
#-----------------------------------------

# Import AD module if not already loaded
if (-not (Get-Module -Name ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to import ActiveDirectory module: $_"
        exit 1
    }
}

# Get the current user running the script
$RunningUser = $env:USERNAME
$DeactivationDate = Get-Date -Format "yyyy-MM-dd HH:mm"

# Prompt for required information
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Mailbox Decommission Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

do {
    $Identity = Read-Host "`nEnter the AD Account Name (SAMAccountName)"
    if ([string]::IsNullOrWhiteSpace($Identity)) {
        Write-Warning "AD Account Name cannot be empty. Please try again."
    }
} while ([string]::IsNullOrWhiteSpace($Identity))

do {
    $HelpdeskReference = Read-Host "Enter the Helpdesk Reference"
    if ([string]::IsNullOrWhiteSpace($HelpdeskReference)) {
        Write-Warning "Helpdesk Reference cannot be empty. Please try again."
    }
} while ([string]::IsNullOrWhiteSpace($HelpdeskReference))

Write-Host "`n----------------------------------------" -ForegroundColor Gray
Write-Host "Processing: $Identity" -ForegroundColor Cyan
Write-Host "Helpdesk Ref: $HelpdeskReference" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Gray

try {
    # Get the user object
    $User = Get-ADUser -Identity $Identity -Properties DisplayName, Name, info, DistinguishedName -ErrorAction Stop
    
    Write-Host "`nFound user: $($User.DisplayName) ($($User.SamAccountName))" -ForegroundColor Green
    Write-Host "Current OU: $($User.DistinguishedName -replace '^CN=[^,]+,')" -ForegroundColor Gray

    # Confirm before proceeding
    Write-Host "`nYou are about to decommission this user:" -ForegroundColor Yellow
    Write-Host "  Display Name: $($User.DisplayName)"
    Write-Host "  SAM Account:  $($User.SamAccountName)"
    Write-Host "  Target OU:    $DeactivatedOU"
    
    $Confirm = Read-Host "`nProceed? (Y/N)"
    if ($Confirm -notmatch '^[Yy]') {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        exit 0
    }

    # Check if already in deactivated OU
    if ($User.DistinguishedName -like "*$DeactivatedOU*") {
        Write-Warning "User is already in the Deactivated OU. Skipping move."
        $AlreadyDeactivated = $true
    }
    else {
        $AlreadyDeactivated = $false
    }

    # Prepare the new display name
    $CurrentDisplayName = $User.DisplayName
    if ($CurrentDisplayName -notlike "*(Deactivated)*") {
        $NewDisplayName = "$CurrentDisplayName (Deactivated)"
    }
    else {
        $NewDisplayName = $CurrentDisplayName
        Write-Warning "Display name already contains (Deactivated)"
    }

    # Prepare the new CN (Name shown in OU list)
    $CurrentName = $User.Name
    if ($CurrentName -notlike "*(Deactivated)*") {
        $NewName = "$CurrentName (Deactivated)"
    }
    else {
        $NewName = $CurrentName
        Write-Warning "Name already contains (Deactivated)"
    }

    # Prepare the telephone notes (info attribute) update
    $NoteEntry = "Deactivated: $DeactivationDate | Ref: $HelpdeskReference | By: $RunningUser"
    
    if ([string]::IsNullOrWhiteSpace($User.info)) {
        $NewInfo = $NoteEntry
    }
    else {
        $NewInfo = "$($User.info)`r`n$NoteEntry"
    }

    # Display planned changes
    Write-Host "`nApplying Changes..." -ForegroundColor Yellow

    # Update AD attributes (DisplayName and info)
    Set-ADUser -Identity $User.DistinguishedName -Replace @{
        DisplayName = $NewDisplayName
        info        = $NewInfo
    } -ErrorAction Stop
    
    Write-Host "[OK] Updated display name: '$NewDisplayName'" -ForegroundColor Green
    Write-Host "[OK] Updated telephone notes" -ForegroundColor Green

    # Rename the object (CN) if not already deactivated
    if ($CurrentName -notlike "*(Deactivated)*") {
        Rename-ADObject -Identity $User.DistinguishedName -NewName $NewName -ErrorAction Stop
        Write-Host "[OK] Updated name (CN): '$NewName'" -ForegroundColor Green
        
        # Update the DN for the move operation (CN has changed)
        $UpdatedDN = "CN=$NewName,$($User.DistinguishedName -replace '^CN=[^,]+,')"
    }
    else {
        $UpdatedDN = $User.DistinguishedName
    }

    if (-not $AlreadyDeactivated) {
        # Move user to deactivated OU
        Move-ADObject -Identity $UpdatedDN -TargetPath $DeactivatedOU -ErrorAction Stop
        Write-Host "[OK] Moved user to Deactivated OU" -ForegroundColor Green
    }

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  DECOMMISSION COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "User:         $($User.SamAccountName)"
    Write-Host "Helpdesk Ref: $HelpdeskReference"
    Write-Host "Processed By: $RunningUser"
    Write-Host "Date/Time:    $DeactivationDate"
    Write-Host "========================================`n" -ForegroundColor Green

}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Host "`n[ERROR] User '$Identity' not found in Active Directory" -ForegroundColor Red
}
catch {
    Write-Host "`n[ERROR] Failed to process user '$Identity'" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Ask if user wants to process another
$Another = Read-Host "Process another user? (Y/N)"
if ($Another -match '^[Yy]') {
    & $PSCommandPath
}
