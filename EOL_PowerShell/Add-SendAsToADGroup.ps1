<#
.SYNOPSIS
    Adds Send As trustees from a text file to an on-prem AD group.

.DESCRIPTION
    Reads a flat list of UPNs from the Send As report, resolves each to an
    AD user object, and adds them to the specified AD group.
    Use -WhatIf to preview changes before committing.

.PARAMETER InputFile
    Path to the flat list text file produced by Get-SendAsPermissions.ps1

.PARAMETER GroupName
    The SamAccountName or distinguished name of the target AD group.

.PARAMETER WhatIf
    Preview what would happen without making any changes.

.EXAMPLE
    .\Add-SendAsToADGroup.ps1 -InputFile "C:\Reports\SendAs.txt" -GroupName "SG_SharedMailbox_SendAs" -WhatIf
    .\Add-SendAsToADGroup.ps1 -InputFile "C:\Reports\SendAs.txt" -GroupName "SG_SharedMailbox_SendAs"
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [string]$InputFile,

    [Parameter(Mandatory = $true)]
    [string]$GroupName
)

# --- Verify input file exists ---
if (-not (Test-Path -Path $InputFile)) {
    Write-Host "Input file not found: $InputFile" -ForegroundColor Red
    exit 1
}

# --- Verify the target group exists ---
try {
    $adGroup = Get-ADGroup -Identity $GroupName -ErrorAction Stop
    Write-Host "Target group found: $($adGroup.DistinguishedName)" -ForegroundColor Cyan
} catch {
    Write-Host "AD group not found: $GroupName" -ForegroundColor Red
    exit 1
}

# --- Read UPNs from file ---
$upns = Get-Content -Path $InputFile | Where-Object { $_ -match '\S' }

if (-not $upns) {
    Write-Host "No entries found in input file." -ForegroundColor Yellow
    exit
}

Write-Host "Processing $($upns.Count) trustee(s)..." -ForegroundColor Cyan

$resolved   = [System.Collections.Generic.List[object]]::new()
$unresolved = [System.Collections.Generic.List[string]]::new()

# --- Resolve each UPN to an AD user object ---
foreach ($upn in $upns) {
    try {
        $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" -ErrorAction Stop

        if ($adUser) {
            $resolved.Add($adUser)
            Write-Host "  [OK]       $upn" -ForegroundColor Green
        } else {
            $unresolved.Add($upn)
            Write-Host "  [NOT FOUND] $upn" -ForegroundColor Yellow
        }
    } catch {
        $unresolved.Add($upn)
        Write-Host "  [ERROR]    $upn — $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Add resolved users to group ---
if ($resolved.Count -gt 0) {
    Write-Host "`nAdding $($resolved.Count) user(s) to '$GroupName'..." -ForegroundColor Cyan

    foreach ($user in $resolved) {
        if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, "Add to AD group '$GroupName'")) {
            try {
                Add-ADGroupMember -Identity $GroupName -Members $user -ErrorAction Stop
                Write-Host "  [ADDED]  $($user.UserPrincipalName)" -ForegroundColor Green
            } catch {
                Write-Host "  [FAILED] $($user.UserPrincipalName) — $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# --- Summary ---
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host "Successfully resolved : $($resolved.Count)" -ForegroundColor Green
Write-Host "Unresolved/skipped    : $($unresolved.Count)" -ForegroundColor $(if ($unresolved.Count -gt 0) { 'Yellow' } else { 'Green' })

if ($unresolved.Count -gt 0) {
    Write-Host "`nUnresolved UPNs:" -ForegroundColor Yellow
    $unresolved | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}
