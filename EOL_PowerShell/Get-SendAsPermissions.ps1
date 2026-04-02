<#
.SYNOPSIS
    Exports a flat list of 'Send As' trustees for a specified mailbox to a text file.

.PARAMETER Mailbox
    The UPN, alias, display name, or email address of the target mailbox.

.PARAMETER OutputPath
    Full path for the output text file. Defaults to the current directory.

.EXAMPLE
    .\Get-SendAsPermissions.ps1 -Mailbox "shared@swp.police.uk"
    .\Get-SendAsPermissions.ps1 -Mailbox "shared@swp.police.uk" -OutputPath "C:\Reports\SendAs.txt"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Mailbox,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\SendAs_$(Get-Date -Format 'yyyy-MM-dd_HHmm').txt"
)

Write-Host "Querying Send As permissions for: $Mailbox" -ForegroundColor Cyan

$trustees = Get-RecipientPermission -Identity $Mailbox |
    Where-Object {
        $_.Trustee -notlike "NT AUTHORITY\SELF" -and
        $_.Trustee -notmatch '^S-1-5-'
    } |
    Select-Object -ExpandProperty Trustee

if (-not $trustees) {
    Write-Host "No Send As permissions found for '$Mailbox'." -ForegroundColor Yellow
    exit
}

# Write flat list to file
$trustees | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Done. $($trustees.Count) trustee(s) written to: $OutputPath" -ForegroundColor Green
