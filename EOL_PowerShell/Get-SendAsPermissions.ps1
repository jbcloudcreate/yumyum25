<#
.SYNOPSIS
    Exports 'Send As' permissions for a specified mailbox to a text file.

.DESCRIPTION
    Retrieves all trustees granted 'Send As' permission on the target mailbox
    and writes the results to a plain text file.

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

# Retrieve Send As permissions — exclude the system 'NT AUTHORITY\SELF' entry
$sendAsPerms = Get-RecipientPermission -Identity $Mailbox |
    Where-Object { $_.Trustee -notlike "NT AUTHORITY\SELF" }

if (-not $sendAsPerms) {
    Write-Host "No Send As permissions found for '$Mailbox'." -ForegroundColor Yellow
    exit
}

# Build output content
$lines = @()
$lines += "Send As Permissions Report"
$lines += "=========================="
$lines += "Mailbox   : $Mailbox"
$lines += "Generated : $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
$lines += ""
$lines += "{0,-40} {1,-30} {2}" -f "Trustee", "Access Rights", "Inherited"
$lines += "{0,-40} {1,-30} {2}" -f "-------", "-------------", "---------"

foreach ($perm in $sendAsPerms) {
    $lines += "{0,-40} {1,-30} {2}" -f $perm.Trustee, ($perm.AccessRights -join ", "), $perm.IsInherited
}

$lines += ""
$lines += "Total entries: $($sendAsPerms.Count)"

# Write to file
$lines | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Done. $($sendAsPerms.Count) trustee(s) found." -ForegroundColor Green
Write-Host "Output written to: $OutputPath" -ForegroundColor Green
