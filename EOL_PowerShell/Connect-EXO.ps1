<#
.SYNOPSIS
    Connects to Exchange Online and verifies access by testing mailbox retrieval.

.DESCRIPTION
    This script connects to Exchange Online using the specified admin account and
    validates the connection by attempting to retrieve a test mailbox. It provides
    color-coded feedback indicating success, partial success (connected but test
    mailbox not found), or failure.

.NOTES
    Requires the ExchangeOnlineManagement module to be installed.
    Update $AdminUPN and $TestMailbox variables before running.
.EXMPLE
"C:\Program Files\PowerShell\7\pwsh.exe" -NoExit -File "C:\Scripts\Connect-EXO.ps1"
#>

$AdminUPN     = "admin@contoso.com"
$TestMailbox  = "someone@contoso.com"
$SuccessText  = "Connected to EXO and PIM'd up"

Import-Module ExchangeOnlineManagement

try {
    Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ShowBanner:$false -ErrorAction Stop

    $mbx = Get-EXOMailbox -Identity $TestMailbox -ErrorAction Stop
    if ($null -ne $mbx) {
        Write-Host $SuccessText -ForegroundColor Green
    }
}
catch {
    $msg = $_.Exception.Message
    if ($msg -match "Couldn't find object|cannot be found|doesn't exist") {
        Write-Host "Connected OK, but test mailbox not found: $TestMailbox" -ForegroundColor Yellow
    } else {
        Write-Host "Not connected / no access / other failure: $msg" -ForegroundColor Red
    }
}
