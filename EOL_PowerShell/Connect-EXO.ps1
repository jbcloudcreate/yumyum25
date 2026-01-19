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
