# Run locally on each Exchange server

try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
} catch {
    Write-Host "Secure Boot is not available or not enabled on this machine." -ForegroundColor Red
    exit
}

Write-Host "`nServer: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Secure Boot Enabled: $secureBoot" -ForegroundColor Green

Write-Host "`n--- db (Allowed Certificates) ---" -ForegroundColor Yellow
$db = Get-SecureBootUEFI -Name db
Write-Host "db store size: $($db.Bytes.Length) bytes"

Write-Host "`n--- KEK ---" -ForegroundColor Yellow
$kek = Get-SecureBootUEFI -Name KEK
Write-Host "KEK store size: $($kek.Bytes.Length) bytes"

Write-Host "`n--- dbx (Revocation List) ---" -ForegroundColor Yellow
$dbx = Get-SecureBootUEFI -Name dbx
Write-Host "dbx store size: $($dbx.Bytes.Length) bytes"
