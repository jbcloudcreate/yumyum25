$siteUrl = "https://southwalespolice-my.sharepoint.com/personal/geraint_morgan_south_wales_police_uk"
$listTitle = "PASF"
$downloadPath = "C:\Temp\SPImages"

New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null

# Create session
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# Trigger login via browser-style request
Invoke-WebRequest -Uri $siteUrl -WebSession $session -UseDefaultCredentials

# Now call API using session cookies
$itemsUrl = "$siteUrl/_api/web/lists/GetByTitle('$listTitle')/items?`$select=Id,AttachmentFiles&`$expand=AttachmentFiles"

$response = Invoke-RestMethod -Uri $itemsUrl -WebSession $session -Headers @{Accept="application/json;odata=verbose"}

foreach ($item in $response.d.results) {
    foreach ($attachment in $item.AttachmentFiles.results) {

        $fileUrl = $siteUrl + $attachment.ServerRelativeUrl
        $fileName = $attachment.FileName
        $outFile = Join-Path $downloadPath $fileName

        Write-Host "Downloading $fileName..."

        Invoke-WebRequest -Uri $fileUrl -OutFile $outFile -WebSession $session
    }
}

Write-Host "Completed."
