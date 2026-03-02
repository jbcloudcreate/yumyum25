# ===== CONFIG =====
$siteUrl      = "https://southwalespolice-my.sharepoint.com/personal/geraint_morgan_south_wales_police_uk"
$listTitle    = "PASF"   # Exact list name
$downloadPath = "C:\Temp\SPImages"

# ===== SETUP =====
New-Item -ItemType Directory -Path $downloadPath -Force | Out-Null

Write-Host "Connecting to SharePoint..."
$cred = Get-Credential

# ===== GET ALL LIST ITEMS =====
$itemsUrl = "$siteUrl/_api/web/lists/GetByTitle('$listTitle')/items?`$select=Id,Title,AttachmentFiles&`$expand=AttachmentFiles"

$items = Invoke-RestMethod -Uri $itemsUrl -Credential $cred -Headers @{Accept="application/json;odata=verbose"}

foreach ($item in $items.d.results) {

    if ($item.AttachmentFiles.results.Count -gt 0) {

        foreach ($attachment in $item.AttachmentFiles.results) {

            $fileUrl = $siteUrl + $attachment.ServerRelativeUrl
            $fileName = $attachment.FileName
            $outFile = Join-Path $downloadPath $fileName

            Write-Host "Downloading $fileName..."

            Invoke-WebRequest -Uri $fileUrl `
                              -OutFile $outFile `
                              -Credential $cred
        }
    }
}

Write-Host "Completed."
