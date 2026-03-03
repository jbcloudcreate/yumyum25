#Requires -Version 5.1

<#
.SYNOPSIS
    Exports a SharePoint Online List including images to HTML or CSV.

.DESCRIPTION
    Connects to SharePoint Online using Device Code OAuth2 authentication and
    exports all list items including Image column data and file attachments.

    ** CONSTRAINED LANGUAGE MODE COMPATIBLE **
    This script uses only native PowerShell cmdlets and allowed type accelerators.
    No Add-Type, no COM objects, no external modules.

    Supports exporting to:
    - HTML : Rich report with embedded base64 images (default, recommended)
            Can be opened directly in Word or printed to PDF from a browser.
    - CSV  : Data export with images saved to a subfolder.

.PARAMETER SiteUrl
    The full URL of the SharePoint site containing the list.
    Examples:
      https://contoso-my.sharepoint.com/personal/user_contoso_com
      https://contoso.sharepoint.com/sites/TeamSite

.PARAMETER ListName
    The display name of the SharePoint list to export.

.PARAMETER ExportFormat
    Output format: HTML (default) or CSV.
    HTML reports can be opened in Word for .docx, or printed to PDF from browser.

.PARAMETER OutputFolder
    Folder where export files will be saved. Defaults to current directory.

.PARAMETER ClientId
    Azure AD application (client) ID for authentication.
    Defaults to the Microsoft Office desktop app ID which has pre-consented
    SharePoint delegated permissions in most M365 tenants.

.PARAMETER PageSize
    Number of items to retrieve per API call. Default: 200. Max: 5000.

.EXAMPLE
    .\Export-SPOListData.ps1 -SiteUrl "https://contoso-my.sharepoint.com/personal/john_contoso_com" -ListName "PASF"

.EXAMPLE
    .\Export-SPOListData.ps1 -SiteUrl "https://contoso-my.sharepoint.com/personal/john_contoso_com" -ListName "PASF" -ExportFormat CSV

.NOTES
    Author  : James - South Wales Police ICT
    Version : 2.0.0
    Date    : 2025
    Repo    : github.com/jbcloudcreate/yumyum25

    CONSTRAINED LANGUAGE MODE (CLM) COMPATIBLE:
    - No Add-Type calls
    - No COM object creation (New-Object -ComObject)
    - No custom .NET class definitions
    - No System.Text.StringBuilder
    - Uses only core cmdlets and PowerShell type accelerators
    - Binary file writes use Set-Content -Encoding Byte

    For Word export: Open the HTML file in Microsoft Word and Save As .docx
    For PDF export:  Open the HTML file in your browser and Print > Save as PDF
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Full URL of the SharePoint site")]
    [ValidateNotNullOrEmpty()]
    [string]$SiteUrl,

    [Parameter(Mandatory = $true, HelpMessage = "Display name of the list to export")]
    [ValidateNotNullOrEmpty()]
    [string]$ListName,

    [Parameter(HelpMessage = "Export format: HTML or CSV")]
    [ValidateSet('HTML', 'CSV')]
    [string]$ExportFormat = 'HTML',

    [Parameter(HelpMessage = "Output folder path")]
    [string]$OutputFolder = (Get-Location).Path,

    [Parameter(HelpMessage = "Azure AD Client ID for authentication")]
    [string]$ClientId = 'd3590ed6-52b3-4102-aeff-aad2292ab01c',

    [Parameter(HelpMessage = "Items per page (1-5000)")]
    [ValidateRange(1, 5000)]
    [int]$PageSize = 200
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'Continue'

# Force TLS 1.2 for Azure AD and SharePoint Online connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Normalise the site URL (remove trailing slash)
$SiteUrl = $SiteUrl.TrimEnd('/')

# Parse the SharePoint host for OAuth scope
$siteUri    = [uri]$SiteUrl
$spHost     = $siteUri.Host
$spResource = "https://$spHost"

# Build the output folder structure
$timestamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$safeListName = $ListName -replace '[^\w\-]', '_'
$exportFolder = Join-Path $OutputFolder "${safeListName}_Export_${timestamp}"
$imagesFolder = Join-Path $exportFolder 'Images'

# ============================================================================
# HELPER: HTML ENCODING (CLM-safe, no System.Web dependency)
# ============================================================================

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $Text = $Text.Replace('&', '&amp;')
    $Text = $Text.Replace('<', '&lt;')
    $Text = $Text.Replace('>', '&gt;')
    $Text = $Text.Replace('"', '&quot;')
    $Text = $Text.Replace("'", '&#39;')
    return $Text
}

# ============================================================================
# HELPER: SAFE BINARY FILE WRITE (CLM-safe, no [System.IO.File])
# ============================================================================

function Write-BinaryFile {
    param(
        [string]$Path,
        [byte[]]$Bytes
    )
    Set-Content -Path $Path -Value $Bytes -Encoding Byte -Force
}

# ============================================================================
# HELPER: BASE64 ENCODE (CLM-safe using type accelerator)
# ============================================================================

function ConvertTo-Base64String {
    param([byte[]]$Bytes)
    return [convert]::ToBase64String($Bytes)
}

# ============================================================================
# SECTION 1: AUTHENTICATION (Device Code OAuth2 Flow)
# ============================================================================

function Get-DeviceCodeAccessToken {
    param(
        [string]$ResourceUri,
        [string]$ClientId
    )

    $deviceCodeUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
    $tokenUrl      = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
    $scope         = "$ResourceUri/AllSites.Read offline_access"

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  AUTHENTICATION REQUIRED" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    # Step 1: Request a device code
    try {
        $deviceCodeBody = @{
            client_id = $ClientId
            scope     = $scope
        }
        $deviceCodeResponse = Invoke-RestMethod -Method Post -Uri $deviceCodeUrl -Body $deviceCodeBody -ContentType 'application/x-www-form-urlencoded'
    }
    catch {
        throw "Device code request failed: $($_.Exception.Message)"
    }

    $userCode        = $deviceCodeResponse.user_code
    $verificationUri = $deviceCodeResponse.verification_uri
    $expiresIn       = $deviceCodeResponse.expires_in
    $interval        = $deviceCodeResponse.interval
    $deviceCode      = $deviceCodeResponse.device_code

    if ($interval -lt 5) { $interval = 5 }

    Write-Host "  To authenticate, please:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Open your browser to: $verificationUri" -ForegroundColor White
    Write-Host "  2. Enter this code:       $userCode" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Your M365 login is linked to Windows, so you should" -ForegroundColor Gray
    Write-Host "  already be signed in when the browser opens." -ForegroundColor Gray
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan

    # Try to open browser automatically
    try { Start-Process $verificationUri -ErrorAction SilentlyContinue } catch { }

    # Step 2: Poll for the token
    $pollStart = Get-Date
    $maxWait   = New-TimeSpan -Seconds $expiresIn

    while ((New-TimeSpan -Start $pollStart -End (Get-Date)) -lt $maxWait) {
        Start-Sleep -Seconds $interval

        try {
            $tokenBody = @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $ClientId
                device_code = $deviceCode
            }
            $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $tokenBody -ContentType 'application/x-www-form-urlencoded'

            Write-Host ""
            Write-Host "  Authentication successful!" -ForegroundColor Green
            Write-Host ""
            return $tokenResponse.access_token
        }
        catch {
            $errText = "$($_.ErrorDetails)"
            if ($errText -match 'authorization_pending') {
                Write-Host "." -NoNewline -ForegroundColor Gray
                continue
            }
            elseif ($errText -match 'slow_down') {
                $interval = $interval + 5
                continue
            }
            elseif ($errText -match 'authorization_declined') {
                throw "Authentication was declined by the user."
            }
            elseif ($errText -match 'expired_token') {
                throw "The device code has expired. Please run the script again."
            }
            else {
                throw "Token request failed: $($_.Exception.Message)"
            }
        }
    }

    throw "Authentication timed out. Please run the script again."
}

# ============================================================================
# SECTION 2: SHAREPOINT REST API HELPERS
# ============================================================================

function Invoke-SPORestMethod {
    param(
        [string]$Url,
        [string]$AccessToken,
        [string]$Method = 'GET',
        [int]$MaxRetries = 5,
        [switch]$RawResponse
    )

    $headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Accept'        = 'application/json;odata=nometadata'
        'Content-Type'  = 'application/json;charset=utf-8'
    }

    $retryCount = 0
    $baseDelay  = 2

    while ($true) {
        try {
            if ($RawResponse) {
                return (Invoke-WebRequest -Uri $Url -Headers $headers -Method $Method -UseBasicParsing)
            }
            else {
                return (Invoke-RestMethod -Uri $Url -Headers $headers -Method $Method)
            }
        }
        catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if (($statusCode -eq 429 -or $statusCode -eq 503) -and $retryCount -lt $MaxRetries) {
                $retryCount++
                $retryAfter = $baseDelay * [math]::Pow(2, $retryCount)
                Write-Warning "HTTP $statusCode - Retry $retryCount/$MaxRetries in ${retryAfter}s..."
                Start-Sleep -Seconds $retryAfter
                continue
            }

            $errDetail = "$($_.ErrorDetails)"
            if ($errDetail -match '"value"\s*:\s*"([^"]+)"') {
                throw "SharePoint API error ($statusCode): $($Matches[1])"
            }
            throw "SharePoint API error ($statusCode): $($_.Exception.Message)"
        }
    }
}

function Get-SPOBinaryContent {
    param(
        [string]$Url,
        [string]$AccessToken,
        [int]$MaxRetries = 3
    )

    $headers = @{
        'Authorization' = "Bearer $AccessToken"
    }

    $retryCount = 0
    $baseDelay  = 2

    while ($true) {
        try {
            $response = Invoke-WebRequest -Uri $Url -Headers $headers -Method GET -UseBasicParsing
            return $response.Content
        }
        catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if (($statusCode -eq 429 -or $statusCode -eq 503) -and $retryCount -lt $MaxRetries) {
                $retryCount++
                $retryAfter = $baseDelay * [math]::Pow(2, $retryCount)
                Write-Warning "Download throttled ($statusCode). Retry $retryCount/$MaxRetries..."
                Start-Sleep -Seconds $retryAfter
                continue
            }

            Write-Warning "Failed to download: $Url (HTTP $statusCode)"
            return $null
        }
    }
}

# ============================================================================
# SECTION 3: DATA EXTRACTION
# ============================================================================

function Get-SPOListFields {
    param(
        [string]$SiteUrl,
        [string]$ListName,
        [string]$AccessToken
    )

    $encodedListName = [uri]::EscapeDataString($ListName)
    $fieldsUrl = "$SiteUrl/_api/web/lists/getbytitle('$encodedListName')/fields?" +
                 "`$filter=Hidden eq false and ReadOnlyField eq false and " +
                 "InternalName ne 'ContentType' and InternalName ne 'Attachments' and " +
                 "InternalName ne 'Edit' and InternalName ne 'DocIcon' and " +
                 "InternalName ne 'ItemChildCount' and InternalName ne 'FolderChildCount' and " +
                 "InternalName ne 'AppAuthor' and InternalName ne 'AppEditor' and " +
                 "InternalName ne 'ComplianceAssetId'"

    $fieldsResponse = Invoke-SPORestMethod -Url $fieldsUrl -AccessToken $AccessToken

    $fields = @()
    foreach ($field in $fieldsResponse.value) {
        if ($field.InternalName -match '^_' -and $field.InternalName -ne '_x0020_') { continue }

        $fields += @{
            InternalName = $field.InternalName
            Title        = $field.Title
            TypeAsString = $field.TypeAsString
        }
    }

    return $fields
}

function Get-SPOListItems {
    param(
        [string]$SiteUrl,
        [string]$ListName,
        [string]$AccessToken,
        [int]$PageSize = 200
    )

    $encodedListName = [uri]::EscapeDataString($ListName)
    $itemsUrl = "$SiteUrl/_api/web/lists/getbytitle('$encodedListName')/items?" +
                "`$top=$PageSize&`$expand=AttachmentFiles"

    $allItems  = @()
    $pageCount = 0

    Write-Host "  Retrieving list items..." -ForegroundColor Cyan

    do {
        $pageCount++
        Write-Host "    Page $pageCount (fetched $($allItems.Count) items so far)..." -ForegroundColor Gray

        $response = Invoke-SPORestMethod -Url $itemsUrl -AccessToken $AccessToken

        if ($response.value) {
            $allItems += $response.value
        }

        $itemsUrl = $response.'odata.nextLink'

    } while ($itemsUrl)

    Write-Host "  Total items retrieved: $($allItems.Count)" -ForegroundColor Green
    return $allItems
}

function Get-ImageFromColumn {
    param(
        $ColumnValue,
        [string]$AccessToken,
        [string]$SiteUrl
    )

    if ([string]::IsNullOrWhiteSpace("$ColumnValue")) { return $null }

    $imageUrl = $null
    $fileName = $null

    if ($ColumnValue -is [PSCustomObject]) {
        if ($ColumnValue.serverRelativeUrl) {
            $siteRoot = $SiteUrl.Substring(0, $SiteUrl.IndexOf('/', 9))
            if ($ColumnValue.serverUrl) { $siteRoot = $ColumnValue.serverUrl }
            $imageUrl = $siteRoot + $ColumnValue.serverRelativeUrl
        }
        elseif ($ColumnValue.Url) {
            $imageUrl = $ColumnValue.Url
        }
        $fileName = $ColumnValue.fileName
    }
    elseif ("$ColumnValue" -match '^https?://') {
        $imageUrl = "$ColumnValue"
    }
    else {
        try {
            $parsed = "$ColumnValue" | ConvertFrom-Json -ErrorAction Stop
            if ($parsed.serverRelativeUrl) {
                $siteRoot = $SiteUrl.Substring(0, $SiteUrl.IndexOf('/', 9))
                if ($parsed.serverUrl) { $siteRoot = $parsed.serverUrl }
                $imageUrl = $siteRoot + $parsed.serverRelativeUrl
            }
            elseif ($parsed.Url) {
                $imageUrl = $parsed.Url
            }
            $fileName = $parsed.fileName
        }
        catch {
            return $null
        }
    }

    if (-not $imageUrl) { return $null }

    if (-not $fileName) {
        try {
            $urlPath  = ([uri]$imageUrl).AbsolutePath
            $fileName = $urlPath.Split('/')[-1]
        }
        catch {
            $fileName = "image_$(Get-Random).jpg"
        }
    }

    $imageBytes = Get-SPOBinaryContent -Url $imageUrl -AccessToken $AccessToken
    if (-not $imageBytes) { return $null }

    $ext = ''
    if ($fileName -match '\.(\w+)$') { $ext = ".$($Matches[1].ToLower())" }

    $mimeType = switch ($ext) {
        '.png'  { 'image/png' }
        '.gif'  { 'image/gif' }
        '.bmp'  { 'image/bmp' }
        '.webp' { 'image/webp' }
        '.svg'  { 'image/svg+xml' }
        default { 'image/jpeg' }
    }

    return @{
        FileName  = $fileName
        Bytes     = $imageBytes
        Base64    = (ConvertTo-Base64String -Bytes $imageBytes)
        MimeType  = $mimeType
        SourceUrl = $imageUrl
    }
}

function Get-ItemAttachments {
    param(
        $AttachmentFiles,
        [string]$AccessToken,
        [string]$SiteUrl
    )

    $attachments = @()
    $siteRoot    = $SiteUrl.Substring(0, $SiteUrl.IndexOf('/', 9))

    foreach ($attachment in $AttachmentFiles) {
        $fileName          = $attachment.FileName
        $serverRelativeUrl = $attachment.ServerRelativeUrl
        $downloadUrl       = "$siteRoot$serverRelativeUrl"

        $fileBytes = Get-SPOBinaryContent -Url $downloadUrl -AccessToken $AccessToken
        if (-not $fileBytes) { continue }

        $ext = ''
        if ($fileName -match '\.(\w+)$') { $ext = ".$($Matches[1].ToLower())" }
        $isImage = $ext -in @('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg')

        $mimeType = switch ($ext) {
            '.jpg'  { 'image/jpeg' }
            '.jpeg' { 'image/jpeg' }
            '.png'  { 'image/png' }
            '.gif'  { 'image/gif' }
            '.bmp'  { 'image/bmp' }
            '.webp' { 'image/webp' }
            default { 'application/octet-stream' }
        }

        $attachments += @{
            FileName  = $fileName
            Bytes     = $fileBytes
            Base64    = (ConvertTo-Base64String -Bytes $fileBytes)
            MimeType  = $mimeType
            IsImage   = $isImage
            SourceUrl = $downloadUrl
        }
    }

    return $attachments
}

# ============================================================================
# SECTION 4: DATA PROCESSING
# ============================================================================

function Build-ExportData {
    param(
        [array]$Items,
        [array]$Fields,
        [string]$AccessToken,
        [string]$SiteUrl
    )

    $imageFields = @($Fields | Where-Object { $_.TypeAsString -eq 'Thumbnail' -or $_.TypeAsString -eq 'Image' })
    $dataFields  = @($Fields | Where-Object { $_.TypeAsString -ne 'Thumbnail' -and $_.TypeAsString -ne 'Image' })

    Write-Host "  Processing $($Items.Count) items..." -ForegroundColor Cyan
    if ($imageFields.Count -gt 0) {
        Write-Host "  Image columns detected: $(($imageFields | ForEach-Object { $_.Title }) -join ', ')" -ForegroundColor Gray
    }

    $processedItems = @()
    $itemIndex = 0

    foreach ($item in $Items) {
        $itemIndex++
        $pct = [math]::Round(($itemIndex / $Items.Count) * 100)
        Write-Progress -Activity "Processing list items" -Status "Item $itemIndex of $($Items.Count)" -PercentComplete $pct

        $fieldValues = [ordered]@{}

        foreach ($field in $dataFields) {
            $internalName = $field.InternalName
            $displayName  = $field.Title
            $value        = $item.$internalName

            if ($null -ne $value) {
                if ($value -is [PSCustomObject]) {
                    if ($value.Title)           { $value = $value.Title }
                    elseif ($value.LookupValue) { $value = $value.LookupValue }
                    elseif ($value.Email)       { $value = $value.Email }
                    else { $value = ($value | ConvertTo-Json -Compress) }
                }
                elseif ($value -is [array]) {
                    $value = ($value | ForEach-Object {
                        if ($_ -is [PSCustomObject]) {
                            if ($_.Title) { $_.Title }
                            elseif ($_.LookupValue) { $_.LookupValue }
                            else { ($_ | ConvertTo-Json -Compress) }
                        }
                        else { "$_" }
                    }) -join '; '
                }
            }

            $fieldValues[$displayName] = $value
        }

        # Extract images from Image columns
        $itemImages = @()
        foreach ($imgField in $imageFields) {
            $imgValue = $item.($imgField.InternalName)
            if ($imgValue) {
                $imageData = Get-ImageFromColumn -ColumnValue $imgValue -AccessToken $AccessToken -SiteUrl $SiteUrl
                if ($imageData) {
                    $imageData['ColumnName'] = $imgField.Title
                    $itemImages += $imageData
                }
            }
        }

        # Download attachments
        $itemAttachments = @()
        if ($item.AttachmentFiles -and $item.AttachmentFiles.Count -gt 0) {
            $itemAttachments = @(Get-ItemAttachments -AttachmentFiles $item.AttachmentFiles -AccessToken $AccessToken -SiteUrl $SiteUrl)
        }

        $processedItems += @{
            Id          = $item.Id
            FieldValues = $fieldValues
            Images      = $itemImages
            Attachments = $itemAttachments
        }
    }

    Write-Progress -Activity "Processing list items" -Completed
    return $processedItems
}

# ============================================================================
# SECTION 5: EXPORT - HTML
# ============================================================================

function Export-ToHTML {
    param(
        [array]$ProcessedItems,
        [string]$ListName,
        [string]$OutputPath,
        [string]$SiteUrl
    )

    $htmlFile = Join-Path $OutputPath "${safeListName}_Report.html"

    # Collect all unique field names in order
    $allFieldNames = @()
    foreach ($item in $ProcessedItems) {
        foreach ($key in $item.FieldValues.Keys) {
            if ($key -notin $allFieldNames) {
                $allFieldNames += $key
            }
        }
    }

    # Build HTML using a string array (CLM-safe, no StringBuilder needed)
    $html = @()

    $html += @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$(ConvertTo-HtmlEncoded $ListName) - Export Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.5; color: #1a1a1a; background: #f5f5f5; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1e3a5f, #2a5298);
            color: white; padding: 30px; border-radius: 8px 8px 0 0;
        }
        .header h1 { font-size: 1.8em; margin-bottom: 8px; }
        .header .meta { font-size: 0.9em; opacity: 0.85; }
        .header .meta span { margin-right: 20px; }
        .content {
            background: white; border-radius: 0 0 8px 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        .item-card { border-bottom: 2px solid #e8e8e8; padding: 24px 30px; }
        .item-card:last-child { border-bottom: none; }
        .item-header { display: flex; align-items: center; margin-bottom: 16px; gap: 12px; }
        .item-number {
            background: #2a5298; color: white; width: 36px; height: 36px;
            border-radius: 50%; display: flex; align-items: center;
            justify-content: center; font-weight: 600; font-size: 0.85em; flex-shrink: 0;
        }
        .item-title { font-size: 1.2em; font-weight: 600; color: #1e3a5f; }
        .fields-table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
        .fields-table td { padding: 8px 12px; border: 1px solid #e0e0e0; vertical-align: top; }
        .fields-table td:first-child {
            width: 200px; font-weight: 600; background: #f8f9fa;
            color: #444; white-space: nowrap;
        }
        .images-section { margin-top: 12px; }
        .images-section h4 {
            font-size: 0.9em; color: #666; margin-bottom: 8px;
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        .image-grid { display: flex; flex-wrap: wrap; gap: 12px; }
        .image-wrapper {
            border: 1px solid #ddd; border-radius: 6px; overflow: hidden; max-width: 500px;
        }
        .image-wrapper img { max-width: 100%; max-height: 400px; display: block; object-fit: contain; }
        .image-caption {
            padding: 6px 10px; font-size: 0.8em; color: #666;
            background: #f8f8f8; border-top: 1px solid #eee;
        }
        .footer { text-align: center; padding: 20px; color: #888; font-size: 0.85em; }
        @media print {
            body { background: white; padding: 0; }
            .header { border-radius: 0; }
            .content { box-shadow: none; }
            .item-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>$(ConvertTo-HtmlEncoded $ListName)</h1>
        <div class="meta">
            <span>Items: $($ProcessedItems.Count)</span>
            <span>Exported: $(Get-Date -Format 'dd MMMM yyyy HH:mm')</span>
            <span>Source: $(ConvertTo-HtmlEncoded $SiteUrl)</span>
        </div>
    </div>
    <div class="content">
"@

    $itemNum = 0
    foreach ($item in $ProcessedItems) {
        $itemNum++

        # Get a display title
        $displayTitle = $item.FieldValues['Title']
        if ([string]::IsNullOrWhiteSpace($displayTitle)) {
            foreach ($val in $item.FieldValues.Values) {
                if (-not [string]::IsNullOrWhiteSpace("$val")) {
                    $displayTitle = "$val"
                    break
                }
            }
        }
        if ([string]::IsNullOrWhiteSpace($displayTitle)) {
            $displayTitle = "Item $($item.Id)"
        }

        $html += @"
        <div class="item-card">
            <div class="item-header">
                <div class="item-number">$itemNum</div>
                <div class="item-title">$(ConvertTo-HtmlEncoded $displayTitle)</div>
            </div>
            <table class="fields-table">
"@

        foreach ($fieldName in $allFieldNames) {
            $value = $item.FieldValues[$fieldName]
            if ($null -eq $value -or [string]::IsNullOrWhiteSpace("$value")) {
                $displayValue = '<span style="color:#ccc;">—</span>'
            }
            else {
                $displayValue = ConvertTo-HtmlEncoded "$value"
            }
            $html += "                <tr><td>$(ConvertTo-HtmlEncoded $fieldName)</td><td>$displayValue</td></tr>"
        }

        $html += "            </table>"

        # Collect all images (Image columns + image attachments)
        $allImages = @()
        $allImages += $item.Images
        $imageAttachments = @($item.Attachments | Where-Object { $_.IsImage })
        $allImages += $imageAttachments

        if ($allImages.Count -gt 0) {
            $html += '            <div class="images-section">'
            $html += '                <h4>Images</h4>'
            $html += '                <div class="image-grid">'

            foreach ($img in $allImages) {
                $caption = if ($img.ColumnName) { "$($img.ColumnName): $($img.FileName)" } else { $img.FileName }
                $html += @"
                    <div class="image-wrapper">
                        <img src="data:$($img.MimeType);base64,$($img.Base64)" alt="$(ConvertTo-HtmlEncoded $img.FileName)" />
                        <div class="image-caption">$(ConvertTo-HtmlEncoded $caption)</div>
                    </div>
"@
            }

            $html += '                </div>'
            $html += '            </div>'
        }

        # Non-image attachments
        $nonImageAttachments = @($item.Attachments | Where-Object { -not $_.IsImage })
        if ($nonImageAttachments.Count -gt 0) {
            $html += '            <div class="images-section">'
            $html += '                <h4>Attachments</h4>'
            foreach ($att in $nonImageAttachments) {
                $html += "                <p>&#128206; $(ConvertTo-HtmlEncoded $att.FileName)</p>"
            }
            $html += '            </div>'
        }

        $html += "        </div>"
    }

    $html += @"
    </div>
    <div class="footer">
        Exported from SharePoint Online &bull; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    </div>
</div>
</body>
</html>
"@

    # Join the array and write to file
    $htmlContent = $html -join "`r`n"
    Set-Content -Path $htmlFile -Value $htmlContent -Encoding UTF8 -Force

    Write-Host "  HTML report saved: $htmlFile" -ForegroundColor Green
    return $htmlFile
}

# ============================================================================
# SECTION 6: EXPORT - CSV
# ============================================================================

function Export-ToCSV {
    param(
        [array]$ProcessedItems,
        [string]$ListName,
        [string]$OutputPath,
        [string]$ImagesPath
    )

    $csvFile = Join-Path $OutputPath "${safeListName}_Data.csv"

    if (-not (Test-Path $ImagesPath)) {
        New-Item -ItemType Directory -Path $ImagesPath -Force | Out-Null
    }

    # Get all unique field names
    $allFieldNames = @()
    foreach ($item in $ProcessedItems) {
        foreach ($key in $item.FieldValues.Keys) {
            if ($key -notin $allFieldNames) {
                $allFieldNames += $key
            }
        }
    }

    # Find image column names
    $imageColNames = @()
    foreach ($item in $ProcessedItems) {
        foreach ($img in $item.Images) {
            if ($img.ColumnName -and $img.ColumnName -notin $imageColNames) {
                $imageColNames += $img.ColumnName
            }
        }
    }

    $csvRows = @()

    foreach ($item in $ProcessedItems) {
        $row = [ordered]@{ 'ID' = $item.Id }

        foreach ($fieldName in $allFieldNames) {
            $value = $item.FieldValues[$fieldName]
            $row[$fieldName] = if ($null -eq $value) { '' } else { "$value" }
        }

        foreach ($colName in $imageColNames) {
            $img = $item.Images | Where-Object { $_.ColumnName -eq $colName } | Select-Object -First 1
            if ($img) {
                $imgFileName = "Item$($item.Id)_${colName}_$($img.FileName)" -replace '[^\w\.\-]', '_'
                $imgPath = Join-Path $ImagesPath $imgFileName
                Write-BinaryFile -Path $imgPath -Bytes $img.Bytes
                $row["${colName}_File"] = "Images\$imgFileName"
            }
            else {
                $row["${colName}_File"] = ''
            }
        }

        $attachmentNames = @()
        foreach ($att in $item.Attachments) {
            $attFileName = "Item$($item.Id)_Att_$($att.FileName)" -replace '[^\w\.\-]', '_'
            $attPath = Join-Path $ImagesPath $attFileName
            Write-BinaryFile -Path $attPath -Bytes $att.Bytes
            $attachmentNames += "Images\$attFileName"
        }
        $row['Attachment_Files'] = $attachmentNames -join '; '

        $csvRows += [PSCustomObject]$row
    }

    $csvRows | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV data saved: $csvFile" -ForegroundColor Green
    Write-Host "  Images saved to: $ImagesPath" -ForegroundColor Green
    return $csvFile
}

# ============================================================================
# SECTION 7: MAIN EXECUTION
# ============================================================================

try {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  SharePoint Online List Exporter v2.0" -ForegroundColor Cyan
    Write-Host "  Constrained Language Mode Compatible" -ForegroundColor Gray
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Site:     $SiteUrl" -ForegroundColor White
    Write-Host "  List:     $ListName" -ForegroundColor White
    Write-Host "  Format:   $ExportFormat" -ForegroundColor White
    Write-Host "  Output:   $exportFolder" -ForegroundColor White
    Write-Host "  Language: $($ExecutionContext.SessionState.LanguageMode)" -ForegroundColor Gray
    Write-Host ""

    # -------------------------------------------------------------------
    # Step 1: Authenticate
    # -------------------------------------------------------------------
    Write-Host "[1/5] Authenticating..." -ForegroundColor Yellow
    $accessToken = Get-DeviceCodeAccessToken -ResourceUri $spResource -ClientId $ClientId
    if (-not $accessToken) {
        throw "Failed to obtain access token."
    }

    # -------------------------------------------------------------------
    # Step 2: Get list field definitions
    # -------------------------------------------------------------------
    Write-Host "[2/5] Reading list schema..." -ForegroundColor Yellow
    $fields = @(Get-SPOListFields -SiteUrl $SiteUrl -ListName $ListName -AccessToken $accessToken)
    if ($fields.Count -eq 0) {
        throw "No exportable fields found in list '$ListName'. Check the list name and permissions."
    }
    Write-Host "  Fields found: $($fields.Count)" -ForegroundColor Green
    Write-Host "  Columns: $(($fields | ForEach-Object { $_.Title }) -join ', ')" -ForegroundColor Gray

    # -------------------------------------------------------------------
    # Step 3: Retrieve all list items
    # -------------------------------------------------------------------
    Write-Host "[3/5] Fetching list items..." -ForegroundColor Yellow
    $items = @(Get-SPOListItems -SiteUrl $SiteUrl -ListName $ListName -AccessToken $accessToken -PageSize $PageSize)
    if ($items.Count -eq 0) {
        Write-Warning "The list '$ListName' contains no items. Nothing to export."
        return
    }

    # -------------------------------------------------------------------
    # Step 4: Process items (extract data, download images)
    # -------------------------------------------------------------------
    Write-Host "[4/5] Processing items and downloading images..." -ForegroundColor Yellow
    $processedItems = @(Build-ExportData -Items $items -Fields $fields -AccessToken $accessToken -SiteUrl $SiteUrl)

    # -------------------------------------------------------------------
    # Step 5: Export
    # -------------------------------------------------------------------
    Write-Host "[5/5] Exporting data..." -ForegroundColor Yellow

    New-Item -ItemType Directory -Path $exportFolder -Force | Out-Null
    New-Item -ItemType Directory -Path $imagesFolder -Force | Out-Null

    # Always generate HTML (base format)
    $htmlFile = Export-ToHTML -ProcessedItems $processedItems -ListName $ListName -OutputPath $exportFolder -SiteUrl $SiteUrl

    # CSV export if requested
    if ($ExportFormat -eq 'CSV') {
        Export-ToCSV -ProcessedItems $processedItems -ListName $ListName -OutputPath $exportFolder -ImagesPath $imagesFolder
    }

    # Save all images to the Images subfolder
    $imageCount = 0
    foreach ($item in $processedItems) {
        foreach ($img in $item.Images) {
            $imgFileName = "Item$($item.Id)_$($img.ColumnName)_$($img.FileName)" -replace '[^\w\.\-]', '_'
            $imgPath = Join-Path $imagesFolder $imgFileName
            Write-BinaryFile -Path $imgPath -Bytes $img.Bytes
            $imageCount++
        }
        foreach ($att in $item.Attachments) {
            $attFileName = "Item$($item.Id)_$($att.FileName)" -replace '[^\w\.\-]', '_'
            $attPath = Join-Path $imagesFolder $attFileName
            Write-BinaryFile -Path $attPath -Bytes $att.Bytes
            $imageCount++
        }
    }

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host "  EXPORT COMPLETE" -ForegroundColor Green
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host ""
    Write-Host "  Items exported : $($processedItems.Count)" -ForegroundColor White
    Write-Host "  Images saved   : $imageCount" -ForegroundColor White
    Write-Host "  Output folder  : $exportFolder" -ForegroundColor White
    Write-Host ""
    Write-Host "  Files:" -ForegroundColor Gray
    Get-ChildItem -Path $exportFolder -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Replace($exportFolder, '').TrimStart('\', '/')
        $sizeKB = [math]::Round($_.Length / 1KB, 1)
        Write-Host "    $relativePath ($sizeKB KB)" -ForegroundColor Gray
    }
    Write-Host ""

    if ($ExportFormat -eq 'HTML') {
        Write-Host "  TIP: Open the HTML file in Word to save as .docx" -ForegroundColor Yellow
        Write-Host "  TIP: Open in a browser and Print > Save as PDF" -ForegroundColor Yellow
        Write-Host ""
    }

    # Open the output folder
    try { Start-Process explorer.exe -ArgumentList $exportFolder -ErrorAction SilentlyContinue } catch { }
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack trace:" -ForegroundColor DarkRed
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    Write-Host ""
    exit 1
}
