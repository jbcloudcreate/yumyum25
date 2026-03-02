#Requires -Version 5.1

<#
.SYNOPSIS
    Exports a SharePoint Online List including images to HTML, CSV, Word, or PDF.

.DESCRIPTION
    Connects to SharePoint Online using Device Code OAuth2 authentication (no external
    modules required) and exports all list items including Image column data and
    file attachments.

    Supports exporting to:
    - HTML  : Rich report with embedded base64 images (default, recommended)
    - CSV   : Data export with images saved to a subfolder
    - Word  : Converts HTML report to .docx via Word COM automation
    - PDF   : Converts HTML report to .pdf via Word COM automation

    Designed for secure enterprise environments where installing PowerShell modules
    (PnP, SharePoint Online, etc.) is not permitted.

.PARAMETER SiteUrl
    The full URL of the SharePoint site containing the list.
    Examples:
      https://contoso-my.sharepoint.com/personal/user_contoso_com
      https://contoso.sharepoint.com/sites/TeamSite

.PARAMETER ListName
    The display name of the SharePoint list to export.

.PARAMETER ExportFormat
    Output format: HTML (default), CSV, Word, or PDF.
    Word and PDF require Microsoft Word to be installed for COM conversion.
    If Word is unavailable, falls back to HTML output.

.PARAMETER OutputFolder
    Folder where export files will be saved. Defaults to current directory.
    A subfolder named '{ListName}_Export_{timestamp}' is created automatically.

.PARAMETER ClientId
    Azure AD application (client) ID for authentication.
    Defaults to the Microsoft Office desktop app ID which has pre-consented
    SharePoint delegated permissions in most M365 tenants.

.PARAMETER PageSize
    Number of items to retrieve per API call. Default: 200. Max: 5000.

.EXAMPLE
    .\Export-SPOListData.ps1 -SiteUrl "https://contoso-my.sharepoint.com/personal/john_contoso_com" -ListName "PASF"
    .\Export-SPOListData.ps1 -SiteUrl "https://southwalespolice-my.sharepoint.com/personal/geraint_morgan_south-wales_police_uk" -ListName "PASF"

.EXAMPLE
    .\Export-SPOListData.ps1 -SiteUrl "https://contoso.sharepoint.com/sites/Security" -ListName "Assessments" -ExportFormat Word
    .\Export-SPOListData.ps1 -SiteUrl "https://southwalespolice-my.sharepoint.com/personal/geraint_morgan_south-wales_police_uk" -ListName "PASF" -ExportFormat Word


.EXAMPLE
    .\Export-SPOListData.ps1 -SiteUrl "https://contoso-my.sharepoint.com/personal/user" -ListName "MyList" -ExportFormat CSV -OutputFolder "C:\Exports"
    .\Export-SPOListData.ps1 -SiteUrl "https://southwalespolice-my.sharepoint.com/personal/geraint_morgan_south-wales_police_uk" -ListName "PASF" -ExportFormat CSV -OutputFolder "C:\Exports"


.NOTES
    Author  : James - South Wales Police ICT
    Version : 1.0.0
    Date    : 2025
    Repo    : github.com/jbcloudcreate/yumyum25

    No external modules required. Uses:
    - Native PowerShell cmdlets (Invoke-RestMethod, Invoke-WebRequest)
    - .NET Framework classes (System.IO, System.Net, System.Text)
    - Word COM automation (optional, for Word/PDF export only)

    Authentication uses the OAuth2 Device Code flow via Azure AD v2.0 endpoints.
    The user will be prompted to open a browser and enter a code to authenticate.
    Since your environment uses Windows-linked M365 logins, you will already be
    signed in when the browser opens.

    THROTTLING: The script includes automatic retry with exponential backoff
    for HTTP 429 (Too Many Requests) responses from SharePoint Online.

    PAGINATION: Handles lists with any number of items via OData pagination.

    IMAGE HANDLING: Supports both modern Image columns (Thumbnail type) and
    traditional file attachments on list items.

    powershell -ExecutionPolicy Bypass -File .\Export-SPOListData.ps1 -SiteUrl "https://southwalespolice-my.sharepoint.com/personal/geraint_morgan_south-wales_police_uk" -ListName "PASF"
    powershell -ExecutionPolicy Bypass -NoProfile -File "%~dp0Export-SPOListData.ps1" -SiteUrl "https://southwalespolice-my.sharepoint.com/personal/geraint_morgan_south-wales_police_uk" -ListName "PASF"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Full URL of the SharePoint site")]
    [ValidateNotNullOrEmpty()]
    [string]$SiteUrl,

    [Parameter(Mandatory = $true, HelpMessage = "Display name of the list to export")]
    [ValidateNotNullOrEmpty()]
    [string]$ListName,

    [Parameter(HelpMessage = "Export format: HTML, CSV, Word, or PDF")]
    [ValidateSet('HTML', 'CSV', 'Word', 'PDF')]
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

# Normalise the site URL (remove trailing slash)
$SiteUrl = $SiteUrl.TrimEnd('/')

# Parse the SharePoint host for OAuth scope
$siteUri       = [System.Uri]$SiteUrl
$spHost        = $siteUri.Host
$spResource    = "https://$spHost"

# Build the output folder structure
$timestamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
$safeListName  = $ListName -replace '[^\w\-]', '_'
$exportFolder  = Join-Path $OutputFolder "${safeListName}_Export_${timestamp}"
$imagesFolder  = Join-Path $exportFolder 'Images'

# ============================================================================
# SECTION 1: AUTHENTICATION (Device Code OAuth2 Flow)
# ============================================================================

function Get-DeviceCodeAccessToken {
    <#
    .SYNOPSIS
        Authenticates to Azure AD using the Device Code flow.
    .DESCRIPTION
        No modules required. Uses Invoke-RestMethod against Azure AD v2.0 endpoints.
        The user opens a browser (where they are already signed in via SSO),
        enters the displayed code, and the script receives an access token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceUri,

        [Parameter(Mandatory)]
        [string]$ClientId
    )

    # Azure AD v2.0 endpoints - using 'organizations' for multi-tenant support
    $deviceCodeUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
    $tokenUrl      = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"

    # Scope: AllSites.Read gives read access to all SharePoint sites the user can access
    $scope = "$ResourceUri/AllSites.Read offline_access"

    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  AUTHENTICATION REQUIRED" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""

    # Step 1: Request a device code
    try {
        $deviceCodeResponse = Invoke-RestMethod -Method Post -Uri $deviceCodeUrl -Body @{
            client_id = $ClientId
            scope     = $scope
        } -ContentType 'application/x-www-form-urlencoded'
    }
    catch {
        $errorDetail = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($errorDetail.error_description) {
            throw "Device code request failed: $($errorDetail.error_description)"
        }
        throw "Device code request failed: $($_.Exception.Message)"
    }

    # Step 2: Display the user code and instructions
    $userCode       = $deviceCodeResponse.user_code
    $verificationUri = $deviceCodeResponse.verification_uri
    $expiresIn      = $deviceCodeResponse.expires_in
    $interval       = [Math]::Max($deviceCodeResponse.interval, 5)
    $deviceCode     = $deviceCodeResponse.device_code

    Write-Host "  To authenticate, please:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Open your browser to: $verificationUri" -ForegroundColor White
    Write-Host "  2. Enter this code:       $userCode" -ForegroundColor Green
    Write-Host ""
    Write-Host "  The code expires in $([math]::Round($expiresIn / 60)) minutes." -ForegroundColor Gray
    Write-Host "  Since your M365 login is linked to Windows, you should" -ForegroundColor Gray
    Write-Host "  already be signed in when the browser opens." -ForegroundColor Gray
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""

    # Attempt to open the verification URL in the default browser
    try {
        Start-Process $verificationUri -ErrorAction SilentlyContinue
        Write-Host "  Browser opened automatically. Please enter the code above." -ForegroundColor Gray
    }
    catch {
        Write-Host "  Please open your browser manually to the URL above." -ForegroundColor Gray
    }

    # Step 3: Poll for the token
    $pollStart = Get-Date
    $maxWait   = [TimeSpan]::FromSeconds($expiresIn)

    while ((Get-Date) - $pollStart -lt $maxWait) {
        Start-Sleep -Seconds $interval

        try {
            $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $ClientId
                device_code = $deviceCode
            } -ContentType 'application/x-www-form-urlencoded'

            # Success - we have a token
            Write-Host ""
            Write-Host "  Authentication successful!" -ForegroundColor Green
            Write-Host ""

            return $tokenResponse.access_token
        }
        catch {
            $errorBody = $null
            try {
                $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json
            }
            catch { }

            if ($errorBody.error -eq 'authorization_pending') {
                # User hasn't completed auth yet - keep polling
                Write-Host "." -NoNewline -ForegroundColor Gray
                continue
            }
            elseif ($errorBody.error -eq 'slow_down') {
                # Increase polling interval
                $interval += 5
                continue
            }
            elseif ($errorBody.error -eq 'authorization_declined') {
                throw "Authentication was declined by the user."
            }
            elseif ($errorBody.error -eq 'expired_token') {
                throw "The device code has expired. Please run the script again."
            }
            else {
                $errMsg = if ($errorBody.error_description) { $errorBody.error_description } else { $_.Exception.Message }
                throw "Token request failed: $errMsg"
            }
        }
    }

    throw "Authentication timed out. Please run the script again."
}

# ============================================================================
# SECTION 2: SHAREPOINT REST API HELPERS
# ============================================================================

function Invoke-SPORestMethod {
    <#
    .SYNOPSIS
        Executes a REST API call to SharePoint Online with retry logic.
    .DESCRIPTION
        Handles authentication headers, JSON content type, and automatic
        retry with exponential backoff for HTTP 429 (throttled) responses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [ValidateSet('GET', 'POST')]
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
                $response = Invoke-WebRequest -Uri $Url -Headers $headers -Method $Method -UseBasicParsing
                return $response
            }
            else {
                $response = Invoke-RestMethod -Uri $Url -Headers $headers -Method $Method
                return $response
            }
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            # Handle throttling (429)
            if ($statusCode -eq 429 -and $retryCount -lt $MaxRetries) {
                $retryCount++
                $retryAfter = $baseDelay * [Math]::Pow(2, $retryCount)

                # Check for Retry-After header
                try {
                    $retryHeader = $_.Exception.Response.Headers | Where-Object { $_.Key -eq 'Retry-After' }
                    if ($retryHeader) {
                        $retryAfter = [int]$retryHeader.Value[0]
                    }
                }
                catch { }

                Write-Warning "Throttled by SharePoint (429). Retry $retryCount/$MaxRetries in ${retryAfter}s..."
                Start-Sleep -Seconds $retryAfter
                continue
            }

            # Handle 503 Service Unavailable with retry
            if ($statusCode -eq 503 -and $retryCount -lt $MaxRetries) {
                $retryCount++
                $retryAfter = $baseDelay * [Math]::Pow(2, $retryCount)
                Write-Warning "Service unavailable (503). Retry $retryCount/$MaxRetries in ${retryAfter}s..."
                Start-Sleep -Seconds $retryAfter
                continue
            }

            # All other errors - throw
            $errDetail = $_.ErrorDetails.Message
            if ($errDetail) {
                try {
                    $parsed = $errDetail | ConvertFrom-Json
                    if ($parsed.'odata.error'.message.value) {
                        throw "SharePoint API error ($statusCode): $($parsed.'odata.error'.message.value)"
                    }
                }
                catch [System.ArgumentException] { }
            }
            throw "SharePoint API error ($statusCode): $($_.Exception.Message)"
        }
    }
}

function Get-SPOBinaryContent {
    <#
    .SYNOPSIS
        Downloads binary content (images/files) from SharePoint Online.
    .DESCRIPTION
        Uses Invoke-WebRequest to download binary data with proper auth headers.
        Returns the raw byte array content.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
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
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if (($statusCode -eq 429 -or $statusCode -eq 503) -and $retryCount -lt $MaxRetries) {
                $retryCount++
                $retryAfter = $baseDelay * [Math]::Pow(2, $retryCount)
                Write-Warning "Download throttled ($statusCode). Retry $retryCount/$MaxRetries in ${retryAfter}s..."
                Start-Sleep -Seconds $retryAfter
                continue
            }

            Write-Warning "Failed to download from: $Url ($statusCode)"
            return $null
        }
    }
}

# ============================================================================
# SECTION 3: DATA EXTRACTION
# ============================================================================

function Get-SPOListFields {
    <#
    .SYNOPSIS
        Retrieves the field (column) definitions for a SharePoint list.
    .DESCRIPTION
        Gets all non-hidden, non-system fields to build the export column set.
        Returns an array of field objects with InternalName, Title, and TypeAsString.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SiteUrl,

        [Parameter(Mandatory)]
        [string]$ListName,

        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    $encodedListName = [System.Uri]::EscapeDataString($ListName)
    $fieldsUrl = "$SiteUrl/_api/web/lists/getbytitle('$encodedListName')/fields?" +
                 "`$filter=Hidden eq false and ReadOnlyField eq false and " +
                 "InternalName ne 'ContentType' and InternalName ne 'Attachments' and " +
                 "InternalName ne 'Edit' and InternalName ne 'DocIcon' and " +
                 "InternalName ne 'ItemChildCount' and InternalName ne 'FolderChildCount' and " +
                 "InternalName ne 'AppAuthor' and InternalName ne 'AppEditor' and " +
                 "InternalName ne 'ComplianceAssetId'"

    Write-Verbose "Fetching list field definitions..."

    $fieldsResponse = Invoke-SPORestMethod -Url $fieldsUrl -AccessToken $AccessToken

    $fields = @()
    foreach ($field in $fieldsResponse.value) {
        # Skip computed and system fields
        if ($field.InternalName -match '^_' -and $field.InternalName -ne '_x0020_') { continue }
        if ($field.SchemaXml -match 'ShowInNewForm="FALSE"' -and
            $field.SchemaXml -match 'ShowInEditForm="FALSE"') { continue }

        $fields += [PSCustomObject]@{
            InternalName = $field.InternalName
            Title        = $field.Title
            TypeAsString = $field.TypeAsString
            FieldType    = $field.FieldTypeKind
            Description  = $field.Description
        }
    }

    Write-Verbose "Found $($fields.Count) exportable fields."
    return $fields
}

function Get-SPOListItems {
    <#
    .SYNOPSIS
        Retrieves all items from a SharePoint list with pagination support.
    .DESCRIPTION
        Fetches list items in batches, expanding AttachmentFiles for each item.
        Handles OData pagination via odata.nextLink to retrieve all items
        regardless of list size.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SiteUrl,

        [Parameter(Mandatory)]
        [string]$ListName,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [int]$PageSize = 200
    )

    $encodedListName = [System.Uri]::EscapeDataString($ListName)
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

        # Check for next page
        $itemsUrl = $response.'odata.nextLink'

    } while ($itemsUrl)

    Write-Host "  Total items retrieved: $($allItems.Count)" -ForegroundColor Green

    return $allItems
}

function Get-ImageFromColumn {
    <#
    .SYNOPSIS
        Extracts image data from a SharePoint Image (Thumbnail) column value.
    .DESCRIPTION
        Modern SharePoint Image columns store their value as a JSON string containing
        the image URL. This function parses that JSON and downloads the image.
        Handles both the JSON format and direct URL formats.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $ColumnValue,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$SiteUrl
    )

    if ([string]::IsNullOrWhiteSpace($ColumnValue)) {
        return $null
    }

    $imageUrl  = $null
    $fileName  = $null

    # Attempt to parse as JSON (modern Image column format)
    try {
        $imageData = $null

        # Handle case where value is already a PSObject (auto-deserialized)
        if ($ColumnValue -is [PSCustomObject]) {
            $imageData = $ColumnValue
        }
        else {
            $imageData = $ColumnValue | ConvertFrom-Json -ErrorAction Stop
        }

        if ($imageData.serverRelativeUrl) {
            $serverUrl = if ($imageData.serverUrl) { $imageData.serverUrl } else { $SiteUrl.Substring(0, $SiteUrl.IndexOf('/', 9)) }
            $imageUrl = $serverUrl + $imageData.serverRelativeUrl
        }
        elseif ($imageData.Url) {
            $imageUrl = $imageData.Url
        }

        $fileName = $imageData.fileName
    }
    catch {
        # Not JSON - might be a direct URL string
        if ($ColumnValue -match '^https?://') {
            $imageUrl = $ColumnValue
        }
    }

    if (-not $imageUrl) {
        return $null
    }

    # Derive filename if not available
    if (-not $fileName) {
        try {
            $urlPath  = ([System.Uri]$imageUrl).AbsolutePath
            $fileName = [System.IO.Path]::GetFileName($urlPath)
        }
        catch {
            $fileName = "image_$(Get-Random).jpg"
        }
    }

    # Download the image
    Write-Verbose "Downloading image: $fileName"
    $imageBytes = Get-SPOBinaryContent -Url $imageUrl -AccessToken $AccessToken

    if ($imageBytes) {
        # Determine MIME type from extension
        $ext = [System.IO.Path]::GetExtension($fileName).ToLower()
        $mimeType = switch ($ext) {
            '.png'  { 'image/png' }
            '.gif'  { 'image/gif' }
            '.bmp'  { 'image/bmp' }
            '.webp' { 'image/webp' }
            '.svg'  { 'image/svg+xml' }
            default { 'image/jpeg' }
        }

        return [PSCustomObject]@{
            FileName  = $fileName
            Bytes     = $imageBytes
            Base64    = [System.Convert]::ToBase64String($imageBytes)
            MimeType  = $mimeType
            SourceUrl = $imageUrl
        }
    }

    return $null
}

function Get-ItemAttachments {
    <#
    .SYNOPSIS
        Downloads all file attachments for a list item.
    .DESCRIPTION
        Takes the AttachmentFiles collection from a list item and downloads
        each file, returning an array of attachment objects with file data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AttachmentFiles,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$SiteUrl
    )

    $attachments = @()

    foreach ($attachment in $AttachmentFiles) {
        $fileName          = $attachment.FileName
        $serverRelativeUrl = $attachment.ServerRelativeUrl

        # Build the full download URL
        $siteRoot    = $SiteUrl.Substring(0, $SiteUrl.IndexOf('/', 9))
        $downloadUrl = "$siteRoot$serverRelativeUrl"

        Write-Verbose "Downloading attachment: $fileName"
        $fileBytes = Get-SPOBinaryContent -Url $downloadUrl -AccessToken $AccessToken

        if ($fileBytes) {
            $ext = [System.IO.Path]::GetExtension($fileName).ToLower()
            $isImage = $ext -in @('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg')

            $mimeType = switch ($ext) {
                '.jpg'  { 'image/jpeg' }
                '.jpeg' { 'image/jpeg' }
                '.png'  { 'image/png' }
                '.gif'  { 'image/gif' }
                '.bmp'  { 'image/bmp' }
                '.webp' { 'image/webp' }
                '.svg'  { 'image/svg+xml' }
                '.pdf'  { 'application/pdf' }
                '.docx' { 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }
                '.xlsx' { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }
                default { 'application/octet-stream' }
            }

            $attachments += [PSCustomObject]@{
                FileName  = $fileName
                Bytes     = $fileBytes
                Base64    = [System.Convert]::ToBase64String($fileBytes)
                MimeType  = $mimeType
                IsImage   = $isImage
                SourceUrl = $downloadUrl
            }
        }
    }

    return $attachments
}

# ============================================================================
# SECTION 4: DATA PROCESSING
# ============================================================================

function Build-ExportData {
    <#
    .SYNOPSIS
        Processes raw list items into a structured export-ready dataset.
    .DESCRIPTION
        Maps internal field names to display names, extracts image column data,
        downloads attachments, and builds a unified data structure for export.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Items,

        [Parameter(Mandatory)]
        [array]$Fields,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$SiteUrl
    )

    # Identify Image/Thumbnail columns
    $imageFields = $Fields | Where-Object { $_.TypeAsString -eq 'Thumbnail' -or $_.TypeAsString -eq 'Image' }
    $dataFields  = $Fields | Where-Object { $_.TypeAsString -ne 'Thumbnail' -and $_.TypeAsString -ne 'Image' }

    Write-Host "  Processing $($Items.Count) items..." -ForegroundColor Cyan

    if ($imageFields) {
        Write-Host "  Image columns detected: $($imageFields.Title -join ', ')" -ForegroundColor Gray
    }

    $processedItems = @()
    $itemIndex = 0

    foreach ($item in $Items) {
        $itemIndex++
        $pct = [math]::Round(($itemIndex / $Items.Count) * 100)
        Write-Progress -Activity "Processing list items" -Status "Item $itemIndex of $($Items.Count)" -PercentComplete $pct

        $processedItem = [PSCustomObject]@{
            Id          = $item.Id
            FieldValues = [ordered]@{}
            Images      = @()
            Attachments = @()
        }

        # Extract standard field values
        foreach ($field in $dataFields) {
            $internalName = $field.InternalName
            $displayName  = $field.Title
            $value        = $item.$internalName

            # Handle lookup and complex field types
            if ($null -ne $value) {
                if ($value -is [PSCustomObject]) {
                    # Person/Lookup field - extract display value
                    if ($value.Title) { $value = $value.Title }
                    elseif ($value.LookupValue) { $value = $value.LookupValue }
                    elseif ($value.Email) { $value = $value.Email }
                    else { $value = $value | ConvertTo-Json -Compress }
                }
                elseif ($value -is [Array]) {
                    # Multi-value field
                    $value = ($value | ForEach-Object {
                        if ($_ -is [PSCustomObject]) {
                            if ($_.Title) { $_.Title }
                            elseif ($_.LookupValue) { $_.LookupValue }
                            else { $_ | ConvertTo-Json -Compress }
                        }
                        else { $_ }
                    }) -join '; '
                }
            }

            $processedItem.FieldValues[$displayName] = $value
        }

        # Extract images from Image columns
        foreach ($imgField in $imageFields) {
            $imgValue = $item.($imgField.InternalName)
            if ($imgValue) {
                $imageData = Get-ImageFromColumn -ColumnValue $imgValue -AccessToken $AccessToken -SiteUrl $SiteUrl
                if ($imageData) {
                    $imageData | Add-Member -NotePropertyName 'ColumnName' -NotePropertyValue $imgField.Title
                    $processedItem.Images += $imageData
                }
            }
        }

        # Download attachments
        if ($item.AttachmentFiles -and $item.AttachmentFiles.Count -gt 0) {
            $attachments = Get-ItemAttachments -AttachmentFiles $item.AttachmentFiles -AccessToken $AccessToken -SiteUrl $SiteUrl
            $processedItem.Attachments = $attachments
        }

        $processedItems += $processedItem
    }

    Write-Progress -Activity "Processing list items" -Completed

    return $processedItems
}

# ============================================================================
# SECTION 5: EXPORT - HTML
# ============================================================================

function Export-ToHTML {
    <#
    .SYNOPSIS
        Exports processed list data to a rich HTML report with embedded images.
    .DESCRIPTION
        Creates a self-contained HTML file with:
        - Professional styling suitable for printing or saving as PDF
        - Data tables with all field values
        - Embedded base64 images from Image columns and attachments
        - Metadata header with export details
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$ProcessedItems,

        [Parameter(Mandatory)]
        [string]$ListName,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$SiteUrl
    )

    $htmlFile = Join-Path $OutputPath "${safeListName}_Report.html"

    # Get all unique field names in order
    $allFieldNames = [ordered]@{}
    foreach ($item in $ProcessedItems) {
        foreach ($key in $item.FieldValues.Keys) {
            if (-not $allFieldNames.Contains($key)) {
                $allFieldNames[$key] = $true
            }
        }
    }

    $fieldNames = @($allFieldNames.Keys)

    # Build the HTML
    $htmlBuilder = [System.Text.StringBuilder]::new()

    [void]$htmlBuilder.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$([System.Web.HttpUtility]::HtmlEncode($ListName)) - Export Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.5;
            color: #1a1a1a;
            background: #f5f5f5;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1e3a5f, #2a5298);
            color: white;
            padding: 30px;
            border-radius: 8px 8px 0 0;
            margin-bottom: 0;
        }
        .header h1 { font-size: 1.8em; margin-bottom: 8px; }
        .header .meta { font-size: 0.9em; opacity: 0.85; }
        .header .meta span { margin-right: 20px; }
        .content {
            background: white;
            padding: 0;
            border-radius: 0 0 8px 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        .item-card {
            border-bottom: 2px solid #e8e8e8;
            padding: 24px 30px;
        }
        .item-card:last-child { border-bottom: none; }
        .item-header {
            display: flex;
            align-items: center;
            margin-bottom: 16px;
            gap: 12px;
        }
        .item-number {
            background: #2a5298;
            color: white;
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.85em;
            flex-shrink: 0;
        }
        .item-title { font-size: 1.2em; font-weight: 600; color: #1e3a5f; }
        .fields-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 16px;
        }
        .fields-table td {
            padding: 8px 12px;
            border: 1px solid #e0e0e0;
            vertical-align: top;
        }
        .fields-table td:first-child {
            width: 200px;
            font-weight: 600;
            background: #f8f9fa;
            color: #444;
            white-space: nowrap;
        }
        .images-section {
            margin-top: 12px;
        }
        .images-section h4 {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .image-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
        }
        .image-wrapper {
            border: 1px solid #ddd;
            border-radius: 6px;
            overflow: hidden;
            max-width: 500px;
        }
        .image-wrapper img {
            max-width: 100%;
            max-height: 400px;
            display: block;
            object-fit: contain;
        }
        .image-caption {
            padding: 6px 10px;
            font-size: 0.8em;
            color: #666;
            background: #f8f8f8;
            border-top: 1px solid #eee;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #888;
            font-size: 0.85em;
        }
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
        <h1>$([System.Web.HttpUtility]::HtmlEncode($ListName))</h1>
        <div class="meta">
            <span>Items: $($ProcessedItems.Count)</span>
            <span>Exported: $(Get-Date -Format 'dd MMMM yyyy HH:mm')</span>
            <span>Source: $([System.Web.HttpUtility]::HtmlEncode($SiteUrl))</span>
        </div>
    </div>
    <div class="content">
"@)

    $itemNum = 0
    foreach ($item in $ProcessedItems) {
        $itemNum++

        # Get a display title (first non-empty text field or ID)
        $displayTitle = $item.FieldValues['Title']
        if ([string]::IsNullOrWhiteSpace($displayTitle)) {
            $displayTitle = ($item.FieldValues.Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
        }
        if ([string]::IsNullOrWhiteSpace($displayTitle)) {
            $displayTitle = "Item $($item.Id)"
        }

        [void]$htmlBuilder.AppendLine(@"
        <div class="item-card">
            <div class="item-header">
                <div class="item-number">$itemNum</div>
                <div class="item-title">$([System.Web.HttpUtility]::HtmlEncode($displayTitle))</div>
            </div>
            <table class="fields-table">
"@)

        foreach ($fieldName in $fieldNames) {
            $value = $item.FieldValues[$fieldName]
            $displayValue = if ($null -eq $value -or [string]::IsNullOrWhiteSpace("$value")) { '<span style="color:#ccc;">—</span>' }
                            else { [System.Web.HttpUtility]::HtmlEncode("$value") }

            [void]$htmlBuilder.AppendLine("                <tr><td>$([System.Web.HttpUtility]::HtmlEncode($fieldName))</td><td>$displayValue</td></tr>")
        }

        [void]$htmlBuilder.AppendLine("            </table>")

        # Add images from Image columns
        $allImages = @()
        $allImages += $item.Images
        $allImages += ($item.Attachments | Where-Object { $_.IsImage })

        if ($allImages.Count -gt 0) {
            [void]$htmlBuilder.AppendLine('            <div class="images-section">')
            [void]$htmlBuilder.AppendLine('                <h4>Images</h4>')
            [void]$htmlBuilder.AppendLine('                <div class="image-grid">')

            foreach ($img in $allImages) {
                $caption = if ($img.ColumnName) { "$($img.ColumnName): $($img.FileName)" } else { $img.FileName }
                [void]$htmlBuilder.AppendLine(@"
                    <div class="image-wrapper">
                        <img src="data:$($img.MimeType);base64,$($img.Base64)" alt="$([System.Web.HttpUtility]::HtmlEncode($img.FileName))" />
                        <div class="image-caption">$([System.Web.HttpUtility]::HtmlEncode($caption))</div>
                    </div>
"@)
            }

            [void]$htmlBuilder.AppendLine('                </div>')
            [void]$htmlBuilder.AppendLine('            </div>')
        }

        # Non-image attachments listed as links (file saved separately)
        $nonImageAttachments = $item.Attachments | Where-Object { -not $_.IsImage }
        if ($nonImageAttachments.Count -gt 0) {
            [void]$htmlBuilder.AppendLine('            <div class="images-section">')
            [void]$htmlBuilder.AppendLine('                <h4>Attachments</h4>')
            foreach ($att in $nonImageAttachments) {
                [void]$htmlBuilder.AppendLine("                <p>&#128206; $([System.Web.HttpUtility]::HtmlEncode($att.FileName))</p>")
            }
            [void]$htmlBuilder.AppendLine('            </div>')
        }

        [void]$htmlBuilder.AppendLine("        </div>")
    }

    [void]$htmlBuilder.AppendLine(@"
    </div>
    <div class="footer">
        Exported from SharePoint Online &bull; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    </div>
</div>
</body>
</html>
"@)

    $htmlContent = $htmlBuilder.ToString()
    [System.IO.File]::WriteAllText($htmlFile, $htmlContent, [System.Text.Encoding]::UTF8)

    Write-Host "  HTML report saved: $htmlFile" -ForegroundColor Green

    return $htmlFile
}

# ============================================================================
# SECTION 6: EXPORT - CSV
# ============================================================================

function Export-ToCSV {
    <#
    .SYNOPSIS
        Exports processed list data to CSV format with images saved separately.
    .DESCRIPTION
        Creates a CSV file with all text/data fields and a separate Images folder
        containing all downloaded images, named by item ID and field name.
        Image columns in the CSV contain the relative path to the saved image file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$ProcessedItems,

        [Parameter(Mandatory)]
        [string]$ListName,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$ImagesPath
    )

    $csvFile = Join-Path $OutputPath "${safeListName}_Data.csv"

    # Ensure images folder exists
    if (-not (Test-Path $ImagesPath)) {
        New-Item -ItemType Directory -Path $ImagesPath -Force | Out-Null
    }

    # Get all unique field names
    $allFieldNames = [ordered]@{}
    foreach ($item in $ProcessedItems) {
        foreach ($key in $item.FieldValues.Keys) {
            if (-not $allFieldNames.Contains($key)) {
                $allFieldNames[$key] = $true
            }
        }
    }

    $fieldNames = @($allFieldNames.Keys)

    # Determine image column names
    $imageColNames = $ProcessedItems.Images | Select-Object -ExpandProperty ColumnName -Unique -ErrorAction SilentlyContinue

    # Build CSV header
    $headers = @('ID') + $fieldNames
    if ($imageColNames) {
        $headers += ($imageColNames | ForEach-Object { "${_}_File" })
    }
    $headers += @('Attachment_Files')

    $csvRows = @()

    foreach ($item in $ProcessedItems) {
        $row = [ordered]@{
            'ID' = $item.Id
        }

        # Standard fields
        foreach ($fieldName in $fieldNames) {
            $value = $item.FieldValues[$fieldName]
            $row[$fieldName] = if ($null -eq $value) { '' } else { "$value" }
        }

        # Save images from Image columns and add path to CSV
        foreach ($colName in $imageColNames) {
            $img = $item.Images | Where-Object { $_.ColumnName -eq $colName } | Select-Object -First 1
            if ($img) {
                $imgFileName = "Item$($item.Id)_${colName}_$($img.FileName)"
                $imgFileName = $imgFileName -replace '[^\w\.\-]', '_'
                $imgPath = Join-Path $ImagesPath $imgFileName
                [System.IO.File]::WriteAllBytes($imgPath, $img.Bytes)
                $row["${colName}_File"] = "Images\$imgFileName"
            }
            else {
                $row["${colName}_File"] = ''
            }
        }

        # Save attachment images
        $attachmentNames = @()
        foreach ($att in $item.Attachments) {
            $attFileName = "Item$($item.Id)_Att_$($att.FileName)"
            $attFileName = $attFileName -replace '[^\w\.\-]', '_'
            $attPath = Join-Path $ImagesPath $attFileName
            [System.IO.File]::WriteAllBytes($attPath, $att.Bytes)
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
# SECTION 7: EXPORT - WORD / PDF (via COM Automation)
# ============================================================================

function Convert-HTMLToWord {
    <#
    .SYNOPSIS
        Converts an HTML file to Word (.docx) format using Word COM automation.
    .DESCRIPTION
        Opens the HTML report in Microsoft Word and saves it as a .docx file.
        Requires Microsoft Word to be installed on the machine.
        If Word is unavailable, returns $null and the caller should fall back to HTML.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HtmlFilePath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$ListName
    )

    $docxFile = Join-Path $OutputPath "${safeListName}_Report.docx"

    try {
        Write-Host "  Attempting Word COM conversion..." -ForegroundColor Gray

        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false
        $word.DisplayAlerts = 0  # wdAlertsNone

        # Open the HTML file in Word
        $doc = $word.Documents.Open($HtmlFilePath, $false, $true)

        # Save as .docx (wdFormatXMLDocument = 12)
        $doc.SaveAs2([ref]$docxFile, [ref]12)
        $doc.Close([ref]$false)
        $word.Quit()

        # Release COM objects
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc)  | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        Write-Host "  Word document saved: $docxFile" -ForegroundColor Green
        return $docxFile
    }
    catch {
        Write-Warning "Word COM automation unavailable: $($_.Exception.Message)"
        Write-Warning "The HTML report can be opened directly in Word as a fallback."

        # Clean up COM if partially created
        try {
            if ($word) { $word.Quit() }
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        }
        catch { }

        return $null
    }
}

function Convert-HTMLToPDF {
    <#
    .SYNOPSIS
        Converts an HTML file to PDF format using Word COM automation.
    .DESCRIPTION
        Opens the HTML report in Microsoft Word and exports it as a PDF.
        Requires Microsoft Word to be installed on the machine.
        If Word is unavailable, returns $null and the caller should fall back to HTML.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HtmlFilePath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$ListName
    )

    $pdfFile = Join-Path $OutputPath "${safeListName}_Report.pdf"

    try {
        Write-Host "  Attempting PDF conversion via Word COM..." -ForegroundColor Gray

        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false
        $word.DisplayAlerts = 0

        $doc = $word.Documents.Open($HtmlFilePath, $false, $true)

        # Export as PDF (wdExportFormatPDF = 17)
        $doc.ExportAsFixedFormat(
            $pdfFile,
            17,     # wdExportFormatPDF
            $false, # OpenAfterExport
            0,      # wdExportOptimizeForPrint
            0,      # Range = wdExportAllDocument
            0, 0,   # From/To page
            0       # Item = wdExportDocumentContent
        )

        $doc.Close([ref]$false)
        $word.Quit()

        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc)  | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        Write-Host "  PDF saved: $pdfFile" -ForegroundColor Green
        return $pdfFile
    }
    catch {
        Write-Warning "PDF conversion unavailable: $($_.Exception.Message)"
        Write-Warning "You can open the HTML report in a browser and use Print > Save as PDF."

        try {
            if ($word) { $word.Quit() }
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        }
        catch { }

        return $null
    }
}

# ============================================================================
# SECTION 8: MAIN EXECUTION
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  SharePoint Online List Exporter" -ForegroundColor Cyan
    Write-Host "  No external modules required" -ForegroundColor Gray
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Site:   $SiteUrl" -ForegroundColor White
    Write-Host "  List:   $ListName" -ForegroundColor White
    Write-Host "  Format: $ExportFormat" -ForegroundColor White
    Write-Host "  Output: $exportFolder" -ForegroundColor White
    Write-Host ""

    # -----------------------------------------------------------------------
    # Step 1: Authenticate
    # -----------------------------------------------------------------------
    Write-Host "[1/5] Authenticating..." -ForegroundColor Yellow

    $accessToken = Get-DeviceCodeAccessToken -ResourceUri $spResource -ClientId $ClientId

    if (-not $accessToken) {
        throw "Failed to obtain access token. Cannot continue."
    }

    # -----------------------------------------------------------------------
    # Step 2: Get list field definitions
    # -----------------------------------------------------------------------
    Write-Host "[2/5] Reading list schema..." -ForegroundColor Yellow

    $fields = Get-SPOListFields -SiteUrl $SiteUrl -ListName $ListName -AccessToken $accessToken

    if ($fields.Count -eq 0) {
        throw "No exportable fields found in list '$ListName'. Check the list name and your permissions."
    }

    Write-Host "  Fields found: $($fields.Count)" -ForegroundColor Green
    Write-Host "  Columns: $($fields.Title -join ', ')" -ForegroundColor Gray

    # -----------------------------------------------------------------------
    # Step 3: Retrieve all list items
    # -----------------------------------------------------------------------
    Write-Host "[3/5] Fetching list items..." -ForegroundColor Yellow

    $items = Get-SPOListItems -SiteUrl $SiteUrl -ListName $ListName -AccessToken $accessToken -PageSize $PageSize

    if ($items.Count -eq 0) {
        Write-Warning "The list '$ListName' contains no items. Nothing to export."
        return
    }

    # -----------------------------------------------------------------------
    # Step 4: Process items (extract data, download images)
    # -----------------------------------------------------------------------
    Write-Host "[4/5] Processing items and downloading images..." -ForegroundColor Yellow

    $processedItems = Build-ExportData -Items $items -Fields $fields -AccessToken $accessToken -SiteUrl $SiteUrl

    # -----------------------------------------------------------------------
    # Step 5: Export to requested format
    # -----------------------------------------------------------------------
    Write-Host "[5/5] Exporting data..." -ForegroundColor Yellow

    # Create output directories
    New-Item -ItemType Directory -Path $exportFolder -Force | Out-Null
    New-Item -ItemType Directory -Path $imagesFolder -Force | Out-Null

    # Always generate the HTML report (used as base for Word/PDF conversion)
    $htmlFile = Export-ToHTML -ProcessedItems $processedItems -ListName $ListName -OutputPath $exportFolder -SiteUrl $SiteUrl

    switch ($ExportFormat) {
        'CSV' {
            Export-ToCSV -ProcessedItems $processedItems -ListName $ListName -OutputPath $exportFolder -ImagesPath $imagesFolder
        }
        'Word' {
            $docxFile = Convert-HTMLToWord -HtmlFilePath $htmlFile -OutputPath $exportFolder -ListName $ListName
            if (-not $docxFile) {
                Write-Host ""
                Write-Host "  FALLBACK: HTML report generated instead." -ForegroundColor Yellow
                Write-Host "  You can open the .html file directly in Word." -ForegroundColor Yellow
            }
        }
        'PDF' {
            $pdfFile = Convert-HTMLToPDF -HtmlFilePath $htmlFile -OutputPath $exportFolder -ListName $ListName
            if (-not $pdfFile) {
                Write-Host ""
                Write-Host "  FALLBACK: HTML report generated instead." -ForegroundColor Yellow
                Write-Host "  Open the .html in a browser and use Print > Save as PDF." -ForegroundColor Yellow
            }
        }
        'HTML' {
            # Already generated above
        }
    }

    # Save all images to the Images subfolder regardless of format
    $imageCount = 0
    foreach ($item in $processedItems) {
        foreach ($img in $item.Images) {
            $imgFileName = "Item$($item.Id)_$($img.ColumnName)_$($img.FileName)" -replace '[^\w\.\-]', '_'
            $imgPath = Join-Path $imagesFolder $imgFileName
            [System.IO.File]::WriteAllBytes($imgPath, $img.Bytes)
            $imageCount++
        }
        foreach ($att in $item.Attachments) {
            $attFileName = "Item$($item.Id)_$($att.FileName)" -replace '[^\w\.\-]', '_'
            $attPath = Join-Path $imagesFolder $attFileName
            [System.IO.File]::WriteAllBytes($attPath, $att.Bytes)
            $imageCount++
        }
    }

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Green
    Write-Host "  EXPORT COMPLETE" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Green
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

    # Open the export folder in Explorer
    if ($env:OS -eq 'Windows_NT') {
        try {
            Start-Process explorer.exe -ArgumentList $exportFolder -ErrorAction SilentlyContinue
        }
        catch { }
    }
}

# Run the main function
try {
    # Ensure System.Web is loaded for HTML encoding
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    Main
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
