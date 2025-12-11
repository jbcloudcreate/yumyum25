<#
.SYNOPSIS
    Track and report changes to Microsoft 365 endpoints over a specified time period.

.DESCRIPTION
    This script queries the Microsoft 365 IP Address & URL Web Service version history,
    compares endpoint changes over time, and generates a detailed report of additions,
    removals, and modifications to URLs and IP addresses.

.PARAMETER SinceDate
    The date from which to track changes. Can be a DateTime object or string (e.g., "2024-01-01").
    Default: 3 months ago.

.PARAMETER Instance
    Microsoft 365 instance to query. Valid values: "Worldwide","USGovDoD","USGovGCCHigh","China","Germany".
    Default: Worldwide.

.PARAMETER OutputPath
    Path where the change report will be saved. Default: ".\M365-Endpoint-Changes.txt"

.PARAMETER OutputFormat
    Format of the output report. Valid values: "Text","CSV","JSON","HTML".
    Default: Text.

.PARAMETER ServiceAreas
    Optional. Array of service-area names to filter (e.g. Exchange, SharePoint, Teams, Common).
    Default: all (no filtering).

.PARAMETER ChangeTypes
    Which types of changes to report. Valid values: "All","Added","Removed","Modified".
    Default: All.

.PARAMETER GroupBy
    How to group the changes in the report. Valid values: "Date","Category","ServiceArea".
    Default: Date.

.PARAMETER ClientRequestId
    GUID for the Microsoft 365 web service call. If not provided, a new GUID is generated.

.PARAMETER Verbose
    Provides verbose logging of steps, counts, and processing.

.EXAMPLE
    .\Get-M365EndpointChanges.ps1 -SinceDate "2024-09-01" -OutputPath "C:\Reports\M365-Changes.txt" -Verbose

.EXAMPLE
    .\Get-M365EndpointChanges.ps1 -SinceDate (Get-Date).AddMonths(-1) -ServiceAreas Exchange,Teams -ChangeTypes Added,Removed

.EXAMPLE
    .\Get-M365EndpointChanges.ps1 -SinceDate "2024-10-01" -OutputFormat HTML -GroupBy ServiceArea

.LINK
    https://docs.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service

#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Date from which to track changes (default: 3 months ago)")]
    [DateTime] $SinceDate = (Get-Date).AddMonths(-3),

    [Parameter(HelpMessage="Microsoft 365 instance")]
    [ValidateSet("Worldwide","USGovDoD","USGovGCCHigh","China","Germany")]
    [string] $Instance = "Worldwide",

    [Parameter(HelpMessage="Output path for the change report")]
    [string] $OutputPath = ".\M365-Endpoint-Changes.txt",

    [Parameter(HelpMessage="Output format for the report")]
    [ValidateSet("Text","CSV","JSON","HTML")]
    [string] $OutputFormat = "Text",

    [Parameter(HelpMessage="Service areas to filter (e.g., Exchange, SharePoint, Teams)")]
    [string[]] $ServiceAreas = @(),

    [Parameter(HelpMessage="Types of changes to report")]
    [ValidateSet("All","Added","Removed","Modified")]
    [string[]] $ChangeTypes = @("All"),

    [Parameter(HelpMessage="How to group changes in the report")]
    [ValidateSet("Date","Category","ServiceArea")]
    [string] $GroupBy = "Date",

    [Parameter(HelpMessage="Client request ID for tracking")]
    [Guid] $ClientRequestId = [guid]::NewGuid()
)

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }

    if ($VerbosePreference -eq 'Continue' -or $Level -ne 'Info') {
        Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    }
}

function Get-InstanceEndpoint {
    param([string]$Instance)

    $instanceMap = @{
        'Worldwide'      = 'worldwide'
        'USGovDoD'       = 'usdod'
        'USGovGCCHigh'   = 'usgovgcchigh'
        'China'          = 'china'
        'Germany'        = 'germany'
    }

    return $instanceMap[$Instance]
}

function Get-EndpointVersions {
    param(
        [string]$Instance,
        [DateTime]$SinceDate
    )

    $instanceEndpoint = Get-InstanceEndpoint -Instance $Instance
    $versionUrl = "https://endpoints.office.com/version/$instanceEndpoint`?allversions=true&format=rss&clientrequestid=$ClientRequestId"

    Write-Log "Fetching version history from: $versionUrl" -Level Info

    try {
        [xml]$rss = Invoke-RestMethod -Uri $versionUrl -Method Get -ErrorAction Stop
        $versions = $rss.rss.channel.item | ForEach-Object {
            [PSCustomObject]@{
                Version = $_.title
                PublishDate = [DateTime]::Parse($_.pubDate)
                Description = $_.description
            }
        } | Where-Object { $_.PublishDate -ge $SinceDate } | Sort-Object PublishDate

        Write-Log "Found $($versions.Count) version(s) since $($SinceDate.ToString('yyyy-MM-dd'))" -Level Info
        return $versions
    }
    catch {
        Write-Log "Failed to fetch version history: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-EndpointsForVersion {
    param(
        [string]$Instance,
        [string]$Version
    )

    $instanceEndpoint = Get-InstanceEndpoint -Instance $Instance
    $endpointUrl = "https://endpoints.office.com/endpoints/$instanceEndpoint`?clientrequestid=$ClientRequestId"
    
    if ($Version) {
        $endpointUrl += "&version=$Version"
    }

    try {
        $endpoints = Invoke-RestMethod -Uri $endpointUrl -Method Get -ErrorAction Stop
        return $endpoints
    }
    catch {
        Write-Log "Failed to fetch endpoints for version $Version`: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Compare-EndpointSets {
    param(
        [array]$OldEndpoints,
        [array]$NewEndpoints
    )

    $changes = @{
        Added = @()
        Removed = @()
        Modified = @()
    }

    # Create lookup dictionaries
    $oldDict = @{}
    $newDict = @{}

    foreach ($ep in $OldEndpoints) {
        $oldDict[$ep.id] = $ep
    }

    foreach ($ep in $NewEndpoints) {
        $newDict[$ep.id] = $ep
    }

    # Find added endpoints
    foreach ($id in $newDict.Keys) {
        if (-not $oldDict.ContainsKey($id)) {
            $changes.Added += $newDict[$id]
        }
    }

    # Find removed endpoints
    foreach ($id in $oldDict.Keys) {
        if (-not $newDict.ContainsKey($id)) {
            $changes.Removed += $oldDict[$id]
        }
    }

    # Find modified endpoints
    foreach ($id in $newDict.Keys) {
        if ($oldDict.ContainsKey($id)) {
            $oldEp = $oldDict[$id]
            $newEp = $newDict[$id]

            # Compare URLs
            $oldUrls = ($oldEp.urls | Sort-Object) -join ','
            $newUrls = ($newEp.urls | Sort-Object) -join ','

            # Compare IPs
            $oldIps = ($oldEp.ips | Sort-Object) -join ','
            $newIps = ($newEp.ips | Sort-Object) -join ','

            if ($oldUrls -ne $newUrls -or $oldIps -ne $newIps) {
                $changes.Modified += [PSCustomObject]@{
                    Id = $id
                    ServiceArea = $newEp.serviceArea
                    ServiceAreaDisplayName = $newEp.serviceAreaDisplayName
                    Category = $newEp.category
                    OldEndpoint = $oldEp
                    NewEndpoint = $newEp
                    UrlsAdded = @($newEp.urls | Where-Object { $_ -notin $oldEp.urls })
                    UrlsRemoved = @($oldEp.urls | Where-Object { $_ -notin $newEp.urls })
                    IpsAdded = @($newEp.ips | Where-Object { $_ -notin $oldEp.ips })
                    IpsRemoved = @($oldEp.ips | Where-Object { $_ -notin $newEp.ips })
                }
            }
        }
    }

    return $changes
}

# Validate output directory
$outputDir = Split-Path -Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    Write-Log "Creating output directory: $outputDir" -Level Info
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Write-Log "Starting M365 endpoint change tracking" -Level Info
Write-Log "Instance: $Instance" -Level Info
Write-Log "Since Date: $($SinceDate.ToString('yyyy-MM-dd'))" -Level Info
Write-Log "Output: $OutputPath (Format: $OutputFormat)" -Level Info

# Get version history
$versions = Get-EndpointVersions -Instance $Instance -SinceDate $SinceDate

if ($versions.Count -eq 0) {
    Write-Log "No versions found since $($SinceDate.ToString('yyyy-MM-dd')). No changes to report." -Level Warning
    return
}

# Get all endpoint snapshots for each version
Write-Log "Fetching endpoint data for $($versions.Count) version(s)..." -Level Info
$versionSnapshots = @()

foreach ($version in $versions) {
    Write-Verbose "Fetching endpoints for version $($version.Version) (Published: $($version.PublishDate))"
    $endpoints = Get-EndpointsForVersion -Instance $Instance -Version $version.Version

    # Apply service area filter if specified
    if ($ServiceAreas -and $ServiceAreas.Count -gt 0) {
        $endpoints = $endpoints | Where-Object { $ServiceAreas -contains $_.serviceAreaDisplayName }
    }

    $versionSnapshots += [PSCustomObject]@{
        Version = $version.Version
        PublishDate = $version.PublishDate
        Description = $version.Description
        Endpoints = $endpoints
    }
}

# Compare consecutive versions to find changes
$allChanges = @()
for ($i = 1; $i -lt $versionSnapshots.Count; $i++) {
    $oldSnapshot = $versionSnapshots[$i - 1]
    $newSnapshot = $versionSnapshots[$i]

    Write-Verbose "Comparing version $($oldSnapshot.Version) to $($newSnapshot.Version)"
    $changes = Compare-EndpointSets -OldEndpoints $oldSnapshot.Endpoints -NewEndpoints $newSnapshot.Endpoints

    if ($changes.Added.Count -gt 0 -or $changes.Removed.Count -gt 0 -or $changes.Modified.Count -gt 0) {
        $allChanges += [PSCustomObject]@{
            FromVersion = $oldSnapshot.Version
            ToVersion = $newSnapshot.Version
            PublishDate = $newSnapshot.PublishDate
            Description = $newSnapshot.Description
            Changes = $changes
        }
    }
}

if ($allChanges.Count -eq 0) {
    Write-Log "No changes detected between versions." -Level Warning
    "No changes detected for Microsoft 365 endpoints since $($SinceDate.ToString('yyyy-MM-dd'))" | 
        Set-Content -Path $OutputPath -Encoding UTF8
    Write-Log "Empty report written to $OutputPath" -Level Info
    return
}

Write-Log "Processing $($allChanges.Count) change set(s)..." -Level Info

# Generate report based on format
$reportContent = switch ($OutputFormat) {
    "Text" {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("="*80)
        [void]$sb.AppendLine("Microsoft 365 Endpoint Changes Report")
        [void]$sb.AppendLine("="*80)
        [void]$sb.AppendLine("Instance: $Instance")
        [void]$sb.AppendLine("Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine("Changes Since: $($SinceDate.ToString('yyyy-MM-dd'))")
        [void]$sb.AppendLine("Total Change Sets: $($allChanges.Count)")
        [void]$sb.AppendLine("="*80)
        [void]$sb.AppendLine()

        foreach ($changeSet in $allChanges) {
            [void]$sb.AppendLine("-"*80)
            [void]$sb.AppendLine("Version: $($changeSet.ToVersion)")
            [void]$sb.AppendLine("Published: $($changeSet.PublishDate.ToString('yyyy-MM-dd HH:mm:ss'))")
            [void]$sb.AppendLine("Description: $($changeSet.Description)")
            [void]$sb.AppendLine("-"*80)

            if (($ChangeTypes -contains "All" -or $ChangeTypes -contains "Added") -and $changeSet.Changes.Added.Count -gt 0) {
                [void]$sb.AppendLine()
                [void]$sb.AppendLine("ADDED ENDPOINTS ($($changeSet.Changes.Added.Count)):")
                [void]$sb.AppendLine()
                foreach ($ep in $changeSet.Changes.Added) {
                    [void]$sb.AppendLine("  [ID: $($ep.id)] $($ep.serviceAreaDisplayName) - Category: $($ep.category)")
                    if ($ep.urls) {
                        [void]$sb.AppendLine("    URLs:")
                        foreach ($url in $ep.urls) {
                            [void]$sb.AppendLine("      - $url")
                        }
                    }
                    if ($ep.ips) {
                        [void]$sb.AppendLine("    IPs:")
                        foreach ($ip in $ep.ips) {
                            [void]$sb.AppendLine("      - $ip")
                        }
                    }
                    [void]$sb.AppendLine()
                }
            }

            if (($ChangeTypes -contains "All" -or $ChangeTypes -contains "Removed") -and $changeSet.Changes.Removed.Count -gt 0) {
                [void]$sb.AppendLine()
                [void]$sb.AppendLine("REMOVED ENDPOINTS ($($changeSet.Changes.Removed.Count)):")
                [void]$sb.AppendLine()
                foreach ($ep in $changeSet.Changes.Removed) {
                    [void]$sb.AppendLine("  [ID: $($ep.id)] $($ep.serviceAreaDisplayName) - Category: $($ep.category)")
                    if ($ep.urls) {
                        [void]$sb.AppendLine("    URLs:")
                        foreach ($url in $ep.urls) {
                            [void]$sb.AppendLine("      - $url")
                        }
                    }
                    if ($ep.ips) {
                        [void]$sb.AppendLine("    IPs:")
                        foreach ($ip in $ep.ips) {
                            [void]$sb.AppendLine("      - $ip")
                        }
                    }
                    [void]$sb.AppendLine()
                }
            }

            if (($ChangeTypes -contains "All" -or $ChangeTypes -contains "Modified") -and $changeSet.Changes.Modified.Count -gt 0) {
                [void]$sb.AppendLine()
                [void]$sb.AppendLine("MODIFIED ENDPOINTS ($($changeSet.Changes.Modified.Count)):")
                [void]$sb.AppendLine()
                foreach ($mod in $changeSet.Changes.Modified) {
                    [void]$sb.AppendLine("  [ID: $($mod.Id)] $($mod.ServiceAreaDisplayName) - Category: $($mod.Category)")
                    
                    if ($mod.UrlsAdded.Count -gt 0) {
                        [void]$sb.AppendLine("    URLs Added:")
                        foreach ($url in $mod.UrlsAdded) {
                            [void]$sb.AppendLine("      + $url")
                        }
                    }
                    if ($mod.UrlsRemoved.Count -gt 0) {
                        [void]$sb.AppendLine("    URLs Removed:")
                        foreach ($url in $mod.UrlsRemoved) {
                            [void]$sb.AppendLine("      - $url")
                        }
                    }
                    if ($mod.IpsAdded.Count -gt 0) {
                        [void]$sb.AppendLine("    IPs Added:")
                        foreach ($ip in $mod.IpsAdded) {
                            [void]$sb.AppendLine("      + $ip")
                        }
                    }
                    if ($mod.IpsRemoved.Count -gt 0) {
                        [void]$sb.AppendLine("    IPs Removed:")
                        foreach ($ip in $mod.IpsRemoved) {
                            [void]$sb.AppendLine("      - $ip")
                        }
                    }
                    [void]$sb.AppendLine()
                }
            }

            [void]$sb.AppendLine()
        }

        [void]$sb.AppendLine("="*80)
        [void]$sb.AppendLine("End of Report")
        [void]$sb.AppendLine("="*80)
        
        $sb.ToString()
    }

    "CSV" {
        $csvData = @()
        foreach ($changeSet in $allChanges) {
            if ($ChangeTypes -contains "All" -or $ChangeTypes -contains "Added") {
                foreach ($ep in $changeSet.Changes.Added) {
                    $csvData += [PSCustomObject]@{
                        ChangeType = "Added"
                        Version = $changeSet.ToVersion
                        PublishDate = $changeSet.PublishDate.ToString('yyyy-MM-dd HH:mm:ss')
                        EndpointId = $ep.id
                        ServiceArea = $ep.serviceAreaDisplayName
                        Category = $ep.category
                        URLs = ($ep.urls -join '; ')
                        IPs = ($ep.ips -join '; ')
                    }
                }
            }

            if ($ChangeTypes -contains "All" -or $ChangeTypes -contains "Removed") {
                foreach ($ep in $changeSet.Changes.Removed) {
                    $csvData += [PSCustomObject]@{
                        ChangeType = "Removed"
                        Version = $changeSet.ToVersion
                        PublishDate = $changeSet.PublishDate.ToString('yyyy-MM-dd HH:mm:ss')
                        EndpointId = $ep.id
                        ServiceArea = $ep.serviceAreaDisplayName
                        Category = $ep.category
                        URLs = ($ep.urls -join '; ')
                        IPs = ($ep.ips -join '; ')
                    }
                }
            }

            if ($ChangeTypes -contains "All" -or $ChangeTypes -contains "Modified") {
                foreach ($mod in $changeSet.Changes.Modified) {
                    if ($mod.UrlsAdded.Count -gt 0 -or $mod.IpsAdded.Count -gt 0) {
                        $csvData += [PSCustomObject]@{
                            ChangeType = "Modified (Added)"
                            Version = $changeSet.ToVersion
                            PublishDate = $changeSet.PublishDate.ToString('yyyy-MM-dd HH:mm:ss')
                            EndpointId = $mod.Id
                            ServiceArea = $mod.ServiceAreaDisplayName
                            Category = $mod.Category
                            URLs = ($mod.UrlsAdded -join '; ')
                            IPs = ($mod.IpsAdded -join '; ')
                        }
                    }
                    if ($mod.UrlsRemoved.Count -gt 0 -or $mod.IpsRemoved.Count -gt 0) {
                        $csvData += [PSCustomObject]@{
                            ChangeType = "Modified (Removed)"
                            Version = $changeSet.ToVersion
                            PublishDate = $changeSet.PublishDate.ToString('yyyy-MM-dd HH:mm:ss')
                            EndpointId = $mod.Id
                            ServiceArea = $mod.ServiceAreaDisplayName
                            Category = $mod.Category
                            URLs = ($mod.UrlsRemoved -join '; ')
                            IPs = ($mod.IpsRemoved -join '; ')
                        }
                    }
                }
            }
        }

        $csvData | ConvertTo-Csv -NoTypeInformation | Out-String
    }

    "JSON" {
        $allChanges | ConvertTo-Json -Depth 10
    }

    "HTML" {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("<!DOCTYPE html>")
        [void]$sb.AppendLine("<html><head>")
        [void]$sb.AppendLine("<title>Microsoft 365 Endpoint Changes</title>")
        [void]$sb.AppendLine("<style>")
        [void]$sb.AppendLine("body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }")
        [void]$sb.AppendLine("h1 { color: #0078d4; }")
        [void]$sb.AppendLine("h2 { color: #106ebe; margin-top: 30px; }")
        [void]$sb.AppendLine("h3 { color: #005a9e; margin-top: 20px; }")
        [void]$sb.AppendLine(".metadata { background: #e1e1e1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }")
        [void]$sb.AppendLine(".changeset { background: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }")
        [void]$sb.AppendLine(".endpoint { margin-left: 20px; margin-bottom: 15px; border-left: 3px solid #0078d4; padding-left: 15px; }")
        [void]$sb.AppendLine(".added { border-left-color: #107c10; }")
        [void]$sb.AppendLine(".removed { border-left-color: #d13438; }")
        [void]$sb.AppendLine(".modified { border-left-color: #ff8c00; }")
        [void]$sb.AppendLine("ul { list-style-type: none; padding-left: 20px; }")
        [void]$sb.AppendLine("li { margin: 5px 0; }")
        [void]$sb.AppendLine(".add-symbol { color: #107c10; font-weight: bold; }")
        [void]$sb.AppendLine(".remove-symbol { color: #d13438; font-weight: bold; }")
        [void]$sb.AppendLine("</style>")
        [void]$sb.AppendLine("</head><body>")
        [void]$sb.AppendLine("<h1>Microsoft 365 Endpoint Changes Report</h1>")
        [void]$sb.AppendLine("<div class='metadata'>")
        [void]$sb.AppendLine("<strong>Instance:</strong> $Instance<br>")
        [void]$sb.AppendLine("<strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>")
        [void]$sb.AppendLine("<strong>Changes Since:</strong> $($SinceDate.ToString('yyyy-MM-dd'))<br>")
        [void]$sb.AppendLine("<strong>Total Change Sets:</strong> $($allChanges.Count)")
        [void]$sb.AppendLine("</div>")

        foreach ($changeSet in $allChanges) {
            [void]$sb.AppendLine("<div class='changeset'>")
            [void]$sb.AppendLine("<h2>Version $($changeSet.ToVersion)</h2>")
            [void]$sb.AppendLine("<p><strong>Published:</strong> $($changeSet.PublishDate.ToString('yyyy-MM-dd HH:mm:ss'))</p>")
            [void]$sb.AppendLine("<p><strong>Description:</strong> $($changeSet.Description)</p>")

            if (($ChangeTypes -contains "All" -or $ChangeTypes -contains "Added") -and $changeSet.Changes.Added.Count -gt 0) {
                [void]$sb.AppendLine("<h3>Added Endpoints ($($changeSet.Changes.Added.Count))</h3>")
                foreach ($ep in $changeSet.Changes.Added) {
                    [void]$sb.AppendLine("<div class='endpoint added'>")
                    [void]$sb.AppendLine("<strong>[ID: $($ep.id)]</strong> $($ep.serviceAreaDisplayName) - Category: $($ep.category)")
                    if ($ep.urls) {
                        [void]$sb.AppendLine("<ul><li><strong>URLs:</strong><ul>")
                        foreach ($url in $ep.urls) {
                            [void]$sb.AppendLine("<li>$url</li>")
                        }
                        [void]$sb.AppendLine("</ul></li></ul>")
                    }
                    if ($ep.ips) {
                        [void]$sb.AppendLine("<ul><li><strong>IPs:</strong><ul>")
                        foreach ($ip in $ep.ips) {
                            [void]$sb.AppendLine("<li>$ip</li>")
                        }
                        [void]$sb.AppendLine("</ul></li></ul>")
                    }
                    [void]$sb.AppendLine("</div>")
                }
            }

            if (($ChangeTypes -contains "All" -or $ChangeTypes -contains "Removed") -and $changeSet.Changes.Removed.Count -gt 0) {
                [void]$sb.AppendLine("<h3>Removed Endpoints ($($changeSet.Changes.Removed.Count))</h3>")
                foreach ($ep in $changeSet.Changes.Removed) {
                    [void]$sb.AppendLine("<div class='endpoint removed'>")
                    [void]$sb.AppendLine("<strong>[ID: $($ep.id)]</strong> $($ep.serviceAreaDisplayName) - Category: $($ep.category)")
                    if ($ep.urls) {
                        [void]$sb.AppendLine("<ul><li><strong>URLs:</strong><ul>")
                        foreach ($url in $ep.urls) {
                            [void]$sb.AppendLine("<li>$url</li>")
                        }
                        [void]$sb.AppendLine("</ul></li></ul>")
                    }
                    if ($ep.ips) {
                        [void]$sb.AppendLine("<ul><li><strong>IPs:</strong><ul>")
                        foreach ($ip in $ep.ips) {
                            [void]$sb.AppendLine("<li>$ip</li>")
                        }
                        [void]$sb.AppendLine("</ul></li></ul>")
                    }
                    [void]$sb.AppendLine("</div>")
                }
            }

            if (($ChangeTypes -contains "All" -or $ChangeTypes -contains "Modified") -and $changeSet.Changes.Modified.Count -gt 0) {
                [void]$sb.AppendLine("<h3>Modified Endpoints ($($changeSet.Changes.Modified.Count))</h3>")
                foreach ($mod in $changeSet.Changes.Modified) {
                    [void]$sb.AppendLine("<div class='endpoint modified'>")
                    [void]$sb.AppendLine("<strong>[ID: $($mod.Id)]</strong> $($mod.ServiceAreaDisplayName) - Category: $($mod.Category)")
                    
                    if ($mod.UrlsAdded.Count -gt 0) {
                        [void]$sb.AppendLine("<ul><li><strong>URLs Added:</strong><ul>")
                        foreach ($url in $mod.UrlsAdded) {
                            [void]$sb.AppendLine("<li><span class='add-symbol'>+</span> $url</li>")
                        }
                        [void]$sb.AppendLine("</ul></li></ul>")
                    }
                    if ($mod.UrlsRemoved.Count -gt 0) {
                        [void]$sb.AppendLine("<ul><li><strong>URLs Removed:</strong><ul>")
                        foreach ($url in $mod.UrlsRemoved) {
                            [void]$sb.AppendLine("<li><span class='remove-symbol'>-</span> $url</li>")
                        }
                        [void]$sb.AppendLine("</ul></li></ul>")
                    }
                    if ($mod.IpsAdded.Count -gt 0) {
                        [void]$sb.AppendLine("<ul><li><strong>IPs Added:</strong><ul>")
                        foreach ($ip in $mod.IpsAdded) {
                            [void]$sb.AppendLine("<li><span class='add-symbol'>+</span> $ip</li>")
                        }
                        [void]$sb.AppendLine("</ul></li></ul>")
                    }
                    if ($mod.IpsRemoved.Count -gt 0) {
                        [void]$sb.AppendLine("<ul><li><strong>IPs Removed:</strong><ul>")
                        foreach ($ip in $mod.IpsRemoved) {
                            [void]$sb.AppendLine("<li><span class='remove-symbol'>-</span> $ip</li>")
                        }
                        [void]$sb.AppendLine("</ul></li></ul>")
                    }
                    [void]$sb.AppendLine("</div>")
                }
            }

            [void]$sb.AppendLine("</div>")
        }

        [void]$sb.AppendLine("</body></html>")
        $sb.ToString()
    }
}

# Write report to file
try {
    $encoding = if ($OutputFormat -eq "Text") { "UTF8" } else { "UTF8" }
    $reportContent | Set-Content -Path $OutputPath -Encoding $encoding -ErrorAction Stop
    Write-Log "Successfully wrote change report to $OutputPath" -Level Info
    
    # Summary statistics
    $totalAdded = ($allChanges.Changes.Added | Measure-Object).Count
    $totalRemoved = ($allChanges.Changes.Removed | Measure-Object).Count
    $totalModified = ($allChanges.Changes.Modified | Measure-Object).Count
    
    Write-Log "Summary:" -Level Info
    Write-Log "  - Total Added: $totalAdded" -Level Info
    Write-Log "  - Total Removed: $totalRemoved" -Level Info
    Write-Log "  - Total Modified: $totalModified" -Level Info
}
catch {
    Write-Log "Failed to write report: $($_.Exception.Message)" -Level Error
    throw
}

Write-Log "Change report generation completed successfully" -Level Info
