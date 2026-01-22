<#
.SYNOPSIS
    Exchange Online Mailbox Information Lookup Tool

.DESCRIPTION
    Retrieves mailbox information from Exchange Online using partial email prefix matching.
    Uses hashtables for optimized lookups and delta processing for efficient data handling.
    Connects to Exchange Online and imports only required commands for performance.

.OUTPUTS
    PSCustomObject containing:
    - DisplayName
    - MaxQuota (GB)
    - CurrentSize (GB)
    - ItemCount

.NOTES
    Version:        0.1
    Author:         SWP
    Creation Date:  22/01/2026
    Purpose:        Quick mailbox lookup by email prefix
    Requirements:   PowerShell 5.1, ExchangeOnlineManagement module
    UPN Domain:     Hardcoded in script configuration

.EXAMPLE
    .\Get-MailboxInfo.ps1
    # Prompts for email prefix and returns mailbox information

.EXAMPLE
    .\Get-MailboxInfo.ps1 -EmailPrefix "john.smith"
    # Returns mailbox info for john.smith@<configured-domain>

.CHANGELOG
    Version 0.1 - 22/01/2026
        - Initial release
        - Hashtable-based lookups for performance
        - Delta processing support
        - ExchangeGuid indexing for speed
        - Stopwatch timing output
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$EmailPrefix
)

#region Configuration
$Script:Config = @{
    UPNDomain = "yourdomain.com"  # CHANGE THIS: Your tenant domain
    CacheFile = "$env:TEMP\MailboxCache.xml"
    CacheMaxAgeMinutes = 60
}
#endregion Configuration

#region Variables
$Script:MailboxHashTable = @{}
$Script:StatisticsHashTable = @{}
$Script:LastSyncTime = $null
$Script:Stopwatch = $null
#endregion Variables

#region Functions

function Start-Timer {
    <#
    .SYNOPSIS
        Initializes and starts the stopwatch
    #>
    $Script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "Timer started"
}

function Stop-Timer {
    <#
    .SYNOPSIS
        Stops the stopwatch and outputs elapsed time
    #>
    if ($Script:Stopwatch) {
        $Script:Stopwatch.Stop()
        $elapsed = $Script:Stopwatch.Elapsed
        $minutes = [math]::Floor($elapsed.TotalMinutes)
        $seconds = $elapsed.Seconds

        Write-Host "`nExecution Time: $minutes min $seconds sec" -ForegroundColor Cyan
    }
}

function Connect-ExchangeSession {
    <#
    .SYNOPSIS
        Connects to Exchange Online with minimal command import
    #>
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow

    try {
        # Check if already connected
        $existingSession = Get-ConnectionInformation -ErrorAction SilentlyContinue

        if ($existingSession) {
            Write-Host "Already connected to Exchange Online" -ForegroundColor Green
            return $true
        }

        # Connect with only required commands for performance
        $commandsToLoad = @(
            "Get-Mailbox",
            "Get-MailboxStatistics",
            "Get-EXOMailbox",
            "Get-EXOMailboxStatistics"
        )

        Connect-ExchangeOnline -CommandName $commandsToLoad -ShowBanner:$false
        Write-Host "Connected successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $_"
        return $false
    }
}

function Import-CachedData {
    <#
    .SYNOPSIS
        Imports cached mailbox data if available and valid
    #>
    if (Test-Path $Script:Config.CacheFile) {
        try {
            $cacheData = Import-Clixml -Path $Script:Config.CacheFile
            $cacheAge = (Get-Date) - $cacheData.Timestamp

            if ($cacheAge.TotalMinutes -lt $Script:Config.CacheMaxAgeMinutes) {
                $Script:MailboxHashTable = $cacheData.Mailboxes
                $Script:StatisticsHashTable = $cacheData.Statistics
                $Script:LastSyncTime = $cacheData.Timestamp

                Write-Host "Loaded cached data from $($cacheData.Timestamp)" -ForegroundColor Green
                Write-Host "Cache contains $($Script:MailboxHashTable.Count) mailboxes" -ForegroundColor Gray
                return $true
            }
            else {
                Write-Verbose "Cache expired, will refresh"
            }
        }
        catch {
            Write-Verbose "Failed to load cache: $_"
        }
    }
    return $false
}

function Export-CachedData {
    <#
    .SYNOPSIS
        Exports current data to cache file
    #>
    try {
        $cacheData = @{
            Timestamp = Get-Date
            Mailboxes = $Script:MailboxHashTable
            Statistics = $Script:StatisticsHashTable
        }

        $cacheData | Export-Clixml -Path $Script:Config.CacheFile -Force
        Write-Verbose "Cache saved successfully"
    }
    catch {
        Write-Warning "Failed to save cache: $_"
    }
}

function Get-MailboxDataWithDelta {
    <#
    .SYNOPSIS
        Retrieves mailbox data using delta processing for efficiency
    #>
    Write-Host "Retrieving mailbox data..." -ForegroundColor Yellow

    # Get all mailboxes with ExchangeGuid for fast indexing
    $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties DisplayName, PrimarySmtpAddress, ExchangeGuid, ProhibitSendReceiveQuota

    $processedCount = 0
    $totalCount = ($mailboxes | Measure-Object).Count

    foreach ($mailbox in $mailboxes) {
        $guid = $mailbox.ExchangeGuid.ToString()

        # Delta check - only update if new or changed
        if (-not $Script:MailboxHashTable.ContainsKey($guid)) {
            $Script:MailboxHashTable[$guid] = @{
                DisplayName = $mailbox.DisplayName
                PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
                ExchangeGuid = $guid
                ProhibitSendReceiveQuota = $mailbox.ProhibitSendReceiveQuota
            }
        }

        $processedCount++
        if ($processedCount % 100 -eq 0) {
            Write-Progress -Activity "Loading Mailboxes" -Status "$processedCount of $totalCount" -PercentComplete (($processedCount / $totalCount) * 100)
        }
    }

    Write-Progress -Activity "Loading Mailboxes" -Completed
    Write-Host "Loaded $($Script:MailboxHashTable.Count) mailboxes into hashtable" -ForegroundColor Green
}

function Get-MailboxStatisticsData {
    <#
    .SYNOPSIS
        Retrieves statistics for a specific mailbox by ExchangeGuid
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExchangeGuid
    )

    # Check hashtable first for cached stats
    if ($Script:StatisticsHashTable.ContainsKey($ExchangeGuid)) {
        $cacheAge = (Get-Date) - $Script:StatisticsHashTable[$ExchangeGuid].Timestamp
        if ($cacheAge.TotalMinutes -lt 5) {
            Write-Verbose "Using cached statistics for $ExchangeGuid"
            return $Script:StatisticsHashTable[$ExchangeGuid]
        }
    }

    # Fetch fresh statistics using ExchangeGuid for speed
    Write-Host "Fetching mailbox statistics..." -ForegroundColor Yellow

    try {
        $stats = Get-EXOMailboxStatistics -ExchangeGuid $ExchangeGuid -Properties ItemCount, TotalItemSize

        # Cache the statistics
        $Script:StatisticsHashTable[$ExchangeGuid] = @{
            ItemCount = $stats.ItemCount
            TotalItemSize = $stats.TotalItemSize
            Timestamp = Get-Date
        }

        return $Script:StatisticsHashTable[$ExchangeGuid]
    }
    catch {
        Write-Error "Failed to get statistics: $_"
        return $null
    }
}

function Convert-QuotaToGB {
    <#
    .SYNOPSIS
        Converts Exchange quota string to GB value
    #>
    param(
        [Parameter(Mandatory = $true)]
        $QuotaValue
    )

    if ($QuotaValue -eq "Unlimited") {
        return "Unlimited"
    }

    $quotaString = $QuotaValue.ToString()

    # Extract bytes from quota string (format: "50 GB (53,687,091,200 bytes)")
    if ($quotaString -match '\(([0-9,]+)\s+bytes\)') {
        $bytes = [long]($Matches[1] -replace ',', '')
        return [math]::Round($bytes / 1GB, 2)
    }
    elseif ($quotaString -match '^([0-9.]+)\s*GB') {
        return [math]::Round([double]$Matches[1], 2)
    }

    return "Unknown"
}

function Convert-SizeToGB {
    <#
    .SYNOPSIS
        Converts Exchange size string to GB value
    #>
    param(
        [Parameter(Mandatory = $true)]
        $SizeValue
    )

    $sizeString = $SizeValue.ToString()

    # Extract bytes from size string
    if ($sizeString -match '\(([0-9,]+)\s+bytes\)') {
        $bytes = [long]($Matches[1] -replace ',', '')
        return [math]::Round($bytes / 1GB, 2)
    }

    return 0
}

function Find-MailboxByPrefix {
    <#
    .SYNOPSIS
        Finds mailbox in hashtable by email prefix
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    $searchEmail = "$Prefix@$($Script:Config.UPNDomain)"

    Write-Host "Searching for: $searchEmail" -ForegroundColor Cyan

    # Search hashtable for matching email
    $matchedMailbox = $null

    foreach ($key in $Script:MailboxHashTable.Keys) {
        $mailbox = $Script:MailboxHashTable[$key]
        if ($mailbox.PrimarySmtpAddress -ieq $searchEmail) {
            $matchedMailbox = $mailbox
            break
        }
    }

    return $matchedMailbox
}

function Get-MailboxInformation {
    <#
    .SYNOPSIS
        Main function to retrieve and display mailbox information
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    # Find mailbox in hashtable
    $mailbox = Find-MailboxByPrefix -Prefix $Prefix

    if (-not $mailbox) {
        Write-Warning "No mailbox found for prefix: $Prefix"
        Write-Host "Searched for: $Prefix@$($Script:Config.UPNDomain)" -ForegroundColor Gray
        return $null
    }

    Write-Host "Found mailbox: $($mailbox.DisplayName)" -ForegroundColor Green

    # Get statistics using ExchangeGuid
    $stats = Get-MailboxStatisticsData -ExchangeGuid $mailbox.ExchangeGuid

    if (-not $stats) {
        Write-Warning "Could not retrieve statistics"
        return $null
    }

    # Build output object
    $result = [PSCustomObject]@{
        DisplayName  = $mailbox.DisplayName
        EmailAddress = $mailbox.PrimarySmtpAddress
        MaxQuotaGB   = Convert-QuotaToGB -QuotaValue $mailbox.ProhibitSendReceiveQuota
        CurrentSizeGB = Convert-SizeToGB -SizeValue $stats.TotalItemSize
        ItemCount    = $stats.ItemCount
        ExchangeGuid = $mailbox.ExchangeGuid
    }

    return $result
}

#endregion Functions

#region Main Execution

# Start timing
Start-Timer

try {
    # Connect to Exchange Online
    if (-not (Connect-ExchangeSession)) {
        throw "Failed to establish Exchange Online connection"
    }

    # Try to load cached data first
    $cacheLoaded = Import-CachedData

    if (-not $cacheLoaded) {
        # Perform full sync if no cache
        Get-MailboxDataWithDelta
        Export-CachedData
    }

    # Get email prefix if not provided
    if ([string]::IsNullOrWhiteSpace($EmailPrefix)) {
        $EmailPrefix = Read-Host "`nEnter email prefix (before @)"
    }

    if ([string]::IsNullOrWhiteSpace($EmailPrefix)) {
        Write-Warning "No email prefix provided"
        return
    }

    # Get and display mailbox information
    $result = Get-MailboxInformation -Prefix $EmailPrefix

    if ($result) {
        Write-Host "`n" -NoNewline
        Write-Host "=" * 50 -ForegroundColor Cyan
        Write-Host "MAILBOX INFORMATION" -ForegroundColor Cyan
        Write-Host "=" * 50 -ForegroundColor Cyan

        $result | Format-List DisplayName, EmailAddress, MaxQuotaGB, CurrentSizeGB, ItemCount

        # Also output as object for pipeline use
        Write-Output $result
    }
}
catch {
    Write-Error "Script execution failed: $_"
}
finally {
    # Stop timing and display
    Stop-Timer

    # Save any updated cache data
    if ($Script:MailboxHashTable.Count -gt 0) {
        Export-CachedData
    }
}

#endregion Main Execution
