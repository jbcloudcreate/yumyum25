#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Retrieves user and shared mailboxes that exceed a specified quota usage threshold.

.DESCRIPTION
    This script connects to Exchange Online and identifies mailboxes that are using
    more than the specified percentage of their assigned quota (ProhibitSendReceiveQuota).
    Optimised for large environments using parallel processing and EXO cmdlets.

.PARAMETER ThresholdPercent
    The percentage threshold for mailbox usage. Default is 75.

.PARAMETER IncludeUnlimited
    If specified, includes mailboxes with unlimited quotas (they will show N/A usage).

.PARAMETER BatchSize
    Number of mailboxes to process in parallel. Default is 50.

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ThresholdPercent 75

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ThresholdPercent 80 -BatchSize 100
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$ThresholdPercent = 75,

    [Parameter()]
    [switch]$IncludeUnlimited,

    [Parameter()]
    [ValidateRange(10, 100)]
    [int]$BatchSize = 50
)

# Check if already connected to Exchange Online
try {
    $null = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "Already connected to Exchange Online." -ForegroundColor Green
}
catch {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false
        Write-Host "Successfully connected to Exchange Online." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $_"
        exit 1
    }
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "`nRetrieving User and Shared mailboxes..." -ForegroundColor Cyan
Write-Host "Threshold set to: $ThresholdPercent%" -ForegroundColor Cyan

# Use EXO cmdlet - REST-based and faster
# Only retrieve the properties we actually need
$mailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox, SharedMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, DisplayName, UserPrincipalName, RecipientTypeDetails

$totalCount = $mailboxes.Count
Write-Host "Found $totalCount mailboxes. Retrieving statistics...`n" -ForegroundColor Cyan

# Get all mailbox statistics in bulk using pipeline - much faster than individual calls
Write-Host "Fetching all mailbox statistics (this is the fastest method)..." -ForegroundColor Yellow

$allStats = @{}
$statsCount = 0

# Process in batches to show progress and avoid timeouts
$batches = [System.Collections.Generic.List[object[]]]::new()
for ($i = 0; $i -lt $mailboxes.Count; $i += $BatchSize) {
    $batch = $mailboxes[$i..([Math]::Min($i + $BatchSize - 1, $mailboxes.Count - 1))]
    $batches.Add($batch)
}

$batchNum = 0
foreach ($batch in $batches) {
    $batchNum++
    Write-Progress -Activity "Fetching Mailbox Statistics" -Status "Batch $batchNum of $($batches.Count)" -PercentComplete (($batchNum / $batches.Count) * 100)
    
    # Pipeline the batch to get statistics - EXO cmdlet is faster
    $batchStats = $batch | Get-EXOMailboxStatistics -Properties TotalItemSize, ItemCount -ErrorAction SilentlyContinue
    
    foreach ($stat in $batchStats) {
        if ($stat.MailboxGuid) {
            $allStats[$stat.MailboxGuid.ToString()] = $stat
            $statsCount++
        }
    }
}

Write-Progress -Activity "Fetching Mailbox Statistics" -Completed
Write-Host "Retrieved statistics for $statsCount mailboxes." -ForegroundColor Green

# Now process the results
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$skippedMailboxes = [System.Collections.Generic.List[PSCustomObject]]::new()
$processedCount = 0

Write-Host "Processing and filtering results..." -ForegroundColor Cyan

foreach ($mailbox in $mailboxes) {
    $processedCount++
    
    if ($processedCount % 500 -eq 0) {
        Write-Progress -Activity "Processing Results" -Status "$processedCount of $totalCount" -PercentComplete (($processedCount / $totalCount) * 100)
    }

    # Get stats from our hashtable
    $stats = $allStats[$mailbox.ExchangeGuid.ToString()]

    # Check if stats exist
    if ($null -eq $stats -or $null -eq $stats.TotalItemSize) {
        $skippedMailboxes.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            Reason            = "No mailbox statistics available"
        })
        continue
    }

    # Get the quota
    $quotaValue = $mailbox.ProhibitSendReceiveQuota

    # Check if quota is null or unlimited
    if ($null -eq $quotaValue -or $quotaValue.IsUnlimited) {
        if ($IncludeUnlimited) {
            # Handle the size - could be string or object
            $sizeBytes = 0
            if ($stats.TotalItemSize -is [string]) {
                if ($stats.TotalItemSize -match '\(([0-9,]+) bytes\)') {
                    $sizeBytes = [long]($matches[1] -replace ',', '')
                }
            }
            else {
                try { $sizeBytes = $stats.TotalItemSize.Value.ToBytes() } catch { $sizeBytes = 0 }
            }
            
            $results.Add([PSCustomObject]@{
                DisplayName       = $mailbox.DisplayName
                UserPrincipalName = $mailbox.UserPrincipalName
                RecipientType     = $mailbox.RecipientTypeDetails
                CurrentSizeGB     = [math]::Round(($sizeBytes / 1GB), 2)
                QuotaGB           = "Unlimited"
                UsagePercent      = "N/A"
                ItemCount         = $stats.ItemCount
            })
        }
        continue
    }

    # Parse sizes - EXO cmdlets sometimes return strings
    $currentSizeBytes = 0
    $quotaBytes = 0

    # Parse current size
    if ($stats.TotalItemSize -is [string]) {
        if ($stats.TotalItemSize -match '\(([0-9,]+) bytes\)') {
            $currentSizeBytes = [long]($matches[1] -replace ',', '')
        }
    }
    else {
        try { $currentSizeBytes = $stats.TotalItemSize.Value.ToBytes() } catch { $currentSizeBytes = 0 }
    }

    # Parse quota
    if ($quotaValue -is [string]) {
        if ($quotaValue -match '\(([0-9,]+) bytes\)') {
            $quotaBytes = [long]($matches[1] -replace ',', '')
        }
    }
    else {
        try { $quotaBytes = $quotaValue.Value.ToBytes() } catch { $quotaBytes = 0 }
    }

    # Avoid division by zero
    if ($quotaBytes -eq 0) {
        $skippedMailboxes.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            Reason            = "Unable to determine quota"
        })
        continue
    }

    # Calculate percentage used
    $usagePercent = [math]::Round(($currentSizeBytes / $quotaBytes) * 100, 2)

    # Check if over threshold
    if ($usagePercent -ge $ThresholdPercent) {
        $results.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            RecipientType     = $mailbox.RecipientTypeDetails
            CurrentSizeGB     = [math]::Round(($currentSizeBytes / 1GB), 2)
            QuotaGB           = [math]::Round(($quotaBytes / 1GB), 2)
            UsagePercent      = $usagePercent
            ItemCount         = $stats.ItemCount
        })
    }
}

Write-Progress -Activity "Processing Results" -Completed

$stopwatch.Stop()

# Display results
if ($results.Count -eq 0) {
    Write-Host "`nNo mailboxes found exceeding the $ThresholdPercent% threshold." -ForegroundColor Green
}
else {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " Mailboxes at or above $ThresholdPercent% usage" -ForegroundColor Cyan
    Write-Host " Total found: $($results.Count)" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Sort by usage percentage descending and display
    $results | Sort-Object { if ($_.UsagePercent -eq "N/A") { -1 } else { $_.UsagePercent } } -Descending |
        Format-Table -Property DisplayName, UserPrincipalName, RecipientType, CurrentSizeGB, QuotaGB, UsagePercent, ItemCount -AutoSize
}

# Display skipped mailboxes count
if ($skippedMailboxes.Count -gt 0) {
    Write-Host "`nSkipped $($skippedMailboxes.Count) mailboxes (no statistics available)" -ForegroundColor Yellow
    Write-Host "Use `$skippedMailboxes to view details" -ForegroundColor Gray
}

# Summary
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host "Total mailboxes scanned: $totalCount"
Write-Host "Mailboxes at or above $ThresholdPercent% threshold: $($results.Count)"
Write-Host "Mailboxes skipped: $($skippedMailboxes.Count)"
Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalMinutes, 2)) minutes" -ForegroundColor Green

if ($results.Count -gt 0) {
    $userCount = ($results | Where-Object { $_.RecipientType -eq 'UserMailbox' }).Count
    $sharedCount = ($results | Where-Object { $_.RecipientType -eq 'SharedMailbox' }).Count
    Write-Host "  - User Mailboxes: $userCount"
    Write-Host "  - Shared Mailboxes: $sharedCount"
}

# Store results in global variables for further use
$global:MailboxResults = $results
$global:SkippedMailboxes = $skippedMailboxes

Write-Host "`nResults stored in `$MailboxResults variable for further use." -ForegroundColor Gray
