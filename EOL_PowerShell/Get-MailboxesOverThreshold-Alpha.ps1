#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Retrieves user and shared mailboxes that exceed a specified quota usage threshold.

.DESCRIPTION
    This script connects to Exchange Online and identifies mailboxes that are using
    more than the specified percentage of their assigned quota (ProhibitSendReceiveQuota).
    Supports alphabetical batching by surname for large environments.

.PARAMETER ThresholdPercent
    The percentage threshold for mailbox usage. Default is 75.

.PARAMETER LetterRange
    Filter mailboxes by surname starting letter. Format: "A-F", "G-K", "L-P", "Q-Z"
    Can also use single letters like "A" or "S".
    If not specified, processes all mailboxes.

.PARAMETER IncludeUnlimited
    If specified, includes mailboxes with unlimited quotas (they will show N/A usage).

.PARAMETER BatchSize
    Number of mailboxes to process in parallel. Default is 50.

.PARAMETER ShowDistribution
    Shows the distribution of mailboxes by surname letter and exits.

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ThresholdPercent 75 -LetterRange "A-F"

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ThresholdPercent 80 -LetterRange "G-K"

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ShowDistribution
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$ThresholdPercent = 75,

    [Parameter()]
    [ValidatePattern('^[A-Za-z](-[A-Za-z])?$')]
    [string]$LetterRange,

    [Parameter()]
    [switch]$IncludeUnlimited,

    [Parameter()]
    [ValidateRange(10, 100)]
    [int]$BatchSize = 50,

    [Parameter()]
    [switch]$ShowDistribution
)

function Get-LettersInRange {
    param ([string]$Range)
    
    if ($Range -match '^([A-Za-z])-([A-Za-z])$') {
        $start = [char]::ToUpper($matches[1])
        $end = [char]::ToUpper($matches[2])
        
        if ([int]$start -gt [int]$end) {
            $start, $end = $end, $start
        }
        
        $letters = @()
        for ($i = [int]$start; $i -le [int]$end; $i++) {
            $letters += [char]$i
        }
        return $letters
    }
    elseif ($Range -match '^([A-Za-z])$') {
        return @([char]::ToUpper($matches[1]))
    }
    
    return @()
}

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

# Get all mailboxes with required properties (without LastName - not supported by Get-EXOMailbox)
$allMailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox, SharedMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, DisplayName, UserPrincipalName, RecipientTypeDetails

Write-Host "Found $($allMailboxes.Count) mailboxes." -ForegroundColor Green
Write-Host "Retrieving user details for surname information..." -ForegroundColor Cyan

# Get all users to retrieve LastName - this is part of Exchange Online Management module
$allUsers = Get-User -ResultSize Unlimited | Select-Object UserPrincipalName, LastName, FirstName

# Create a lookup hashtable for fast surname retrieval
$userLookup = @{}
foreach ($user in $allUsers) {
    if ($user.UserPrincipalName) {
        $userLookup[$user.UserPrincipalName.ToLower()] = $user
    }
}

Write-Host "Retrieved details for $($allUsers.Count) users." -ForegroundColor Green

# Show distribution and exit if requested
if ($ShowDistribution) {
    Write-Host "`n--- Mailbox Distribution by Surname ---`n" -ForegroundColor Cyan
    
    $distribution = $allMailboxes | Group-Object { 
        $user = $userLookup[$_.UserPrincipalName.ToLower()]
        if ($user -and $user.LastName) { 
            $user.LastName.Substring(0,1).ToUpper() 
        } else { 
            '#' 
        } 
    } | Sort-Object Name
    
    $distribution | Format-Table @{L='Letter';E={$_.Name}}, @{L='Count';E={$_.Count}}, @{L='Percentage';E={'{0:P1}' -f ($_.Count / $allMailboxes.Count)}} -AutoSize
    
    Write-Host "`nSuggested batches:" -ForegroundColor Yellow
    Write-Host "  -LetterRange 'A-D'" -ForegroundColor Gray
    Write-Host "  -LetterRange 'E-H'" -ForegroundColor Gray
    Write-Host "  -LetterRange 'I-L'" -ForegroundColor Gray
    Write-Host "  -LetterRange 'M-P'" -ForegroundColor Gray
    Write-Host "  -LetterRange 'Q-T'" -ForegroundColor Gray
    Write-Host "  -LetterRange 'U-Z'" -ForegroundColor Gray
    
    $noSurnameCount = ($distribution | Where-Object { $_.Name -eq '#' }).Count
    if ($noSurnameCount -gt 0) {
        Write-Host "`nNote: '#' represents $noSurnameCount mailboxes with no surname set" -ForegroundColor Yellow
    }
    
    Write-Host "`nTotal mailboxes: $($allMailboxes.Count)" -ForegroundColor Cyan
    
    $stopwatch.Stop()
    Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green
    return
}

# Filter by letter range if specified
if ($LetterRange) {
    $letters = Get-LettersInRange -Range $LetterRange
    
    if ($letters.Count -eq 0) {
        Write-Error "Invalid letter range format. Use format like 'A-F' or 'G-K' or single letter 'A'"
        exit 1
    }
    
    Write-Host "Filtering mailboxes with surnames starting: $($letters -join ', ')" -ForegroundColor Yellow
    
    $mailboxes = $allMailboxes | Where-Object {
        $user = $userLookup[$_.UserPrincipalName.ToLower()]
        if ($user -and $user.LastName) {
            $firstLetter = $user.LastName.Substring(0,1).ToUpper()
            $letters -contains $firstLetter
        }
        else {
            $false
        }
    }
    
    Write-Host "Filtered to $($mailboxes.Count) mailboxes (from $($allMailboxes.Count) total)" -ForegroundColor Yellow
}
else {
    $mailboxes = $allMailboxes
    Write-Host "Processing ALL mailboxes. Consider using -LetterRange to batch." -ForegroundColor Yellow
    Write-Host "Use -ShowDistribution to see mailbox counts by surname letter.`n" -ForegroundColor Gray
}

$totalCount = $mailboxes.Count

if ($totalCount -eq 0) {
    Write-Host "`nNo mailboxes found matching the criteria." -ForegroundColor Yellow
    exit 0
}

Write-Host "Threshold set to: $ThresholdPercent%" -ForegroundColor Cyan
Write-Host "Processing $totalCount mailboxes...`n" -ForegroundColor Cyan

# Get mailbox statistics in batches
Write-Host "Fetching mailbox statistics..." -ForegroundColor Yellow

$allStats = @{}
$batches = [System.Collections.Generic.List[object[]]]::new()

for ($i = 0; $i -lt $mailboxes.Count; $i += $BatchSize) {
    $batch = @($mailboxes[$i..([Math]::Min($i + $BatchSize - 1, $mailboxes.Count - 1))])
    $batches.Add($batch)
}

$batchNum = 0
foreach ($batch in $batches) {
    $batchNum++
    Write-Progress -Activity "Fetching Mailbox Statistics" -Status "Batch $batchNum of $($batches.Count)" -PercentComplete (($batchNum / $batches.Count) * 100)
    
    $batchStats = $batch | Get-EXOMailboxStatistics -Properties TotalItemSize, ItemCount -ErrorAction SilentlyContinue
    
    foreach ($stat in $batchStats) {
        if ($stat.MailboxGuid) {
            $allStats[$stat.MailboxGuid.ToString()] = $stat
        }
    }
}

Write-Progress -Activity "Fetching Mailbox Statistics" -Completed
Write-Host "Retrieved statistics for $($allStats.Count) mailboxes." -ForegroundColor Green

# Process results
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$skippedMailboxes = [System.Collections.Generic.List[PSCustomObject]]::new()
$processedCount = 0

Write-Host "Processing and filtering results..." -ForegroundColor Cyan

foreach ($mailbox in $mailboxes) {
    $processedCount++
    
    if ($processedCount % 500 -eq 0) {
        Write-Progress -Activity "Processing Results" -Status "$processedCount of $totalCount" -PercentComplete (($processedCount / $totalCount) * 100)
    }

    # Get user details from lookup
    $user = $userLookup[$mailbox.UserPrincipalName.ToLower()]
    $lastName = if ($user) { $user.LastName } else { $null }

    $stats = $allStats[$mailbox.ExchangeGuid.ToString()]

    if ($null -eq $stats -or $null -eq $stats.TotalItemSize) {
        $skippedMailboxes.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            LastName          = $lastName
            Reason            = "No mailbox statistics available"
        })
        continue
    }

    $quotaValue = $mailbox.ProhibitSendReceiveQuota

    if ($null -eq $quotaValue -or $quotaValue.IsUnlimited) {
        if ($IncludeUnlimited) {
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
                LastName          = $lastName
                RecipientType     = $mailbox.RecipientTypeDetails
                CurrentSizeGB     = [math]::Round(($sizeBytes / 1GB), 2)
                QuotaGB           = "Unlimited"
                UsagePercent      = "N/A"
                ItemCount         = $stats.ItemCount
            })
        }
        continue
    }

    $currentSizeBytes = 0
    $quotaBytes = 0

    if ($stats.TotalItemSize -is [string]) {
        if ($stats.TotalItemSize -match '\(([0-9,]+) bytes\)') {
            $currentSizeBytes = [long]($matches[1] -replace ',', '')
        }
    }
    else {
        try { $currentSizeBytes = $stats.TotalItemSize.Value.ToBytes() } catch { $currentSizeBytes = 0 }
    }

    if ($quotaValue -is [string]) {
        if ($quotaValue -match '\(([0-9,]+) bytes\)') {
            $quotaBytes = [long]($matches[1] -replace ',', '')
        }
    }
    else {
        try { $quotaBytes = $quotaValue.Value.ToBytes() } catch { $quotaBytes = 0 }
    }

    if ($quotaBytes -eq 0) {
        $skippedMailboxes.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            LastName          = $lastName
            Reason            = "Unable to determine quota"
        })
        continue
    }

    $usagePercent = [math]::Round(($currentSizeBytes / $quotaBytes) * 100, 2)

    if ($usagePercent -ge $ThresholdPercent) {
        $results.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            LastName          = $lastName
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
$rangeLabel = if ($LetterRange) { " (Surnames: $LetterRange)" } else { "" }

if ($results.Count -eq 0) {
    Write-Host "`nNo mailboxes found exceeding the $ThresholdPercent% threshold$rangeLabel." -ForegroundColor Green
}
else {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " Mailboxes at or above $ThresholdPercent% usage$rangeLabel" -ForegroundColor Cyan
    Write-Host " Total found: $($results.Count)" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $results | Sort-Object { if ($_.UsagePercent -eq "N/A") { -1 } else { $_.UsagePercent } } -Descending |
        Format-Table -Property DisplayName, LastName, UserPrincipalName, RecipientType, CurrentSizeGB, QuotaGB, UsagePercent, ItemCount -AutoSize
}

if ($skippedMailboxes.Count -gt 0) {
    Write-Host "`nSkipped $($skippedMailboxes.Count) mailboxes (no statistics available)" -ForegroundColor Yellow
}

# Summary
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
if ($LetterRange) {
    Write-Host "Letter range: $LetterRange" -ForegroundColor Yellow
}
Write-Host "Mailboxes scanned: $totalCount"
Write-Host "Mailboxes at or above $ThresholdPercent% threshold: $($results.Count)"
Write-Host "Mailboxes skipped: $($skippedMailboxes.Count)"
Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalMinutes, 2)) minutes" -ForegroundColor Green

if ($results.Count -gt 0) {
    $userCount = ($results | Where-Object { $_.RecipientType -eq 'UserMailbox' }).Count
    $sharedCount = ($results | Where-Object { $_.RecipientType -eq 'SharedMailbox' }).Count
    Write-Host "  - User Mailboxes: $userCount"
    Write-Host "  - Shared Mailboxes: $sharedCount"
}

# Store results in global variables
$global:MailboxResults = $results
$global:SkippedMailboxes = $skippedMailboxes

Write-Host "`nResults stored in `$MailboxResults variable." -ForegroundColor Gray
Write-Host "Export with: `$MailboxResults | Export-Csv -Path 'Mailboxes_$($LetterRange -replace '-','to').csv' -NoTypeInformation" -ForegroundColor Gray
