#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Retrieves user and shared mailboxes that exceed a specified quota usage threshold.

.DESCRIPTION
    This script connects to Exchange Online and identifies mailboxes that are using
    more than the specified percentage of their assigned quota (ProhibitSendReceiveQuota).
    Supports alphabetical batching by surname for large environments.
    Assumes you are already connected to Exchange Online.

.PARAMETER ThresholdPercent
    The percentage threshold for mailbox usage. Default is 75.

.PARAMETER LetterRange
    Filter mailboxes by surname starting letter. Format: "A-F", "G-K", "L-P", "Q-Z"
    Can also use single letters like "A" or "S".
    If not specified, processes all mailboxes.

.PARAMETER NoSurname
    Filter mailboxes that have no surname set (typically shared mailboxes).

.PARAMETER IncludeUnlimited
    If specified, includes mailboxes with unlimited quotas (they will show N/A usage).

.PARAMETER BatchSize
    Number of mailboxes to process in parallel. Default is 50.

.PARAMETER ShowDistribution
    Shows the distribution of mailboxes by surname letter and exits.

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ThresholdPercent 75 -LetterRange "A-F"

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ThresholdPercent 80 -NoSurname

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
    [switch]$NoSurname,

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

function Get-BytesFromValue {
    param ($Value)
    
    if ($null -eq $Value) {
        return 0
    }
    
    if ($Value -is [string]) {
        if ($Value -match '\(([0-9,]+) bytes\)') {
            return [long]($matches[1] -replace ',', '')
        }
        return 0
    }
    
    if ($Value.PSObject.Properties['Value'] -and $null -ne $Value.Value) {
        try {
            return $Value.Value.ToBytes()
        }
        catch {
            return 0
        }
    }
    
    try {
        return $Value.ToBytes()
    }
    catch {
        return 0
    }
}

# Check for conflicting parameters
if ($LetterRange -and $NoSurname) {
    Write-Error "Cannot use both -LetterRange and -NoSurname parameters together."
    exit 1
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "`nRetrieving User and Shared mailboxes..." -ForegroundColor Cyan

# Get all mailboxes with required properties
$allMailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox, SharedMailbox -ResultSize Unlimited -Properties ProhibitSendReceiveQuota, DisplayName, UserPrincipalName, RecipientTypeDetails

Write-Host "Found $($allMailboxes.Count) mailboxes." -ForegroundColor Green
Write-Host "Retrieving user details for surname information..." -ForegroundColor Cyan

# Get all users to retrieve LastName
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
    Write-Host "  -NoSurname (for '#' entries)" -ForegroundColor Gray
    
    $noSurnameCount = ($distribution | Where-Object { $_.Name -eq '#' }).Count
    if ($noSurnameCount -gt 0) {
        Write-Host "`nNote: '#' represents $noSurnameCount mailboxes with no surname set (typically shared mailboxes)" -ForegroundColor Yellow
        Write-Host "Use -NoSurname parameter to process these" -ForegroundColor Yellow
    }
    
    Write-Host "`nTotal mailboxes: $($allMailboxes.Count)" -ForegroundColor Cyan
    
    $stopwatch.Stop()
    Write-Host "Execution time: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds" -ForegroundColor Green
    return
}

# Filter by letter range or no surname
if ($NoSurname) {
    Write-Host "Filtering mailboxes with no surname set..." -ForegroundColor Yellow
    
    $mailboxes = $allMailboxes | Where-Object {
        $user = $userLookup[$_.UserPrincipalName.ToLower()]
        -not ($user -and $user.LastName)
    }
    
    Write-Host "Filtered to $($mailboxes.Count) mailboxes with no surname (from $($allMailboxes.Count) total)" -ForegroundColor Yellow
}
elseif ($LetterRange) {
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
    Write-Host "Processing ALL mailboxes. Consider using -LetterRange or -NoSurname to batch." -ForegroundColor Yellow
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

    # Check if quota is unlimited
    $isUnlimited = $false
    if ($null -eq $quotaValue) {
        $isUnlimited = $true
    }
    elseif ($quotaValue.PSObject.Properties['IsUnlimited'] -and $quotaValue.IsUnlimited) {
        $isUnlimited = $true
    }
    elseif ($quotaValue -is [string] -and $quotaValue -match 'unlimited') {
        $isUnlimited = $true
    }

    if ($isUnlimited) {
        if ($IncludeUnlimited) {
            $sizeBytes = Get-BytesFromValue -Value $stats.TotalItemSize
            
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

    # Get sizes using helper function
    $currentSizeBytes = Get-BytesFromValue -Value $stats.TotalItemSize
    $quotaBytes = Get-BytesFromValue -Value $quotaValue

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

# Summary
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
if ($LetterRange) {
    Write-Host "Letter range: $LetterRange" -ForegroundColor Yellow
}
if ($NoSurname) {
    Write-Host "Filter: Mailboxes with no surname" -ForegroundColor Yellow
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
