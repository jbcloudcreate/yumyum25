#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Retrieves user and shared mailboxes that exceed a specified quota usage threshold.

.DESCRIPTION
    This script connects to Exchange Online and identifies mailboxes that are using
    more than the specified percentage of their assigned quota (ProhibitSendReceiveQuota).

.PARAMETER ThresholdPercent
    The percentage threshold for mailbox usage. Default is 75.

.PARAMETER IncludeUnlimited
    If specified, includes mailboxes with unlimited quotas (they will show 0% usage).

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ThresholdPercent 75

.EXAMPLE
    .\Get-MailboxesOverThreshold.ps1 -ThresholdPercent 80 -IncludeUnlimited
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$ThresholdPercent = 75,

    [Parameter()]
    [switch]$IncludeUnlimited
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

Write-Host "`nRetrieving User and Shared mailboxes..." -ForegroundColor Cyan
Write-Host "Threshold set to: $ThresholdPercent%" -ForegroundColor Cyan
Write-Host "This may take a while depending on the number of mailboxes...`n" -ForegroundColor Yellow

# Get all user and shared mailboxes
$mailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox, SharedMailbox -ResultSize Unlimited

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$skippedMailboxes = [System.Collections.Generic.List[PSCustomObject]]::new()
$processedCount = 0
$totalCount = $mailboxes.Count

foreach ($mailbox in $mailboxes) {
    $processedCount++
    Write-Progress -Activity "Processing Mailboxes" -Status "$processedCount of $totalCount - $($mailbox.UserPrincipalName)" -PercentComplete (($processedCount / $totalCount) * 100)

    try {
        # Get mailbox statistics
        $stats = Get-MailboxStatistics -Identity $mailbox.Identity -ErrorAction Stop

        # Check if stats or TotalItemSize is null (mailbox never accessed)
        if ($null -eq $stats -or $null -eq $stats.TotalItemSize -or $null -eq $stats.TotalItemSize.Value) {
            $skippedMailboxes.Add([PSCustomObject]@{
                DisplayName       = $mailbox.DisplayName
                UserPrincipalName = $mailbox.UserPrincipalName
                Reason            = "No mailbox statistics available (never accessed)"
            })
            continue
        }

        # Get the quota - use ProhibitSendReceiveQuota as the main limit
        $quotaValue = $mailbox.ProhibitSendReceiveQuota

        # Check if quota is null or unlimited
        if ($null -eq $quotaValue -or $quotaValue.IsUnlimited) {
            if ($IncludeUnlimited) {
                $results.Add([PSCustomObject]@{
                    DisplayName       = $mailbox.DisplayName
                    UserPrincipalName = $mailbox.UserPrincipalName
                    RecipientType     = $mailbox.RecipientTypeDetails
                    CurrentSizeGB     = [math]::Round(($stats.TotalItemSize.Value.ToBytes() / 1GB), 2)
                    QuotaGB           = "Unlimited"
                    UsagePercent      = "N/A"
                    ItemCount         = $stats.ItemCount
                })
            }
            continue
        }

        # Check if quota value is accessible
        if ($null -eq $quotaValue.Value) {
            $skippedMailboxes.Add([PSCustomObject]@{
                DisplayName       = $mailbox.DisplayName
                UserPrincipalName = $mailbox.UserPrincipalName
                Reason            = "Unable to determine quota value"
            })
            continue
        }

        # Calculate quota in bytes
        $quotaBytes = $quotaValue.Value.ToBytes()
        
        # Avoid division by zero
        if ($quotaBytes -eq 0) {
            $skippedMailboxes.Add([PSCustomObject]@{
                DisplayName       = $mailbox.DisplayName
                UserPrincipalName = $mailbox.UserPrincipalName
                Reason            = "Quota is set to zero"
            })
            continue
        }

        $currentSizeBytes = $stats.TotalItemSize.Value.ToBytes()

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
    catch {
        $skippedMailboxes.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            Reason            = $_.Exception.Message
        })
    }
}

Write-Progress -Activity "Processing Mailboxes" -Completed

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

# Display skipped mailboxes if any
if ($skippedMailboxes.Count -gt 0) {
    Write-Host "`n--- Skipped Mailboxes ($($skippedMailboxes.Count)) ---" -ForegroundColor Yellow
    $skippedMailboxes | Format-Table -Property DisplayName, UserPrincipalName, Reason -AutoSize -Wrap
}

# Summary
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
Write-Host "Total mailboxes scanned: $totalCount"
Write-Host "Mailboxes at or above $ThresholdPercent% threshold: $($results.Count)"
Write-Host "Mailboxes skipped: $($skippedMailboxes.Count)" -ForegroundColor Yellow
if ($results.Count -gt 0) {
    $userCount = ($results | Where-Object { $_.RecipientType -eq 'UserMailbox' }).Count
    $sharedCount = ($results | Where-Object { $_.RecipientType -eq 'SharedMailbox' }).Count
    Write-Host "  - User Mailboxes: $userCount"
    Write-Host "  - Shared Mailboxes: $sharedCount"
}
