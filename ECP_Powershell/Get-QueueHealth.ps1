<#
.SYNOPSIS
    Reports transport queue health across Exchange SE mailbox servers.

.DESCRIPTION
    - Finds transport servers automatically (or uses -Server)
    - Excludes shadow redundancy queues by filtering on the server side
    - Sums messages per server, counts retry queues, and checks the poison queue
    - Marks each server OK / WARNING / CRITICAL / UNREACHABLE
    - Returns objects, so you can format, sort or export them at the end of the pipeline
    Run it from the Exchange Management Shell.

.EXAMPLE
    .\Get-QueueHealth.ps1 | Format-Table -AutoSize

.EXAMPLE
    .\Get-QueueHealth.ps1 -Server SWPHQ-MBS01,SWPHQ-MBS02 -WarningThreshold 50

.EXAMPLE
    .\Get-QueueHealth.ps1 -LogPath D:\Logs\QueueHealth |
        Export-Csv .\QueueHealth.csv -NoTypeInformation -Append
#>
[CmdletBinding()]
param(
    # Servers to check. If you leave this out, it finds transport services that match -NameLike.
    [string[]]$Server,

    [string]$NameLike = 'SWPHQ-MBS*',

    [int]$WarningThreshold  = 100,
    [int]$CriticalThreshold = 500,

    # Folder for the transcript log. If you leave this out, nothing is logged.
    [string]$LogPath
)

function Write-Section {
    param([string]$Text)
    if ($LogPath) { Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] === {1} ===" -f (Get-Date), $Text) }
}

if (-not (Get-Command Get-Queue -ErrorAction SilentlyContinue)) {
    throw 'Get-Queue not found - run this from the Exchange Management Shell.'
}

if ($LogPath) {
    if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    Start-Transcript -Path (Join-Path $LogPath ("QueueHealth_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))) | Out-Null
}

try {
    Write-Section 'Discovering transport servers'
    if (-not $Server) {
        # Get the whole collection before looping. Piping one Exchange cmdlet straight into
        # another inside ForEach-Object can fail in EMS with "Pipelines cannot be executed concurrently".
        $Server = @(Get-TransportService | Where-Object Name -like $NameLike).Name | Sort-Object
    }
    if (-not $Server) { throw "No transport servers matched '$NameLike'." }

    Write-Section ("Checking queues on: {0}" -f ($Server -join ', '))
    $results = foreach ($s in $Server) {
        try {
            $queues = @(Get-Queue -Server $s -Filter "DeliveryType -ne 'ShadowRedundancy'" -ErrorAction Stop)

            $total  = [int]($queues | Measure-Object MessageCount -Sum).Sum
            $retry  = @($queues | Where-Object Status -eq 'Retry')
            $poison = [int]($queues | Where-Object { "$($_.Identity)" -like '*\Poison' } |
                            Measure-Object MessageCount -Sum).Sum
            $top    = $queues | Sort-Object MessageCount -Descending | Select-Object -First 1

            $state = if ($poison -gt 0 -or $total -ge $CriticalThreshold) { 'CRITICAL' }
                     elseif ($retry.Count -gt 0 -or $total -ge $WarningThreshold) { 'WARNING' }
                     else { 'OK' }

            [PSCustomObject]@{
                Server       = $s
                State        = $state
                Messages     = $total
                Queues       = $queues.Count
                RetryQueues  = $retry.Count
                Poison       = $poison
                BusiestQueue = if ($top.MessageCount -gt 0) { '{0} ({1})' -f $top.NextHopDomain, $top.MessageCount } else { '-' }
                LastError    = ($retry | Select-Object -First 1).LastError
                CheckedAt    = Get-Date
            }
        }
        catch {
            [PSCustomObject]@{
                Server       = $s
                State        = 'UNREACHABLE'
                Messages     = $null
                Queues       = $null
                RetryQueues  = $null
                Poison       = $null
                BusiestQueue = $null
                LastError    = $_.Exception.Message
                CheckedAt    = Get-Date
            }
        }
    }

    Write-Section 'Results'
    if ($LogPath) {
        # Write the table into the transcript. The caller's own formatting runs after the transcript stops.
        $results | Format-Table Server, State, Messages, Queues, RetryQueues, Poison, BusiestQueue, LastError -AutoSize |
            Out-String -Width 250 | Write-Host
    }

    $results
}
finally {
    Write-Section 'Complete'
    if ($LogPath) { Stop-Transcript | Out-Null }
}
