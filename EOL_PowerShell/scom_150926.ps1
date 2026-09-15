Step 1 — Service state

Get-Service HostControllerService, MSExchangeFastSearch -ComputerName SWPFW-MBS04 |
  Select-Object Name, DisplayName, Status, StartType

Set-Service -Name HostControllerService -StartupType Automatic
Start-Service -Name HostControllerService

Get-Service HostControllerService, MSExchangeFastSearch |
  Select-Object Name, Status, StartType

Restart-Service MSExchangeFastSearch

Get-Process noderunner -ErrorAction SilentlyContinue | Select-Object Id, StartTime, WorkingSet

Get-MailboxDatabaseCopyStatus -Server SWPFW-MBS04 |
  Select-Object Name, Status, ContentIndexState, ContentIndexErrorMessage | Format-Table -AutoSize

Get-ServerHealth -Identity SWPFW-MBS04 -HealthSet Search |
  Where-Object { $_.AlertValue -ne 'Healthy' }

Get-MailboxDatabase -Server SWPFW-MBS04 -Status |
  Select-Object Name, Mounted, Server | Format-Table -AutoSize

##

(Get-WinEvent -LogName System -MaxEvents 1 -Oldest).TimeCreated

Get-WinEvent -FilterHashtable @{LogName='System'; ID=104; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Message | Format-List

Get-MailboxDatabase | Select-Object Name, Server | Format-Table -AutoSize
Get-ExchangeServer SWPFW-MBS04 | Select-Object Name, ServerRole, Site

##

$key = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\HostControllerService'
$key.GetType().GetProperty('LastWriteTime','NonPublic,Instance')

Cause: Host Controller service found Stopped with start type Disabled. Managed Availability could not auto-recover, as the SCM cannot start a disabled service.
Fix: Start type restored to Automatic, service started, dependent MSExchangeFastSearch restarted. Four noderunner processes confirmed spawned. Search health set returned clean.
Impact: None. MBS04 hosts no mailbox databases, so no content indexing or search functionality was affected.
Root cause: Not established. No Event ID 7040 in 11 weeks of System log, indicating the start type was changed outside the SCM rather than through normal service management. Build parity with MBS05 rules out a failed CU; MBS05 unaffected rules out estate-wide policy.
Follow-up: MBS04 is a Mailbox-role server with no databases assigned — worth confirming its intended purpose.
