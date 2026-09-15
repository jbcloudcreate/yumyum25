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

