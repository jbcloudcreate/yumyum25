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
