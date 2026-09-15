Step 1 — Service state

Get-Service HostControllerService, MSExchangeFastSearch -ComputerName SWPFW-MBS04 |
  Select-Object Name, DisplayName, Status, StartType

Looking for: is HostControllerService Stopped, and is StartType still Automatic (or has something set it to Disabled)?

Step 2 — Current health set state

Get-ServerHealth -Identity SWPFW-MBS04 -HealthSet Search |
  Where-Object { $_.AlertValue -ne 'Healthy' } |
  Select-Object Name, AlertValue, HealthSetName, FirstAlertObservedTime

Step 3 — Index state of the database copies (the bit that matters)

Get-MailboxDatabaseCopyStatus -Server SWPFW-MBS04 |
  Select-Object Name, Status, ContentIndexState, ContentIndexErrorMessage |
  Format-Table -AutoSize

Step 4 — Disk space, since a full index volume is the single most common cause of the Host Controller falling over:

Get-CimInstance Win32_LogicalDisk -ComputerName SWPFW-MBS04 -Filter "DriveType=3" |
  Select-Object DeviceID, @{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}},
                          @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}}

