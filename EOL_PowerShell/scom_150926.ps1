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

Who changed it

Get-WinEvent -ComputerName SWPFW-MBS04 -FilterHashtable @{
    LogName = 'System'; ID = 7040
} -MaxEvents 50 |
  Where-Object { $_.Message -like '*Host Controller*' -or $_.Message -like '*HostController*' } |
  Select-Object TimeCreated, Id, Message |
  Format-List

Get-WinEvent -ComputerName SWPFW-MBS04 -FilterHashtable @{
    LogName = 'System'; StartTime = '2026-09-15 00:00'; EndTime = '2026-09-15 01:30'
} | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName -First 40

Set-ADServerSettings -ViewEntireForest $true
Get-MailboxDatabaseCopyStatus -Server SWPFW-MBS04 |
  Select-Object Name, Status, ContentIndexState, ContentIndexErrorMessage |
  Format-Table -AutoSize

## Step 7 — Check for an interrupted update

Get-ExchangeServer SWPFW-MBS04, SWPFW-MBS05 | Select-Object Name, AdminDisplayVersion, Edition

Get-ChildItem \\SWPFW-MBS04\C$\ExchangeSetupLogs\ | Sort-Object LastWriteTime -Descending | Select-Object -First 5
Get-Content \\SWPFW-MBS04\C$\ExchangeSetupLogs\ExchangeSetup.log -Tail 100

Get-HotFix -ComputerName SWPFW-MBS04 | Sort-Object InstalledOn -Descending | Select-Object -First 10

Get-WinEvent -ComputerName SWPFW-MBS04 -FilterHashtable @{
    LogName = 'System'; ID = 7040; StartTime = (Get-Date).AddDays(-7)
} | Where-Object { $_.Message -match 'Host Controller|HostController' } |
  Select-Object TimeCreated, Message | Format-List

Get-WinEvent -ComputerName SWPFW-MBS04 -FilterHashtable @{
    LogName = 'System'; StartTime = '2026-09-15 00:00'; EndTime = '2026-09-15 02:00'
    Level = 1,2,3
} | Sort-Object TimeCreated | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
  Format-Table -AutoSize -Wrap

