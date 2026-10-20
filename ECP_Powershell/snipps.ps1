# Q Sizes?

(Get-TransportService | ? Name -like 'SWPHQ-MBS*').Name | % { $s=$_; try { $q=@(Get-Queue -Server $s -Filter "DeliveryType -ne 'ShadowRedundancy'" -EA Stop); [PSCustomObject]@{Server=$s; Messages=[int]($q|Measure-Object MessageCount -Sum).Sum; Queues=$q.Count; Retry=@($q|? Status -eq 'Retry').Count; Poison=[int]($q|?{"$($_.Identity)" -like '*\Poison'}|Measure-Object MessageCount -Sum).Sum} } catch { [PSCustomObject]@{Server=$s; Messages='UNREACHABLE'} } } | ft -AutoSize

# or

'SWPHQ-MBS01','SWPHQ-MBS02','SWPHQ-MBS03' | % { [PSCustomObject]@{Server=$_;QueuedMessages=((Get-Queue -Server $_ | ? {$_.Identity -notlike '*shadow*'} | Measure-Object MessageCount -Sum).Sum)} } | ft -AutoSize

