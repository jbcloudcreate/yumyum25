Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Subject -like "*SWPDEV-ICTWEB*" } |
  Format-List Subject, DnsNameList, NotBefore, NotAfter, Thumbprint, HasPrivateKey, EnhancedKeyUsageList, Issuer

Resolve-DnsName swpdev-ictweb.swp-rest.police.int

Get-WebBinding | Select-Object protocol, bindingInformation, ItemXPath
netsh http show sslcert

Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Thumbprint -eq 'F07598B26011CE01C99E492AE62DD2EAC24875B7' } |
  Format-List Subject, DnsNameList, NotAfter, EnhancedKeyUsageList, Issuer

Get-Website | Select-Object Name, State, PhysicalPath
Get-WebApplication

Get-ChildItem Cert:\LocalMachine -Recurse |
  Where-Object { $_.Thumbprint -eq 'F07598B26011CE01C99E492AE62DD2EAC24875B7' } |
  Format-List PSParentPath, Subject, DnsNameList, NotAfter
