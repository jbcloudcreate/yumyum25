Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Subject -like "*SWPDEV-ICTWEB*" } |
  Format-List Subject, DnsNameList, NotBefore, NotAfter, Thumbprint, HasPrivateKey, EnhancedKeyUsageList, Issuer

Resolve-DnsName swpdev-ictweb.swp-rest.police.int

