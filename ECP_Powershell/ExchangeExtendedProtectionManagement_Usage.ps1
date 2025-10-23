# https://microsoft.github.io/CSS-Exchange/Security/ExchangeExtendedProtectionManagement/
# Preview current status
.\ExchangeExtendedProtectionManagement.ps1 -ShowExtendedProtection

# If all green, enable across all servers
.\ExchangeExtendedProtectionManagement.ps1

# Audit current TLS usage
Get-TlsCipherSuite | Where-Object { $_.Name -match "TLS" } | 
Select-Object Name, Enabled, Exchange, MinimumTLSVersion, MaximumTLSVersion
# And / Or
Get-EventLog -LogName "Microsoft-Exchange-ActiveSync/Logs" -Newest 1000 | 
Select-String "TLS"


