<#
.SYNOPSIS
    Generates a WPAD file with Microsoft 365 URLs and IP addresses.

.DESCRIPTION
    Retrieves Microsoft 365 endpoint data from the official Microsoft API and creates
    a WPAD (wpad.dat) proxy auto-config file based on the specified category and IP version.

.PARAMETER Category
    Specifies which M365 endpoints to include: Optimize, Default, or All
    - Optimize: Only Optimize category endpoints (lowest latency required)
    - Default: Optimize + Allow category endpoints
    - All: All endpoints including Optimize, Allow, and Default categories

.PARAMETER IPVersion
    Specifies which IP version to include: IPv4, IPv6, or All

.PARAMETER OutputPath
    Path where the wpad.dat file will be saved. Default: .\wpad.dat

.PARAMETER ProxyServer
    Proxy server address to use in the PAC file (e.g., "proxy.company.com:8080")

.EXAMPLE
    .\Generate-M365WPAD.ps1 -Category Optimize -IPVersion IPv4 -ProxyServer "proxy.company.com:8080"

.EXAMPLE
    .\Generate-M365WPAD.ps1 -Category All -IPVersion All -Verbose -WhatIf

# Basic usage - Optimize endpoints, IPv4 only
    .\Generate-M365WPAD.ps1 -Category Optimize -IPVersion IPv4 -ProxyServer "proxy.internal.com:8080"

# All endpoints with both IP versions
    .\Generate-M365WPAD.ps1 -Category All -IPVersion All -Verbose

# Test what would happen without creating the file
    .\Generate-M365WPAD.ps1 -Category Default -IPVersion All -WhatIf

# Custom output location
    .\Generate-M365WPAD.ps1 -Category Optimize -IPVersion IPv4 -OutputPath "C:\Proxy\wpad.dat" -Verbose

.NOTES
    Author: Systems Engineer
    Requires: PowerShell 5.1 or later
    Microsoft 365 Endpoints: https://endpoints.office.com/
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Optimize','Default','All')]
    [string]$Category = 'Default',
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('IPv4','IPv6','All')]
    [string]$IPVersion = 'All',
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\wpad.dat",
    
    [Parameter(Mandatory=$false)]
    [string]$ProxyServer = "proxy.company.com:8080"
)

# Microsoft 365 Endpoints API
$EndpointURL = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$(New-Guid)"

Write-Verbose "Starting M365 WPAD generation with Category: $Category, IPVersion: $IPVersion"

try {
    # Retrieve M365 endpoints
    Write-Verbose "Retrieving Microsoft 365 endpoints from: $EndpointURL"
    $endpoints = Invoke-RestMethod -Uri $EndpointURL -Method Get -ErrorAction Stop
    Write-Verbose "Retrieved $($endpoints.Count) endpoint entries"
    
    # Filter by category
    $filteredEndpoints = switch ($Category) {
        'Optimize' {
            Write-Verbose "Filtering for Optimize category only"
            $endpoints | Where-Object { $_.category -eq 'Optimize' }
        }
        'Default' {
            Write-Verbose "Filtering for Optimize and Allow categories"
            $endpoints | Where-Object { $_.category -in @('Optimize','Allow') }
        }
        'All' {
            Write-Verbose "Including all categories"
            $endpoints
        }
    }
    
    Write-Verbose "Filtered to $($filteredEndpoints.Count) endpoints"
    
    # Extract URLs and IPs
    $urls = @()
    $ipv4Ranges = @()
    $ipv6Ranges = @()
    
    foreach ($endpoint in $filteredEndpoints) {
        # Collect URLs
        if ($endpoint.urls) {
            $urls += $endpoint.urls
        }
        
        # Collect IPs
        if ($endpoint.ips) {
            foreach ($ip in $endpoint.ips) {
                if ($ip -match ':') {
                    $ipv6Ranges += $ip
                } else {
                    $ipv4Ranges += $ip
                }
            }
        }
    }
    
    # Remove duplicates and sort
    $urls = $urls | Select-Object -Unique | Sort-Object
    $ipv4Ranges = $ipv4Ranges | Select-Object -Unique | Sort-Object
    $ipv6Ranges = $ipv6Ranges | Select-Object -Unique | Sort-Object
    
    Write-Verbose "Collected $($urls.Count) unique URLs"
    Write-Verbose "Collected $($ipv4Ranges.Count) unique IPv4 ranges"
    Write-Verbose "Collected $($ipv6Ranges.Count) unique IPv6 ranges"
    
    # Filter IP ranges by version
    $selectedIPs = @()
    switch ($IPVersion) {
        'IPv4' {
            Write-Verbose "Including IPv4 addresses only"
            $selectedIPs = $ipv4Ranges
        }
        'IPv6' {
            Write-Verbose "Including IPv6 addresses only"
            $selectedIPs = $ipv6Ranges
        }
        'All' {
            Write-Verbose "Including both IPv4 and IPv6 addresses"
            $selectedIPs = $ipv4Ranges + $ipv6Ranges
        }
    }
    
    # Generate WPAD content
    Write-Verbose "Generating WPAD file content"
    
    $wpadContent = @"
function FindProxyForURL(url, host) {
    // Microsoft 365 WPAD Configuration
    // Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    // Category: $Category
    // IP Version: $IPVersion
    
    // Convert host to lowercase for comparison
    host = host.toLowerCase();
    
    // Bypass proxy for localhost and private addresses
    if (isPlainHostName(host) ||
        shExpMatch(host, "localhost") ||
        isInNet(host, "127.0.0.0", "255.0.0.0") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return "DIRECT";
    }
    
"@

    # Add URL rules
    if ($urls.Count -gt 0) {
        $wpadContent += "    // Direct access for Microsoft 365 URLs`r`n"
        foreach ($url in $urls) {
            # Remove protocol and wildcards for domain matching
            $domain = $url -replace '^\*\.', '' -replace '^https?://', ''
            $wpadContent += "    if (shExpMatch(host, `"*$domain`")) { return `"DIRECT`"; }`r`n"
        }
        $wpadContent += "`r`n"
    }
    
    # Add IP rules
    if ($selectedIPs.Count -gt 0) {
        $wpadContent += "    // Direct access for Microsoft 365 IP ranges`r`n"
        foreach ($ipRange in $selectedIPs) {
            if ($ipRange -match '^([\d\.]+)/(\d+)$') {
                # IPv4 CIDR
                $ip = $matches[1]
                $cidr = [int]$matches[2]
                $mask = [System.Net.IPAddress]::Parse((([UInt32]::MaxValue) -shl (32 - $cidr) -shr (32 - $cidr)))
                $wpadContent += "    if (isInNet(host, `"$ip`", `"$($mask.IPAddressToString)`")) { return `"DIRECT`"; }`r`n"
            } elseif ($ipRange -match ':') {
                # IPv6 - note: PAC files have limited IPv6 support
                $wpadContent += "    // IPv6: $ipRange (limited PAC support)`r`n"
            }
        }
        $wpadContent += "`r`n"
    }
    
    # Default proxy rule
    $wpadContent += @"
    // All other traffic goes through proxy
    return "PROXY $ProxyServer; DIRECT";
}
"@

    # Write to file
    if ($PSCmdlet.ShouldProcess($OutputPath, "Create WPAD file")) {
        Write-Verbose "Writing WPAD file to: $OutputPath"
        $wpadContent | Out-File -FilePath $OutputPath -Encoding ASCII -Force
        
        Write-Host "✓ WPAD file successfully created: $OutputPath" -ForegroundColor Green
        Write-Host "`nSummary:" -ForegroundColor Cyan
        Write-Host "  Category: $Category"
        Write-Host "  IP Version: $IPVersion"
        Write-Host "  URLs: $($urls.Count)"
        Write-Host "  IPv4 Ranges: $($ipv4Ranges.Count)"
        Write-Host "  IPv6 Ranges: $($ipv6Ranges.Count)"
        Write-Host "  Proxy Server: $ProxyServer"
        
        # Return file info
        Get-Item $OutputPath
    } else {
        Write-Host "WhatIf: Would create WPAD file at $OutputPath" -ForegroundColor Yellow
        Write-Host "  URLs to include: $($urls.Count)"
        Write-Host "  IP ranges to include: $($selectedIPs.Count)"
    }
    
} catch {
    Write-Error "Failed to generate WPAD file: $_"
    exit 1
}
