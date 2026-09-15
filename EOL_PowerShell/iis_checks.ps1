## Phase 1

<#
.SYNOPSIS
    Read-only IIS inventory for decommissioning readiness.

.DESCRIPTION
    Collects a comprehensive picture of an IIS server: sites, bindings, application
    pools, applications, virtual directories, certificates, handlers, modules,
    configuration dependencies, co-located workloads, and (critically) evidence of
    whether anything is still actually using the server, taken from the IIS logs.

    This script makes NO changes. It only reads. Nothing is started, stopped,
    recycled or deleted.

    Output: JSON (full fidelity), CSVs (per object type), and an HTML report.

.PARAMETER OutputPath
    Folder to write results to. Created if missing.

.PARAMETER LogDays
    How many days of IIS logs to analyse for traffic evidence. Default 30.

.PARAMETER SkipLogAnalysis
    Skip IIS log parsing (much faster, but you lose the "is it still in use" evidence).

.PARAMETER IncludeContentSize
    Calculate the on-disk size of each site's content folder. Can be slow on large shares.

.PARAMETER CollectConfigFiles
    Copy applicationHost.config, administration.config, redirection.config and each
    site's web.config into the output folder. WARNING: these can contain credentials
    and connection strings. Treat the output folder as sensitive if you use this.

.PARAMETER RevealSecrets
    Do not redact passwords in connection strings. Off by default.

.EXAMPLE
    .\Get-IISDecommInventory.ps1 -OutputPath D:\Decomm\SERVER01 -LogDays 90

.NOTES
    Requires: PowerShell 5.1+, local Administrator, IIS WebAdministration module.
    Run on the IIS server itself.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\Temp\IISInventory",
    [int]$LogDays = 30,
    [switch]$SkipLogAnalysis,
    [switch]$IncludeContentSize,
    [switch]$CollectConfigFiles,
    [switch]$RevealSecrets
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

#region ---------------------------------------------------------- Preflight

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run from an elevated (Run as Administrator) PowerShell session."
}

try {
    Import-Module WebAdministration -ErrorAction Stop
} catch {
    throw "Could not load the WebAdministration module. Is the IIS Management Scripts and Tools feature installed? ($($_.Exception.Message))"
}

$stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$computer   = $env:COMPUTERNAME
$OutputPath = Join-Path $OutputPath "$computer-$stamp"
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

Start-Transcript -Path (Join-Path $OutputPath 'run-transcript.txt') -Force | Out-Null

Write-Host ""
Write-Host "IIS Decommissioning Inventory" -ForegroundColor Green
Write-Host "Server : $computer"
Write-Host "Output : $OutputPath"
Write-Host "Mode   : READ-ONLY (no changes will be made)" -ForegroundColor Green
Write-Host ""

$inv    = [ordered]@{}
$errors = New-Object System.Collections.ArrayList

function Invoke-Section {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ("  [*] {0}" -f $Name) -ForegroundColor Cyan
    try {
        . $Body
    } catch {
        [void]$errors.Add([pscustomobject]@{ Section = $Name; Error = $_.Exception.Message })
        Write-Host ("      ! {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

function Expand-IISPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    [Environment]::ExpandEnvironmentVariables($Path)
}

function Protect-Secret {
    param([string]$Text)
    if ($RevealSecrets -or [string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $out = $Text
    $out = $out -replace '(?i)(password|pwd)\s*=\s*[^;]*', '$1=***REDACTED***'
    $out = $out -replace '(?i)(accountkey|sharedaccesskey|apikey|api_key|secret)\s*=\s*[^;]*', '$1=***REDACTED***'
    return $out
}

function ConvertTo-Thumbprint {
    param($Hash)
    if (-not $Hash) { return $null }
    if ($Hash -is [string]) { return $Hash }
    ($Hash | ForEach-Object { $_.ToString('X2') }) -join ''
}

#endregion

#region ---------------------------------------------------------- Server context

$serverIPs = @()

Invoke-Section 'Server context' {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $bios= Get-CimInstance Win32_BIOS

    $iisVersion = $null
    try {
        $iisVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction Stop).VersionString
    } catch { }

    $script:serverIPs = @(Get-NetIPAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -ExpandProperty IPAddress)

    $inv.Server = [pscustomobject]@{
        ComputerName      = $computer
        FQDN              = "$($cs.DNSHostName).$($cs.Domain)"
        Domain            = $cs.Domain
        Manufacturer      = $cs.Manufacturer
        Model             = $cs.Model
        SerialNumber      = $bios.SerialNumber
        IsVirtual         = ($cs.Model -match 'Virtual|VMware|KVM|Hyper-V')
        OperatingSystem   = $os.Caption
        OSVersion         = $os.Version
        InstallDate       = $os.InstallDate
        LastBootUpTime    = $os.LastBootUpTime
        UptimeDays        = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
        LogicalProcessors = $cs.NumberOfLogicalProcessors
        MemoryGB          = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        IISVersion        = $iisVersion
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IPAddresses       = ($script:serverIPs -join ', ')
        CollectedBy       = $identity.Name
        CollectedOn       = (Get-Date)
    }

    $inv.Volumes = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [pscustomobject]@{
            Drive       = $_.DeviceID
            Label       = $_.VolumeName
            SizeGB      = [math]::Round($_.Size / 1GB, 1)
            FreeGB      = [math]::Round($_.FreeSpace / 1GB, 1)
            PercentFree = if ($_.Size) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { $null }
        }
    }
}

Invoke-Section 'Installed IIS role services / Windows features' {
    $inv.WindowsFeatures = @()
    try {
        Import-Module ServerManager -ErrorAction Stop
        $inv.WindowsFeatures = Get-WindowsFeature | Where-Object Installed |
            Select-Object @{n='Name';e={$_.Name}}, @{n='DisplayName';e={$_.DisplayName}}, @{n='FeatureType';e={$_.FeatureType}}
    } catch {
        $inv.WindowsFeatures = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -like 'IIS*' } |
            Select-Object @{n='Name';e={$_.FeatureName}}, @{n='DisplayName';e={$_.FeatureName}}, @{n='FeatureType';e={'OptionalFeature'}}
    }
}

Invoke-Section 'Installed software' {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $inv.InstalledSoftware = Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object @{n='Name';e={$_.DisplayName}},
                      @{n='Version';e={$_.DisplayVersion}},
                      @{n='Publisher';e={$_.Publisher}},
                      @{n='InstallDate';e={$_.InstallDate}} |
        Sort-Object Name -Unique
}

Invoke-Section '.NET Framework / runtime versions' {
    $ndp = @()
    $base = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    if (Test-Path $base) {
        $ndp = Get-ChildItem $base -Recurse -ErrorAction SilentlyContinue |
            Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue |
            Where-Object { $_.Version } |
            Select-Object @{n='Key';e={$_.PSChildName}}, Version, Release |
            Sort-Object Version -Unique
    }
    $core = @()
    $dotnetExe = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
    if (Test-Path $dotnetExe) {
        $core = & $dotnetExe --list-runtimes 2>$null | ForEach-Object { [pscustomobject]@{ Runtime = $_ } }
    }
    $inv.DotNetVersions   = $ndp
    $inv.DotNetCoreRuntimes = $core
}

#endregion

#region ---------------------------------------------------------- IIS core objects

Invoke-Section 'Application pools' {
    $pools = @()
    foreach ($p in (Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop)) {
        $item = $null
        try { $item = Get-Item -Path ("IIS:\AppPools\" + $p.Name) -ErrorAction Stop } catch { }

        $state = $null
        try { $state = (Get-WebAppPoolState -Name $p.Name -ErrorAction Stop).Value } catch { $state = 'Unknown' }

        $schedules = $null
        try {
            $schedules = ($item.recycling.periodicRestart.schedule.Collection | ForEach-Object { $_.value }) -join ', '
        } catch { }

        $pools += [pscustomobject]@{
            Name                 = $p.Name
            State                = $state
            AutoStart            = $item.autoStart
            StartMode            = $item.startMode
            ManagedRuntimeVersion= if ([string]::IsNullOrWhiteSpace($item.managedRuntimeVersion)) { 'No Managed Code' } else { $item.managedRuntimeVersion }
            ManagedPipelineMode  = $item.managedPipelineMode
            Enable32BitOnWin64   = $item.enable32BitAppOnWin64
            QueueLength          = $item.queueLength
            IdentityType         = $item.processModel.identityType
            IdentityUser         = $item.processModel.userName
            LoadUserProfile      = $item.processModel.loadUserProfile
            IdleTimeoutMinutes   = if ($item.processModel.idleTimeout) { [math]::Round(([TimeSpan]$item.processModel.idleTimeout).TotalMinutes,0) } else { $null }
            MaxProcesses         = $item.processModel.maxProcesses
            PingingEnabled       = $item.processModel.pingingEnabled
            RecycleTimeMinutes   = if ($item.recycling.periodicRestart.time) { [math]::Round(([TimeSpan]$item.recycling.periodicRestart.time).TotalMinutes,0) } else { $null }
            RecycleRequests      = $item.recycling.periodicRestart.requests
            RecycleMemoryKB      = $item.recycling.periodicRestart.memory
            RecyclePrivateMemKB  = $item.recycling.periodicRestart.privateMemory
            RecycleSchedule      = $schedules
            RapidFailProtection  = $item.failure.rapidFailProtection
        }
    }
    $inv.AppPools = $pools
}

Invoke-Section 'Worker processes (live activity)' {
    $wp = @()
    foreach ($proc in (Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" -ErrorAction SilentlyContinue)) {
        $poolName = $null
        if ($proc.CommandLine -match '-ap\s+"([^"]+)"') { $poolName = $Matches[1] }
        $wp += [pscustomobject]@{
            ProcessId    = $proc.ProcessId
            AppPool      = $poolName
            StartTime    = $proc.CreationDate
            WorkingSetMB = [math]::Round($proc.WorkingSetSize / 1MB, 1)
        }
    }
    $inv.WorkerProcesses = $wp
}

Invoke-Section 'Web sites and bindings' {
    $sites    = @()
    $bindings = @()

    foreach ($s in (Get-Website -ErrorAction Stop)) {
        $physical = Expand-IISPath $s.physicalPath
        $logDir   = Expand-IISPath $s.logFile.directory

        $contentSizeMB = $null
        if ($IncludeContentSize -and $physical -and (Test-Path $physical)) {
            try {
                $sum = (Get-ChildItem -Path $physical -Recurse -Force -File -ErrorAction SilentlyContinue |
                        Measure-Object -Property Length -Sum).Sum
                $contentSizeMB = [math]::Round($sum / 1MB, 1)
            } catch { }
        }

        $lastContentWrite = $null
        if ($physical -and (Test-Path $physical)) {
            try {
                $lastContentWrite = (Get-ChildItem -Path $physical -Recurse -Force -File -ErrorAction SilentlyContinue |
                                     Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
            } catch { }
        }

        $sites += [pscustomobject]@{
            Name                = $s.Name
            Id                  = $s.Id
            State               = $s.State
            PhysicalPath        = $physical
            PathExists          = if ($physical) { Test-Path $physical } else { $false }
            ContentSizeMB       = $contentSizeMB
            LastContentModified = $lastContentWrite
            AppPool             = $s.applicationPool
            ServerAutoStart     = $s.serverAutoStart
            BindingCount        = @($s.bindings.Collection).Count
            Bindings            = (@($s.bindings.Collection | ForEach-Object { "$($_.protocol)/$($_.bindingInformation)" }) -join '; ')
            LogEnabled          = $s.logFile.enabled
            LogDirectory        = $logDir
            LogFormat           = $s.logFile.logFormat
            LogPeriod           = $s.logFile.period
            LogExtFileFlags     = $s.logFile.logExtFileFlags
            PreloadEnabled      = $s.applicationDefaults.preloadEnabled
        }

        foreach ($b in $s.bindings.Collection) {
            $parts = ($b.bindingInformation -split ':')
            $ip    = $parts[0]; $port = $parts[1]; $hostHdr = $parts[2]

            $dnsResult = $null; $dnsPointsHere = $null
            if ($hostHdr) {
                try {
                    $resolved = Resolve-DnsName -Name $hostHdr -ErrorAction Stop |
                                Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
                    if ($resolved) {
                        $dnsResult    = ($resolved -join ', ')
                        $dnsPointsHere = [bool](@($resolved | Where-Object { $serverIPs -contains $_ }).Count)
                    } else {
                        $dnsResult = 'No A/AAAA record'
                    }
                } catch { $dnsResult = 'Resolution failed' }
            }

            $bindings += [pscustomobject]@{
                Site              = $s.Name
                SiteState         = $s.State
                Protocol          = $b.protocol
                IPAddress         = if ($ip -eq '*') { 'All Unassigned' } else { $ip }
                Port              = $port
                HostHeader        = $hostHdr
                SslFlags          = $b.sslFlags
                CertThumbprint    = ConvertTo-Thumbprint $b.certificateHash
                CertStore         = $b.certificateStoreName
                DnsResolvesTo     = $dnsResult
                DnsPointsAtServer = $dnsPointsHere
            }
        }
    }

    $inv.Sites    = $sites
    $inv.Bindings = $bindings
}

Invoke-Section 'Applications and virtual directories' {
    $apps  = @()
    $vdirs = @()

    foreach ($a in (Get-WebApplication -ErrorAction SilentlyContinue)) {
        $physical = Expand-IISPath $a.PhysicalPath
        $apps += [pscustomobject]@{
            Site             = ($a.GetParentElement().Attributes['name'].Value)
            Path             = $a.Path
            AppPool          = $a.applicationPool
            PhysicalPath     = $physical
            PathExists       = if ($physical) { Test-Path $physical } else { $false }
            EnabledProtocols = $a.enabledProtocols
        }
    }

    foreach ($v in (Get-WebVirtualDirectory -ErrorAction SilentlyContinue)) {
        $physical = Expand-IISPath $v.PhysicalPath
        $vdirs += [pscustomobject]@{
            Path             = $v.Path
            PhysicalPath     = $physical
            PathExists       = if ($physical) { Test-Path $physical } else { $false }
            IsUNC            = ($physical -like '\\*')
            LogonMethod      = $v.logonMethod
            ConnectAsUser    = $v.userName
            HasStoredCred    = -not [string]::IsNullOrWhiteSpace($v.userName)
        }
    }

    $inv.Applications       = $apps
    $inv.VirtualDirectories = $vdirs
}

Invoke-Section 'Certificates' {
    $certs = @()
    foreach ($store in @('My','WebHosting')) {
        $path = "Cert:\LocalMachine\$store"
        if (-not (Test-Path $path)) { continue }
        foreach ($c in (Get-ChildItem $path -ErrorAction SilentlyContinue)) {
            $san = ($c.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' } |
                    ForEach-Object { $_.Format($false) }) -join ' '
            $certs += [pscustomobject]@{
                Store           = $store
                Thumbprint      = $c.Thumbprint
                Subject         = $c.Subject
                FriendlyName    = $c.FriendlyName
                Issuer          = $c.Issuer
                NotBefore       = $c.NotBefore
                NotAfter        = $c.NotAfter
                DaysToExpiry    = [math]::Round(($c.NotAfter - (Get-Date)).TotalDays, 0)
                Expired         = ($c.NotAfter -lt (Get-Date))
                HasPrivateKey   = $c.HasPrivateKey
                SubjectAltNames = $san
            }
        }
    }
    $inv.Certificates = $certs

    $sslBindings = @()
    try {
        foreach ($sb in (Get-ChildItem 'IIS:\SslBindings' -ErrorAction Stop)) {
            $sslBindings += [pscustomobject]@{
                IPAddress  = $sb.IPAddress
                Port       = $sb.Port
                HostHeader = $sb.Host
                Thumbprint = $sb.Thumbprint
                Store      = $sb.Store
                Sites      = ($sb.Sites -join ', ')
            }
        }
    } catch { }
    $inv.SslBindings = $sslBindings

    # Raw HTTP.SYS view - catches bindings IIS itself does not own
    try {
        netsh http show sslcert  | Out-File (Join-Path $OutputPath 'netsh-sslcert.txt')  -Encoding UTF8
        netsh http show urlacl   | Out-File (Join-Path $OutputPath 'netsh-urlacl.txt')   -Encoding UTF8
        netsh http show servicestate | Out-File (Join-Path $OutputPath 'netsh-servicestate.txt') -Encoding UTF8
    } catch { }
}

Invoke-Section 'Global modules, ISAPI filters and handlers' {
    $inv.GlobalModules = Get-WebGlobalModule -ErrorAction SilentlyContinue |
        Select-Object Name, @{n='Image';e={ Expand-IISPath $_.Image }}

    $filters = @()
    try {
        $f = Get-WebConfiguration -Filter '/system.webServer/isapiFilters/filter' -PSPath 'IIS:\' -ErrorAction Stop
        foreach ($i in $f) {
            $filters += [pscustomobject]@{
                Name = $i.name; Path = Expand-IISPath $i.path; Enabled = $i.enabled; PreCondition = $i.preCondition
            }
        }
    } catch { }
    $inv.IsapiFilters = $filters

    $handlers = @()
    try {
        $h = Get-WebConfiguration -Filter '/system.webServer/handlers/add' -PSPath 'IIS:\' -ErrorAction Stop
        foreach ($i in $h) {
            $handlers += [pscustomobject]@{
                Name = $i.name; Path = $i.path; Verb = $i.verb
                Modules = $i.modules; ScriptProcessor = Expand-IISPath $i.scriptProcessor
            }
        }
    } catch { }
    $inv.Handlers = $handlers
}

Invoke-Section 'Site configuration dependencies (connection strings, rewrite, auth)' {
    $connStrings = @()
    $rewrites    = @()
    $auth        = @()

    $scopes = @()
    foreach ($s in (Get-Website -ErrorAction SilentlyContinue)) { $scopes += "IIS:\Sites\$($s.Name)" }
    foreach ($a in (Get-WebApplication -ErrorAction SilentlyContinue)) {
        $parent = $a.GetParentElement().Attributes['name'].Value
        $scopes += ("IIS:\Sites\" + $parent + $a.Path)
    }

    foreach ($scope in ($scopes | Sort-Object -Unique)) {
        try {
            $cs = Get-WebConfigurationProperty -PSPath $scope -Filter 'connectionStrings' -Name 'collection' -ErrorAction SilentlyContinue
            foreach ($c in $cs) {
                if ($c.name) {
                    $connStrings += [pscustomobject]@{
                        Scope            = $scope
                        Name             = $c.name
                        ConnectionString = Protect-Secret $c.connectionString
                        Provider         = $c.providerName
                        TargetServer     = if ($c.connectionString -match '(?i)(data source|server|host)\s*=\s*([^;]+)') { $Matches[2].Trim() } else { $null }
                        TargetDatabase   = if ($c.connectionString -match '(?i)(initial catalog|database)\s*=\s*([^;]+)') { $Matches[2].Trim() } else { $null }
                    }
                }
            }
        } catch { }

        try {
            $rr = Get-WebConfiguration -PSPath $scope -Filter '/system.webServer/rewrite/rules/rule' -ErrorAction SilentlyContinue
            foreach ($r in $rr) {
                $rewrites += [pscustomobject]@{
                    Scope   = $scope
                    Name    = $r.name
                    Enabled = $r.enabled
                    Pattern = $r.match.url
                    Action  = $r.action.type
                    Target  = $r.action.url
                }
            }
        } catch { }

        try {
            $modes = @()
            foreach ($mode in @('anonymousAuthentication','basicAuthentication','windowsAuthentication','digestAuthentication','clientCertificateMappingAuthentication')) {
                $val = Get-WebConfigurationProperty -PSPath $scope -Filter "/system.webServer/security/authentication/$mode" -Name enabled -ErrorAction SilentlyContinue
                if ($val -and $val.Value) { $modes += $mode }
            }
            $ssl = Get-WebConfigurationProperty -PSPath $scope -Filter '/system.webServer/security/access' -Name sslFlags -ErrorAction SilentlyContinue
            $auth += [pscustomobject]@{
                Scope          = $scope
                EnabledAuth    = ($modes -join ', ')
                SslFlags       = if ($ssl) { $ssl.Value } else { $null }
            }
        } catch { }
    }

    $inv.ConnectionStrings = $connStrings
    $inv.RewriteRules      = $rewrites
    $inv.Authentication    = $auth
}

#endregion

#region ---------------------------------------------------------- Co-located workloads

Invoke-Section 'Other workloads on this server' {
    $inv.Services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.StartMode -ne 'Disabled' -and $_.PathName -notmatch '(?i)\\Windows\\(system32|SysWOW64)\\(svchost|services)\.exe' } |
        Select-Object Name, DisplayName, State, StartMode, StartName, @{n='PathName';e={$_.PathName}} |
        Sort-Object DisplayName

    $tasks = @()
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } |
            ForEach-Object {
                $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    TaskName   = $_.TaskName
                    TaskPath   = $_.TaskPath
                    State      = $_.State
                    RunAs      = $_.Principal.UserId
                    Action     = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ')
                    LastRun    = $info.LastRunTime
                    LastResult = $info.LastTaskResult
                    NextRun    = $info.NextRunTime
                }
            }
    } catch { }
    $inv.ScheduledTasks = $tasks

    $inv.Shares = Get-SmbShare -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^\w\$$|^(ADMIN|IPC)\$$' } |
        Select-Object Name, Path, Description

    $inv.LocalAdministrators = @()
    try {
        $inv.LocalAdministrators = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
            Select-Object Name, ObjectClass, PrincipalSource
    } catch { }

    $inv.LocalUsers = @()
    try {
        $inv.LocalUsers = Get-LocalUser -ErrorAction Stop |
            Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description
    } catch { }

    $inv.ListeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort,
                      @{n='Process';e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }} |
        Sort-Object LocalPort -Unique

    $inv.OutboundConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notin @('127.0.0.1','::1') } |
        Select-Object RemoteAddress, RemotePort,
                      @{n='Process';e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }} |
        Sort-Object RemoteAddress, RemotePort -Unique

    $inv.FirewallRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
        ForEach-Object {
            $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Name        = $_.DisplayName
                Profile     = $_.Profile
                Protocol    = $pf.Protocol
                LocalPort   = ($pf.LocalPort -join ',')
                Group       = $_.DisplayGroup
            }
        } | Where-Object { $_.LocalPort -and $_.LocalPort -ne 'Any' }
}

#endregion

#region ---------------------------------------------------------- Log traffic analysis

function Get-IISLogStats {
    param(
        [string]$LogDirectory,
        [int]$SiteId,
        [datetime]$Cutoff,
        [string[]]$LocalIPs
    )

    $dir = Join-Path (Expand-IISPath $LogDirectory) ("W3SVC" + $SiteId)
    if (-not (Test-Path $dir)) {
        return [pscustomobject]@{ LogDirectory = $dir; Status = 'Log directory not found'; TotalRequests = 0 }
    }

    $files = @(Get-ChildItem -Path $dir -Filter '*.log' -File -ErrorAction SilentlyContinue |
               Where-Object { $_.LastWriteTime -ge $Cutoff })

    if ($files.Count -eq 0) {
        $allFiles = @(Get-ChildItem -Path $dir -Filter '*.log' -File -ErrorAction SilentlyContinue)
        $newest = ($allFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
        return [pscustomobject]@{
            LogDirectory  = $dir
            Status        = "No log files modified in the last $LogDays days"
            TotalRequests = 0
            NewestLogFile = if ($newest) { $newest.LastWriteTime } else { $null }
            TotalLogFiles = $allFiles.Count
        }
    }

    $fields   = @()
    $idxDate  = -1; $idxTime = -1; $idxCIP = -1; $idxUri = -1; $idxStatus = -1; $idxAgent = -1
    $total    = 0
    $external = 0
    $ips      = New-Object 'System.Collections.Generic.HashSet[string]'
    $extIps   = New-Object 'System.Collections.Generic.HashSet[string]'
    $byDay    = @{}
    $byUri    = @{}
    $byStatus = @{}
    $byAgent  = @{}
    $first    = $null
    $last     = $null

    foreach ($file in ($files | Sort-Object LastWriteTime)) {
        Get-Content -Path $file.FullName -ReadCount 5000 -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($line in $_) {
                if ($line.Length -eq 0) { continue }
                if ($line[0] -eq '#') {
                    if ($line.StartsWith('#Fields:')) {
                        $fields    = ($line.Substring(8).Trim() -split '\s+')
                        $idxDate   = [array]::IndexOf($fields,'date')
                        $idxTime   = [array]::IndexOf($fields,'time')
                        $idxCIP    = [array]::IndexOf($fields,'c-ip')
                        $idxUri    = [array]::IndexOf($fields,'cs-uri-stem')
                        $idxStatus = [array]::IndexOf($fields,'sc-status')
                        $idxAgent  = [array]::IndexOf($fields,'cs(User-Agent)')
                    }
                    continue
                }

                $p = $line -split ' '
                $total++

                if ($idxDate -ge 0 -and $p.Count -gt $idxDate) {
                    $d = $p[$idxDate]
                    if ($byDay.ContainsKey($d)) { $byDay[$d]++ } else { $byDay[$d] = 1 }
                    if (-not $first) { $first = $d }
                    $last = $d
                    if ($idxTime -ge 0 -and $p.Count -gt $idxTime) { $lastTime = $p[$idxTime] }
                }

                if ($idxCIP -ge 0 -and $p.Count -gt $idxCIP) {
                    $ip = $p[$idxCIP]
                    [void]$ips.Add($ip)
                    if ($ip -ne '127.0.0.1' -and $ip -ne '::1' -and ($LocalIPs -notcontains $ip)) {
                        $external++
                        [void]$extIps.Add($ip)
                    }
                }

                if ($idxUri -ge 0 -and $p.Count -gt $idxUri -and $byUri.Count -lt 20000) {
                    $u = $p[$idxUri]
                    if ($byUri.ContainsKey($u)) { $byUri[$u]++ } else { $byUri[$u] = 1 }
                }

                if ($idxStatus -ge 0 -and $p.Count -gt $idxStatus) {
                    $st = $p[$idxStatus]
                    if ($byStatus.ContainsKey($st)) { $byStatus[$st]++ } else { $byStatus[$st] = 1 }
                }

                if ($idxAgent -ge 0 -and $p.Count -gt $idxAgent -and $byAgent.Count -lt 5000) {
                    $ua = $p[$idxAgent]
                    if ($byAgent.ContainsKey($ua)) { $byAgent[$ua]++ } else { $byAgent[$ua] = 1 }
                }
            }
        }
    }

    [pscustomobject]@{
        LogDirectory      = $dir
        Status            = 'Parsed'
        FilesParsed       = $files.Count
        LogSizeMB         = [math]::Round((($files | Measure-Object -Property Length -Sum).Sum / 1MB), 1)
        WindowDays        = $LogDays
        TotalRequests     = $total
        ExternalRequests  = $external
        UniqueClientIPs   = $ips.Count
        UniqueExternalIPs = $extIps.Count
        FirstEntryDate    = $first
        LastEntryDate     = $last
        AvgRequestsPerDay = if ($byDay.Count) { [math]::Round($total / $byDay.Count, 1) } else { 0 }
        DailyCounts       = ($byDay.GetEnumerator()   | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
        StatusCodes       = ($byStatus.GetEnumerator()| Sort-Object { [int]$_.Value } -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
        TopUris           = ($byUri.GetEnumerator()   | Sort-Object { [int]$_.Value } -Descending | Select-Object -First 15 | ForEach-Object { "$($_.Name) ($($_.Value))" }) -join '; '
        TopUserAgents     = ($byAgent.GetEnumerator() | Sort-Object { [int]$_.Value } -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Name) ($($_.Value))" }) -join '; '
        TopClientIPs      = (($extIps | Select-Object -First 25) -join ', ')
    }
}

if (-not $SkipLogAnalysis) {
    Invoke-Section "IIS log traffic analysis (last $LogDays days)" {
        $cutoff  = (Get-Date).AddDays(-$LogDays)
        $results = @()
        foreach ($s in (Get-Website -ErrorAction SilentlyContinue)) {
            Write-Host ("      - {0}" -f $s.Name) -ForegroundColor DarkGray
            if (-not $s.logFile.enabled) {
                $results += [pscustomobject]@{ Site = $s.Name; SiteId = $s.Id; Status = 'LOGGING DISABLED - no usage evidence available'; TotalRequests = $null }
                continue
            }
            $stat = Get-IISLogStats -LogDirectory $s.logFile.directory -SiteId $s.Id -Cutoff $cutoff -LocalIPs $serverIPs
            $obj  = [pscustomobject]@{ Site = $s.Name; SiteId = $s.Id }
            foreach ($prop in $stat.PSObject.Properties) {
                $obj | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
            }
            $results += $obj
        }
        $inv.LogAnalysis = $results
    }
} else {
    $inv.LogAnalysis = @()
    Write-Host "  [-] IIS log analysis skipped" -ForegroundColor DarkYellow
}

#endregion

#region ---------------------------------------------------------- Decommissioning risk flags

Invoke-Section 'Decommissioning risk assessment' {
    $flags = @()

    foreach ($s in $inv.Sites) {
        $log = $inv.LogAnalysis | Where-Object { $_.Site -eq $s.Name } | Select-Object -First 1

        if ($s.State -eq 'Started' -and $log -and $log.ExternalRequests -gt 0) {
            $flags += [pscustomobject]@{
                Severity = 'HIGH'; Category = 'Active traffic'; Item = $s.Name
                Detail   = "$($log.ExternalRequests) external requests from $($log.UniqueExternalIPs) distinct IPs in the last $LogDays days. This site is in use - identify consumers before decommissioning."
            }
        } elseif ($s.State -eq 'Started' -and $log -and $log.TotalRequests -eq 0) {
            $flags += [pscustomobject]@{
                Severity = 'LOW'; Category = 'No traffic'; Item = $s.Name
                Detail   = "Site is running but logged zero requests in the last $LogDays days. Strong candidate for shutdown-then-decommission."
            }
        } elseif ($s.State -eq 'Started' -and $log -and $log.TotalRequests -gt 0 -and $log.ExternalRequests -eq 0) {
            $flags += [pscustomobject]@{
                Severity = 'MEDIUM'; Category = 'Local-only traffic'; Item = $s.Name
                Detail   = "All $($log.TotalRequests) requests came from the server itself or loopback - likely monitoring or health checks only. Verify before decommissioning."
            }
        }

        if ($s.LogEnabled -eq $false) {
            $flags += [pscustomobject]@{
                Severity = 'MEDIUM'; Category = 'No audit trail'; Item = $s.Name
                Detail   = 'Logging is disabled for this site, so usage cannot be evidenced. Consider enabling logging and observing for a period before decommissioning.'
            }
        }

        if (-not $s.PathExists) {
            $flags += [pscustomobject]@{
                Severity = 'LOW'; Category = 'Broken site'; Item = $s.Name
                Detail   = "Physical path does not exist: $($s.PhysicalPath)"
            }
        }
    }

    foreach ($b in ($inv.Bindings | Where-Object { $_.HostHeader })) {
        if ($b.DnsPointsAtServer -eq $true) {
            $flags += [pscustomobject]@{
                Severity = 'HIGH'; Category = 'DNS cleanup'; Item = $b.HostHeader
                Detail   = "DNS record for $($b.HostHeader) currently resolves to this server ($($b.DnsResolvesTo)). Must be removed or repointed as part of decommissioning."
            }
        } elseif ($b.DnsResolvesTo -and $b.DnsPointsAtServer -eq $false) {
            $flags += [pscustomobject]@{
                Severity = 'MEDIUM'; Category = 'DNS mismatch'; Item = $b.HostHeader
                Detail   = "Host header $($b.HostHeader) resolves elsewhere ($($b.DnsResolvesTo)) - possibly behind a load balancer or reverse proxy. Check upstream config for references to this server."
            }
        }
    }

    foreach ($p in ($inv.AppPools | Where-Object { $_.IdentityType -eq 'SpecificUser' -and $_.IdentityUser })) {
        $flags += [pscustomobject]@{
            Severity = 'MEDIUM'; Category = 'Service account'; Item = $p.Name
            Detail   = "App pool runs as $($p.IdentityUser). This account may need disabling or reviewing in AD once the server is retired, and may hold permissions elsewhere."
        }
    }

    foreach ($c in ($inv.ConnectionStrings | Where-Object { $_.TargetServer })) {
        $flags += [pscustomobject]@{
            Severity = 'HIGH'; Category = 'Downstream dependency'; Item = "$($c.Name) -> $($c.TargetServer)"
            Detail   = "Connects to database '$($c.TargetDatabase)' on '$($c.TargetServer)'. Decide whether that database is also being retired, migrated, or has other consumers."
        }
    }

    foreach ($v in ($inv.VirtualDirectories | Where-Object { $_.IsUNC -or $_.HasStoredCred })) {
        $flags += [pscustomobject]@{
            Severity = 'MEDIUM'; Category = 'External content dependency'; Item = $v.Path
            Detail   = "Points at $($v.PhysicalPath)$(if ($v.HasStoredCred) { " using stored credentials for $($v.ConnectAsUser)" }). Content may live off-box and be shared with other systems."
        }
    }

    foreach ($c in ($inv.Certificates | Where-Object { -not $_.Expired })) {
        if ($inv.Bindings.CertThumbprint -contains $c.Thumbprint) {
            $flags += [pscustomobject]@{
                Severity = 'MEDIUM'; Category = 'Certificate'; Item = $c.Subject
                Detail   = "In active use, expires $($c.NotAfter.ToString('yyyy-MM-dd')) ($($c.DaysToExpiry) days). Revoke or transfer as part of decommissioning; confirm it is not also deployed elsewhere."
            }
        }
    }

    if ($inv.ScheduledTasks.Count -gt 0) {
        $flags += [pscustomobject]@{
            Severity = 'HIGH'; Category = 'Co-located workload'; Item = 'Scheduled tasks'
            Detail   = "$($inv.ScheduledTasks.Count) non-Microsoft scheduled task(s) found. These are separate workloads that will stop when the server is retired - review each one."
        }
    }

    if ($inv.Shares.Count -gt 0) {
        $flags += [pscustomobject]@{
            Severity = 'HIGH'; Category = 'Co-located workload'; Item = 'File shares'
            Detail   = "$($inv.Shares.Count) non-administrative SMB share(s) published from this server. Consumers may have mapped drives or hardcoded UNC paths."
        }
    }

    $nonIisPorts = $inv.ListeningPorts | Where-Object { $_.Process -notin @('System','svchost','Idle') -and $_.LocalPort -notin @(80,443,135,445,3389,5985,5986) }
    if ($nonIisPorts) {
        $flags += [pscustomobject]@{
            Severity = 'MEDIUM'; Category = 'Unexpected listener'; Item = 'Listening ports'
            Detail   = "Non-standard listening ports detected: $(($nonIisPorts | ForEach-Object { "$($_.LocalPort)/$($_.Process)" }) -join ', '). Something other than IIS may be serving traffic."
        }
    }

    $inv.RiskFlags = $flags | Sort-Object @{e={ switch ($_.Severity) { 'HIGH' {1} 'MEDIUM' {2} default {3} } }}, Category
}

#endregion

#region ---------------------------------------------------------- Config file collection

if ($CollectConfigFiles) {
    Invoke-Section 'Collecting configuration files' {
        Write-Host "      NOTE: collected config may contain credentials - treat output as sensitive" -ForegroundColor Yellow
        $cfgDir = Join-Path $OutputPath 'config'
        New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null

        $inetsrvCfg = Join-Path $env:windir 'system32\inetsrv\config'
        foreach ($f in @('applicationHost.config','administration.config','redirection.config')) {
            $src = Join-Path $inetsrvCfg $f
            if (Test-Path $src) { Copy-Item $src -Destination $cfgDir -Force }
        }

        $machineCfg = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\Config\machine.config'
        if (Test-Path $machineCfg) { Copy-Item $machineCfg -Destination (Join-Path $cfgDir 'machine.config') -Force }

        foreach ($s in (Get-Website -ErrorAction SilentlyContinue)) {
            $wc = Join-Path (Expand-IISPath $s.physicalPath) 'web.config'
            if (Test-Path $wc) {
                $safeName = ($s.Name -replace '[^\w\-\.]', '_')
                Copy-Item $wc -Destination (Join-Path $cfgDir "site-$safeName-web.config") -Force
            }
        }
    }
}

#endregion

#region ---------------------------------------------------------- Output

Invoke-Section 'Writing output files' {

    $inv.CollectionErrors = @($errors)

    # Full fidelity JSON
    $inv | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputPath 'inventory.json') -Encoding UTF8

    # Per-object CSVs
    $csvDir = Join-Path $OutputPath 'csv'
    New-Item -Path $csvDir -ItemType Directory -Force | Out-Null
    foreach ($key in $inv.Keys) {
        $data = $inv[$key]
        if ($null -eq $data) { continue }
        if ($data -is [System.Collections.IEnumerable] -and $data -isnot [string]) {
            if (@($data).Count -gt 0) {
                @($data) | Export-Csv -Path (Join-Path $csvDir "$key.csv") -NoTypeInformation -Encoding UTF8
            }
        } else {
            @($data) | Export-Csv -Path (Join-Path $csvDir "$key.csv") -NoTypeInformation -Encoding UTF8
        }
    }

    # HTML report
    $css = @"
<style>
body { font-family: Segoe UI, Tahoma, sans-serif; font-size: 13px; margin: 24px; color: #1a1a1a; }
h1 { font-size: 22px; border-bottom: 3px solid #0b5394; padding-bottom: 6px; }
h2 { font-size: 16px; margin-top: 32px; background: #0b5394; color: #fff; padding: 6px 10px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 12px; }
th { background: #e8eef5; text-align: left; padding: 6px 8px; border: 1px solid #c3cfdd; font-weight: 600; }
td { padding: 5px 8px; border: 1px solid #dde3ea; vertical-align: top; word-break: break-word; }
tr:nth-child(even) td { background: #fafbfc; }
.meta { background: #f4f6f8; padding: 10px; border-left: 4px solid #0b5394; margin-bottom: 18px; }
.HIGH { background: #fdecea !important; }
.MEDIUM { background: #fff6e0 !important; }
.LOW { background: #eef7ee !important; }
.footer { margin-top: 32px; font-size: 11px; color: #666; border-top: 1px solid #ddd; padding-top: 8px; }
</style>
"@

    function New-HtmlSection {
        param([string]$Title, $Data)
        if ($null -eq $Data -or @($Data).Count -eq 0) {
            return "<h2>$Title</h2><p><em>No data collected.</em></p>"
        }
        $frag = @($Data) | ConvertTo-Html -Fragment
        return "<h2>$Title</h2>" + ($frag -join "`n")
    }

    $body = New-Object System.Text.StringBuilder
    [void]$body.AppendLine("<h1>IIS Decommissioning Inventory - $computer</h1>")
    [void]$body.AppendLine("<div class='meta'>Collected $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $($identity.Name)<br/>Log analysis window: $LogDays days<br/>This report is read-only output; no changes were made to the server.</div>")

    [void]$body.AppendLine((New-HtmlSection 'Decommissioning risk flags' $inv.RiskFlags))
    [void]$body.AppendLine((New-HtmlSection 'Server' $inv.Server))
    [void]$body.AppendLine((New-HtmlSection 'Volumes' $inv.Volumes))
    [void]$body.AppendLine((New-HtmlSection 'Sites' $inv.Sites))
    [void]$body.AppendLine((New-HtmlSection 'Bindings' $inv.Bindings))
    [void]$body.AppendLine((New-HtmlSection 'Log traffic analysis' $inv.LogAnalysis))
    [void]$body.AppendLine((New-HtmlSection 'Application pools' $inv.AppPools))
    [void]$body.AppendLine((New-HtmlSection 'Worker processes' $inv.WorkerProcesses))
    [void]$body.AppendLine((New-HtmlSection 'Applications' $inv.Applications))
    [void]$body.AppendLine((New-HtmlSection 'Virtual directories' $inv.VirtualDirectories))
    [void]$body.AppendLine((New-HtmlSection 'Connection strings' $inv.ConnectionStrings))
    [void]$body.AppendLine((New-HtmlSection 'URL rewrite rules' $inv.RewriteRules))
    [void]$body.AppendLine((New-HtmlSection 'Authentication' $inv.Authentication))
    [void]$body.AppendLine((New-HtmlSection 'Certificates' $inv.Certificates))
    [void]$body.AppendLine((New-HtmlSection 'SSL bindings' $inv.SslBindings))
    [void]$body.AppendLine((New-HtmlSection 'ISAPI filters' $inv.IsapiFilters))
    [void]$body.AppendLine((New-HtmlSection 'Global modules' $inv.GlobalModules))
    [void]$body.AppendLine((New-HtmlSection 'Handlers' $inv.Handlers))
    [void]$body.AppendLine((New-HtmlSection 'Scheduled tasks' $inv.ScheduledTasks))
    [void]$body.AppendLine((New-HtmlSection 'Services' $inv.Services))
    [void]$body.AppendLine((New-HtmlSection 'SMB shares' $inv.Shares))
    [void]$body.AppendLine((New-HtmlSection 'Listening ports' $inv.ListeningPorts))
    [void]$body.AppendLine((New-HtmlSection 'Established outbound connections' $inv.OutboundConnections))
    [void]$body.AppendLine((New-HtmlSection 'Inbound firewall rules' $inv.FirewallRules))
    [void]$body.AppendLine((New-HtmlSection 'Local administrators' $inv.LocalAdministrators))
    [void]$body.AppendLine((New-HtmlSection 'Local users' $inv.LocalUsers))
    [void]$body.AppendLine((New-HtmlSection 'Installed IIS features' $inv.WindowsFeatures))
    [void]$body.AppendLine((New-HtmlSection '.NET Framework versions' $inv.DotNetVersions))
    [void]$body.AppendLine((New-HtmlSection '.NET Core runtimes' $inv.DotNetCoreRuntimes))
    [void]$body.AppendLine((New-HtmlSection 'Installed software' $inv.InstalledSoftware))
    [void]$body.AppendLine((New-HtmlSection 'Collection errors' $inv.CollectionErrors))
    [void]$body.AppendLine("<div class='footer'>Generated by Get-IISDecommInventory.ps1</div>")

    $html = "<html><head><meta charset='utf-8'><title>IIS Inventory - $computer</title>$css</head><body>$($body.ToString())</body></html>"

    # Colour the risk rows by severity
    $html = $html -replace '<tr><td>HIGH</td>',   "<tr class='HIGH'><td>HIGH</td>"
    $html = $html -replace '<tr><td>MEDIUM</td>', "<tr class='MEDIUM'><td>MEDIUM</td>"
    $html = $html -replace '<tr><td>LOW</td>',    "<tr class='LOW'><td>LOW</td>"

    $html | Out-File (Join-Path $OutputPath 'IIS-Inventory-Report.html') -Encoding UTF8
}

#endregion

#region ---------------------------------------------------------- Console summary

#From an elevated session on the IIS server
# .\Get-IISDecommInventory.ps1 -OutputPath D:\Decomm -LogDays 90

# Fast pass, no log parsing
# .\Get-IISDecommInventory.ps1 -SkipLogAnalysis

Write-Host ""
Write-Host "==================== SUMMARY ====================" -ForegroundColor Green
Write-Host ("Sites             : {0} ({1} started, {2} stopped)" -f @($inv.Sites).Count, @($inv.Sites | Where-Object State -eq 'Started').Count, @($inv.Sites | Where-Object State -ne 'Started').Count)
Write-Host ("App pools         : {0}" -f @($inv.AppPools).Count)
Write-Host ("Bindings          : {0}" -f @($inv.Bindings).Count)
Write-Host ("Applications      : {0}" -f @($inv.Applications).Count)
Write-Host ("Certificates      : {0}" -f @($inv.Certificates).Count)
Write-Host ("Connection strings: {0}" -f @($inv.ConnectionStrings).Count)
Write-Host ""
Write-Host ("Risk flags        : {0} HIGH, {1} MEDIUM, {2} LOW" -f `
    @($inv.RiskFlags | Where-Object Severity -eq 'HIGH').Count, `
    @($inv.RiskFlags | Where-Object Severity -eq 'MEDIUM').Count, `
    @($inv.RiskFlags | Where-Object Severity -eq 'LOW').Count) -ForegroundColor Yellow

if (-not $SkipLogAnalysis) {
    Write-Host ""
    Write-Host "Traffic evidence (last $LogDays days):" -ForegroundColor Cyan
    $inv.LogAnalysis | Select-Object Site, TotalRequests, ExternalRequests, UniqueExternalIPs, LastEntryDate, Status | Format-Table -AutoSize
}

if (@($errors).Count -gt 0) {
    Write-Host ("Collection errors : {0} (see report)" -f @($errors).Count) -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Report: $(Join-Path $OutputPath 'IIS-Inventory-Report.html')" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

Stop-Transcript | Out-Null

#endregion

## Phase 2


