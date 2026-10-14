<#
.SYNOPSIS
    Read-only discovery of Absolute Secure Access (NetMotion) and Insights for Network (IFN)
    components, to inform Microsoft Defender exclusion requests.

.DESCRIPTION
    Makes NO configuration changes. The only thing it writes is the report file
    (and C:\Temp if it doesn't already exist).

    Reports:
      1. Install and data folders (Program Files, Program Files (x86), ProgramData, and the root of every fixed drive)
      2. Services running from those folders
      3. Running processes from those folders
      4. Kernel drivers published by Absolute / NetMotion, with signature details
      5. TCP/UDP ports those processes are listening on
      6. Non-admin write access on the discovered folders
      7. Database or search services that may need their own vendor exclusions
      8. Defender status and current exclusions

    Report is saved to C:\Temp\<COMPUTERNAME>_AbsoluteExclusionInfo.txt

    Run from an elevated PowerShell session. Tested for Windows PowerShell 5.1.
#>

$ErrorActionPreference = 'SilentlyContinue'

$pattern = 'NetMotion|Absolute|AIFN'
$outDir  = 'C:\Temp'
$outFile = Join-Path $outDir ('{0}_AbsoluteExclusionInfo.txt' -f $env:COMPUTERNAME)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Not running elevated - process paths and Defender exclusions will be incomplete.'
}

New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Write-Section {
    param(
        [string]$Title,
        $Data,
        [switch]$List
    )
    $text = "`r`n==== $Title ====`r`n"
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        $text += "None found`r`n"
    }
    elseif ($List) {
        $text += ($Data | Format-List | Out-String -Width 400)
    }
    else {
        $text += ($Data | Format-Table -AutoSize -Wrap | Out-String -Width 400)
    }
    $text | Out-File -FilePath $outFile -Append -Encoding utf8
    Write-Host $text
}

# ---- Header -------------------------------------------------------------
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$header = @"
Absolute Secure Access - Defender exclusion discovery
Server : $env:COMPUTERNAME
Run    : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
OS     : $os
Elevated: $isAdmin
"@
$header | Out-File -FilePath $outFile -Encoding utf8
Write-Host $header

# ---- 1. Folders ---------------------------------------------------------
$roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)
$roots += (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3').DeviceID | ForEach-Object { "$_\" }

$folders = foreach ($root in ($roots | Where-Object { $_ } | Select-Object -Unique)) {
    Get-ChildItem -Path $root -Directory -Force | Where-Object { $_.Name -match $pattern }
}
$folders     = $folders | Sort-Object FullName -Unique
$folderPaths = @($folders.FullName)

Write-Section '1. Install and data folders' ($folders | Select-Object FullName, LastWriteTime)

function Test-InScope {
    param([string]$Path)
    if (-not $Path) { return $false }
    $clean = $Path -replace '^"', ''
    foreach ($f in $folderPaths) {
        if ($clean -like "$f\*") { return $true }
    }
    return ($clean -match $pattern)
}

# ---- 2. Services --------------------------------------------------------
$services = Get-CimInstance Win32_Service | Where-Object { Test-InScope $_.PathName }
Write-Section '2. Services' ($services | Sort-Object Name |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName)

# ---- 3. Processes -------------------------------------------------------
$procs = Get-Process | Where-Object { Test-InScope $_.Path }
Write-Section '3. Running processes (unique paths)' ($procs | Sort-Object Path -Unique |
    Select-Object Name, Path)

# ---- 4. Drivers (matched on publisher, not file name) -------------------
$driverSvcs = Get-CimInstance Win32_SystemDriver
$drivers = Get-ChildItem "$env:SystemRoot\System32\drivers\*.sys" |
    Where-Object { $_.VersionInfo.CompanyName -match $pattern } |
    ForEach-Object {
        $file = $_
        $sig  = Get-AuthenticodeSignature $file.FullName
        $svc  = $driverSvcs | Where-Object { $_.PathName -like "*\$($file.Name)" } | Select-Object -First 1
        [pscustomobject]@{
            Name      = $file.Name
            Path      = $file.FullName
            Company   = $file.VersionInfo.CompanyName
            Version   = $file.VersionInfo.FileVersion
            State     = if ($svc) { $svc.State } else { 'No service entry (library driver or unused)' }
            SigStatus = $sig.Status
            Signer    = $sig.SignerCertificate.Subject
        }
    }
Write-Section '4. Absolute / NetMotion kernel drivers' ($drivers | Sort-Object Name) -List

# ---- 5. Listening ports -------------------------------------------------
$pids = @($procs.Id)
$procNames = @{}
foreach ($p in $procs) { $procNames[$p.Id] = $p.Name }

$tcp = Get-NetTCPConnection -State Listen | Where-Object { $pids -contains $_.OwningProcess } |
    ForEach-Object {
        [pscustomobject]@{
            Protocol     = 'TCP'
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            Process      = $procNames[[int]$_.OwningProcess]
        }
    }
$udp = Get-NetUDPEndpoint | Where-Object { $pids -contains $_.OwningProcess } |
    ForEach-Object {
        [pscustomobject]@{
            Protocol     = 'UDP'
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            Process      = $procNames[[int]$_.OwningProcess]
        }
    }
$ports = @($tcp) + @($udp) | Where-Object { $_ } |
    Sort-Object Protocol, LocalPort, LocalAddress -Unique
Write-Section '5. Listening ports owned by these processes' $ports
$portNote = "NOTE: ports opened by kernel drivers show as the System process (PID 4) and are not listed above. " +
            "Cross-check against the port table in Absolute's documentation.`r`n"
$portNote | Out-File -FilePath $outFile -Append -Encoding utf8
Write-Host $portNote

# ---- 6. Folder permissions ----------------------------------------------
$broadIds    = 'Everyone|BUILTIN\\Users|Authenticated Users|Domain Users'
$writeRights = 'Write|Modify|FullControl|CreateFiles|AppendData'
$aclFindings = foreach ($f in $folderPaths) {
    (Get-Acl -Path $f).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference.Value -match $broadIds -and
        $_.FileSystemRights.ToString() -match $writeRights
    } | ForEach-Object {
        [pscustomobject]@{
            Folder    = $f
            Identity  = $_.IdentityReference.Value
            Rights    = $_.FileSystemRights
            Inherited = $_.IsInherited
        }
    }
}
Write-Section '6. Non-admin write access on these folders (ideally none)' $aclFindings

# ---- 7. Database / search services --------------------------------------
$dbPattern = 'sqlservr|mongod|postgres|elasticsearch|redis'
$dbSvcs = Get-CimInstance Win32_Service | Where-Object {
    $_.Name -match '^MSSQL|^SQLAgent' -or $_.PathName -match $dbPattern
}
Write-Section '7. Database / search services (may need their own vendor exclusions)' ($dbSvcs |
    Select-Object Name, State, PathName)

# ---- 8. Defender status and current exclusions --------------------------
$status = Get-MpComputerStatus
$mp     = Get-MpPreference
$defender = [pscustomobject]@{
    AMRunningMode          = $status.AMRunningMode
    PlatformVersion        = $status.AMProductVersion
    RealTimeProtection     = $status.RealTimeProtectionEnabled
    DisableLocalAdminMerge = $mp.DisableLocalAdminMerge
    ExclusionPath          = ($mp.ExclusionPath -join '; ')
    ExclusionProcess       = ($mp.ExclusionProcess -join '; ')
    ExclusionExtension     = ($mp.ExclusionExtension -join '; ')
}
Write-Section '8. Defender status and current exclusions' $defender -List

Write-Host "`r`nReport saved to $outFile" -ForegroundColor Green
