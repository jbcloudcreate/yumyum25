# Get-AllFolderPermissions.ps1
# Returns folder permissions for every folder in a shared mailbox

param (
    [Parameter(Mandatory = $true)]
    [string]$Mailbox
)

$permMap = @{
    'Owner'            = 'Owner'
    'PublishingEditor' = 'Publishing Editor'
    'Editor'           = 'Editor'
    'PublishingAuthor' = 'Publishing Author'
    'Author'           = 'Author'
    'NonEditingAuthor' = 'Non-Editing Author'
    'Reviewer'         = 'Reviewer'
    'Contributor'      = 'Contributor'
    'None'             = 'None'
}

$excludeFolders = @('Yammer', 'Tasks', 'Notes', 'Junk Email', 'Outbox')

$results = @()

$folders = Get-MailboxFolderStatistics -Identity $Mailbox |
    Where-Object { $excludeFolders -notcontains $_.Name } |
    Select-Object -ExpandProperty FolderPath

foreach ($folderPath in $folders) {

    $identity = $Mailbox + ":" + $folderPath.Replace("/", "\")

    try {
        $perms = Get-MailboxFolderPermission -Identity $identity -ErrorAction Stop

        foreach ($perm in $perms) {
            $rights = $perm.AccessRights -join ', '
            $level  = if ($permMap.ContainsKey($rights)) { $permMap[$rights] } else { $rights }

            $results += [PSCustomObject]@{
                Folder             = $folderPath
                User               = $perm.User.DisplayName
                'Permission Level' = $level
                AccessRights       = $rights
            }
        }
    }
    catch {
        Write-Verbose "Skipped: $identity — $($_.Exception.Message)"
    }
}

$results | Format-Table -AutoSize

# $results | Export-Csv -Path ".\MailboxFolderPermissions.csv" -NoTypeInformation
