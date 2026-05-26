# Get-AllFolderPermissions.ps1
# Returns folder permissions for every folder in a shared mailbox
# Optionally filter by a specific user

# All users
#.\Get-AllFolderPermissions.ps1 -Mailbox "sharedmailbox@swp.police.uk"

# Specific user
#.\Get-AllFolderPermissions.ps1 -Mailbox "sharedmailbox@swp.police.uk" -User "Jones,David"

#.\Get-AllFolderPermissions.ps1 -Mailbox "sharedmailbox@swp.police.uk" -User "david.jones@swp.police.uk"

param (
    [Parameter(Mandatory = $true)]
    [string]$Mailbox,

    [Parameter(Mandatory = $false)]
    [string]$User
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

        # Filter by email address if param was supplied
        if ($User) {
            $perms = $perms | Where-Object { $_.User.ADRecipient.PrimarySmtpAddress -like "*$User*" }
        }

        foreach ($perm in $perms) {
            $rights = $perm.AccessRights -join ', '
            $level  = if ($permMap.ContainsKey($rights)) { $permMap[$rights] } else { $rights }

            $results += [PSCustomObject]@{
                Folder             = $folderPath
                User               = $perm.User.ADRecipient.PrimarySmtpAddress
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
