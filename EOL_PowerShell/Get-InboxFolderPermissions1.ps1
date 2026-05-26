param (
    [Parameter(Mandatory = $true)]
    [string]$Mailbox
)

$folder = "${Mailbox}:\Inbox"

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

Get-MailboxFolderPermission -Identity $folder |
    ForEach-Object {
        $rights = $_.AccessRights -join ', '
        $level  = if ($permMap.ContainsKey($rights)) { $permMap[$rights] } else { $rights }
        [PSCustomObject]@{
            User            = $_.User.DisplayName
            'Permission Level' = $level
            AccessRights    = $rights
        }
    } |
    Format-Table -AutoSize
