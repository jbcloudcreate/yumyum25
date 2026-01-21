# Check if connected to Exchange Online
try {
    Get-EXOMailbox -ResultSize 1 -ErrorAction Stop | Out-Null
    Write-Host "Connected to Exchange Online" -ForegroundColor Green
}
catch {
    Write-Host "Not connected to Exchange Online. Connecting..." -ForegroundColor Yellow
    Connect-ExchangeOnline
}

# Get the user email
$UserEmail = Read-Host "Enter the user's email address"

# Validate the user exists
try {
    $User = Get-EXOMailbox -Identity $UserEmail -ErrorAction Stop
    Write-Host "`nFound user: $($User.DisplayName) ($($User.UserPrincipalName))" -ForegroundColor Green
}
catch {
    Write-Host "User not found: $UserEmail" -ForegroundColor Red
    exit
}

Write-Host "`nSearching for permissions... This may take a few minutes.`n" -ForegroundColor Cyan

# Initialize results array
$Results = @()

# 1. CHECK FULL ACCESS PERMISSIONS ON SHARED MAILBOXES
Write-Host "Checking Full Access permissions on Shared Mailboxes..." -ForegroundColor Cyan
$SharedMailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails SharedMailbox

foreach ($Mailbox in $SharedMailboxes) {
    $FullAccess = Get-EXOMailboxPermission -Identity $Mailbox.UserPrincipalName |
        Where-Object { $_.User -eq $UserEmail -and $_.AccessRights -contains "FullAccess" }

    if ($FullAccess) {
        $Results += [PSCustomObject]@{
            PermissionType = "Full Access"
            TargetMailbox = $Mailbox.DisplayName
            TargetEmail = $Mailbox.UserPrincipalName
            MailboxType = $Mailbox.RecipientTypeDetails
            AccessRights = "FullAccess"
        }
        Write-Host "  Found: Full Access to $($Mailbox.DisplayName)" -ForegroundColor Yellow
    }
}

Write-Host "Full Access check complete.`n" -ForegroundColor Green

# 2. CHECK CALENDAR PERMISSIONS ON SHARED MAILBOXES
Write-Host "Checking Calendar permissions on Shared Mailboxes..." -ForegroundColor Cyan

foreach ($Mailbox in $SharedMailboxes) {
    try {
        $CalendarPerms = Get-EXOMailboxFolderPermission -Identity "$($Mailbox.UserPrincipalName):\Calendar" -ErrorAction SilentlyContinue |
            Where-Object { $_.User.DisplayName -eq $UserEmail -or $_.User.ADRecipient.PrimarySmtpAddress -eq $UserEmail }

        if ($CalendarPerms) {
            foreach ($Perm in $CalendarPerms) {
                $Results += [PSCustomObject]@{
                    PermissionType = "Calendar"
                    TargetMailbox = $Mailbox.DisplayName
                    TargetEmail = $Mailbox.UserPrincipalName
                    MailboxType = $Mailbox.RecipientTypeDetails
                    AccessRights = $Perm.AccessRights -join ", "
                }
                Write-Host "  Found: Calendar access ($($Perm.AccessRights -join ', ')) to $($Mailbox.DisplayName)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        # Calendar may not exist or be inaccessible
    }
}

Write-Host "Calendar check complete.`n" -ForegroundColor Green

# Display results summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RESULTS SUMMARY FOR: $($User.DisplayName)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($Results.Count -eq 0) {
    Write-Host "No shared mailbox or calendar permissions found for this user." -ForegroundColor Yellow
}
else {
    Write-Host "Found $($Results.Count) permission(s):`n" -ForegroundColor Green
    $Results | Format-Table -AutoSize
}
