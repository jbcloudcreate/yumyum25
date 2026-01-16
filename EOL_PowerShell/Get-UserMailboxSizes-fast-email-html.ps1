# ============================================
# SEND EMAIL NOTIFICATION (.NET SmtpClient)
# ============================================

# Email Configuration
$SendEmails = $false  # Set to $true to actually send emails
$TestMode = $true     # Set to $true to send test emails to TestEmailAddress instead of real users
$TestEmailAddress = "your.test.account@south-wales.police.uk"  # Test recipient for TestMode
$FromAddress = "ict-noreply@south-wales.police.uk"
$SMTPServer = "smtp-in.swp.police.uk"
$EmailSubject = "Mailbox Storage Warning - Action Required"

# Email Template (HTML)
$EmailBodyTemplate = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            font-size: 14px;
            color: #333333;
            line-height: 1.6;
        }
        .header {
            background-color: #003366;
            color: #ffffff;
            padding: 20px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .content {
            padding: 20px;
        }
        .stats-box {
            background-color: #f5f5f5;
            border-left: 4px solid #003366;
            padding: 15px;
            margin: 20px 0;
        }
        .stats-box h3 {
            margin-top: 0;
            color: #003366;
        }
        .stats-table {
            width: 100%;
            border-collapse: collapse;
        }
        .stats-table td {
            padding: 8px;
            border-bottom: 1px solid #dddddd;
        }
        .stats-table td:first-child {
            font-weight: bold;
            width: 40%;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .steps {
            background-color: #e8f4f8;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .steps h3 {
            color: #003366;
            margin-top: 0;
        }
        .steps ol {
            margin-bottom: 0;
        }
        .steps li {
            margin-bottom: 10px;
        }
        .footer {
            background-color: #f5f5f5;
            padding: 15px;
            text-align: center;
            font-size: 12px;
            color: #666666;
            border-top: 1px solid #dddddd;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Mailbox Storage Warning</h1>
    </div>
    
    <div class="content">
        <p>Dear {FirstName},</p>
        
        <p>We are writing to inform you that your mailbox size has exceeded the recommended limit. To ensure you can continue to send and receive emails without any interruptions, we kindly ask you to reduce your mailbox size.</p>
        
        <div class="stats-box">
            <h3>Current Mailbox Statistics</h3>
            <table class="stats-table">
                <tr>
                    <td>Current Size:</td>
                    <td>{CurrentSize}</td>
                </tr>
                <tr>
                    <td>Maximum Quota:</td>
                    <td>{MaxQuota}</td>
                </tr>
                <tr>
                    <td>Items in Mailbox:</td>
                    <td>{ItemCount}</td>
                </tr>
                <tr>
                    <td>Deleted Items:</td>
                    <td>{DeletedItemCount} ({DeletedItemSize})</td>
                </tr>
            </table>
        </div>
        
        <div class="warning">
            <strong>Warning:</strong> If your mailbox size is not reduced, you may soon be unable to send or receive new emails.
        </div>
        
        <div class="steps">
            <h3>Steps to Reduce Your Mailbox Size</h3>
            <ol>
                <li>
                    <strong>Sort and Delete Large Emails</strong><br>
                    Open Outlook &rarr; Go to your Inbox &rarr; Click View &rarr; Arrange By &rarr; Size<br>
                    Review the largest emails and delete those you no longer need.<br>
                    <em>Tip: Save attachments to OneDrive or your H:\ Home Drive before deleting.</em>
                </li>
                <li>
                    <strong>Empty Deleted Items and Junk</strong><br>
                    In the Folder Pane, right-click Deleted Items &rarr; Select Empty Folder<br>
                    Repeat for the Junk Email folder.
                </li>
            </ol>
        </div>
        
        <p>If you have any questions or need assistance, please do not hesitate to contact the <strong>ICT Service Desk</strong>.</p>
        
        <p>Thank you for your cooperation.</p>
        
        <p>Best regards,<br>
        <strong>ICT Support Team</strong></p>
    </div>
    
    <div class="footer">
        This is an automated message. Please do not reply directly to this email.
    </div>
</body>
</html>
"@

# Send Emails action
if ($SendEmails -and $LargeMailboxes.Count -gt 0) {
    
    if ($TestMode) {
        Write-Host "`n--- TEST MODE: Emails will be sent to $TestEmailAddress ---" -ForegroundColor Magenta
    }
    
    Write-Host "`n--- Email Notifications ---" -ForegroundColor Cyan
    
    $emailsSent = 0
    $emailsFailed = 0
    
    foreach ($user in $LargeMailboxes) {
        
        # Build personalised email body
        $emailBody = $EmailBodyTemplate -replace '{FirstName}', $user.FirstName `
                                        -replace '{Surname}', $user.Surname `
                                        -replace '{CurrentSize}', $user.CurrentSize `
                                        -replace '{MaxQuota}', $user.MaxQuota `
                                        -replace '{ItemCount}', $user.ItemCount `
                                        -replace '{DeletedItemCount}', $user.DeletedItemCount `
                                        -replace '{DeletedItemSize}', $user.DeletedItemSize
        
        # Determine recipient - test account or real user
        $recipient = if ($TestMode) { $TestEmailAddress } else { $user.UPN }
        
        # Modify subject in test mode to show intended recipient
        $subject = if ($TestMode) { "[TEST - Intended for: $($user.UPN)] $EmailSubject" } else { $EmailSubject }
        
        try {
            # Create SMTP client and mail message
            $smtpClient = New-Object System.Net.Mail.SmtpClient($SMTPServer)
            $mailMessage = New-Object System.Net.Mail.MailMessage
            
            $mailMessage.From = $FromAddress
            $mailMessage.To.Add($recipient)
            $mailMessage.Subject = $subject
            $mailMessage.Body = $emailBody
            $mailMessage.IsBodyHtml = $true
            
            # Send the email
            $smtpClient.Send($mailMessage)
            
            Write-Host "Email sent to: $recipient $(if ($TestMode) { "(intended for $($user.UPN))" })" -ForegroundColor Green
            $emailsSent++
        }
        catch {
            Write-Host "Failed to send email to: $recipient - $_" -ForegroundColor Red
            $emailsFailed++
        }
        finally {
            # Clean up
            if ($mailMessage) { $mailMessage.Dispose() }
            if ($smtpClient) { $smtpClient.Dispose() }
        }
    }
    
    Write-Host "`nEmails sent: $emailsSent" -ForegroundColor Green
    Write-Host "Emails failed: $emailsFailed" -ForegroundColor $(if ($emailsFailed -gt 0) { 'Red' } else { 'Green' })
    
    if ($TestMode) {
        Write-Host "`nTEST MODE: All emails sent to $TestEmailAddress" -ForegroundColor Magenta
        Write-Host "Set `$TestMode = `$false to send to actual users" -ForegroundColor Magenta
    }
}
elseif ($LargeMailboxes.Count -eq 0) {
    Write-Host "`nNo mailboxes over threshold - no emails to send." -ForegroundColor Green
}
else {
    Write-Host "`nEmail sending is disabled. Set `$SendEmails = `$true to enable." -ForegroundColor Yellow
}
