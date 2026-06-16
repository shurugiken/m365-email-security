<#
.SYNOPSIS
    Restrict a Microsoft Graph "Mail.Send" application so it can only send as a
    SINGLE mailbox, instead of every mailbox in the tenant (least privilege).

.DESCRIPTION
    Registering an Entra ID app with the Mail.Send *application* permission lets a
    script send mail with no signed-in user — but by default it can impersonate ANY
    mailbox. An Application Access Policy scopes that down to the members of one
    mail-enabled security group.

    Prereqs you do once in the Entra portal (entra.microsoft.com):
      1. App registrations -> New registration (single tenant, no redirect URI).
      2. API permissions -> Microsoft Graph -> Application permissions -> Mail.Send -> add.
      3. Grant admin consent.
      4. Certificates & secrets -> New client secret (store it safely; never commit it).
    Then run this script with the app's Client ID to lock it to one mailbox.

.NOTES
    Requires: ExchangeOnlineManagement module + admin. Sanitized example.
#>

param(
    [Parameter(Mandatory)] [string]$AppId,                         # the Entra app (client) ID
    [Parameter(Mandatory)] [string]$SenderUpn,                     # e.g. notifications@example.com
    [string]$GroupName  = "GraphMailSenders",
    [string]$GroupSmtp  = "graphmailsenders@example.com",
    [string]$AdminUpn   = "admin@example.onmicrosoft.com"
)

Import-Module ExchangeOnlineManagement -ErrorAction Stop
Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false

# Mail-enabled security group that holds the allowed sender(s).
if (-not (Get-DistributionGroup -Identity $GroupName -ErrorAction SilentlyContinue)) {
    New-DistributionGroup -Name $GroupName -Type Security -PrimarySmtpAddress $GroupSmtp | Out-Null
}
Add-DistributionGroupMember -Identity $GroupName -Member $SenderUpn -ErrorAction SilentlyContinue

# Restrict the app to ONLY the group's members.
New-ApplicationAccessPolicy -AppId $AppId -PolicyScopeGroupId $GroupName `
    -AccessRight RestrictAccess -Description "Restrict $AppId to $GroupName only"

# Verify: should return Granted for the sender, Denied for anyone else.
Write-Host "`nVerification:" -ForegroundColor Cyan
Test-ApplicationAccessPolicy -Identity $SenderUpn -AppId $AppId | Format-List Identity,AccessCheckResult

Disconnect-ExchangeOnline -Confirm:$false
