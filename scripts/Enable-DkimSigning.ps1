<#
.SYNOPSIS
    Enable DKIM signing for a custom domain in Microsoft 365 (Exchange Online),
    and print the exact CNAME records you must publish in DNS.

.DESCRIPTION
    DKIM record values are tenant-specific. The reliable workflow is:
      1) create the signing config (provisions the keys),
      2) read the EXACT Selector1/Selector2 CNAME targets from Exchange,
      3) publish those two CNAMEs in your DNS,
      4) enable signing once DNS has propagated.
    Don't guess the CNAME targets — read them from Get-DkimSigningConfig.

.NOTES
    Requires: ExchangeOnlineManagement module + an Exchange/Global admin account.
    Sanitized example — replace the domain with your own.
#>

param(
    [Parameter(Mandatory)] [string]$Domain,                  # e.g. example.com
    [string]$AdminUpn = "admin@example.onmicrosoft.com"
)

# One-time: Install-Module ExchangeOnlineManagement -Scope CurrentUser
Import-Module ExchangeOnlineManagement -ErrorAction Stop
Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false

# 1) Create the signing config if it doesn't exist (keys get provisioned here).
if (-not (Get-DkimSigningConfig -Identity $Domain -ErrorAction SilentlyContinue)) {
    Write-Host "Creating DKIM signing config for $Domain (disabled until CNAMEs are published)..."
    New-DkimSigningConfig -DomainName $Domain -Enabled:$false | Out-Null
}

# 2) Read the EXACT CNAME targets Exchange expects — publish THESE in DNS.
$cfg = Get-DkimSigningConfig -Identity $Domain
Write-Host "`nPublish these two CNAME records in your DNS (DNS-only / not proxied):" -ForegroundColor Cyan
Write-Host "  selector1._domainkey.$Domain  ->  $($cfg.Selector1CNAME)"
Write-Host "  selector2._domainkey.$Domain  ->  $($cfg.Selector2CNAME)"

# 3) After the CNAMEs resolve (give DNS a few minutes), enable signing.
Write-Host "`nWhen the CNAMEs have propagated, run:" -ForegroundColor Yellow
Write-Host "  Set-DkimSigningConfig -Identity $Domain -Enabled `$true"
Write-Host "Then confirm:"
Write-Host "  Get-DkimSigningConfig -Identity $Domain | Format-List Domain,Enabled,Status   # want Enabled=True, Status=Valid"

Disconnect-ExchangeOnline -Confirm:$false
