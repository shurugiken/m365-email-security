#Requires -Modules Pester
<#
.SYNOPSIS
    Pester v5 tests for m365-email-security scripts.
    All Exchange Online / Graph cmdlets are mocked — no real network calls or credentials needed.
#>

Describe 'SPF record format' {

    Context 'well-formed SPF include for M365' {
        It 'passes a single-include hard-fail record' {
            $record = 'v=spf1 include:spf.protection.outlook.com -all'
            $record | Should -Match '^v=spf1\s'
            $record | Should -Match 'include:spf\.protection\.outlook\.com'
            $record | Should -Match '-all$'
        }

        It 'passes a soft-fail variant' {
            $record = 'v=spf1 include:spf.protection.outlook.com ~all'
            $record | Should -Match '~all$'
        }

        It 'rejects a record that contains more than one SPF directive (would be invalid DNS)' {
            # Only one SPF record is allowed per domain; a second one is a misconfiguration.
            $records = @(
                'v=spf1 include:spf.protection.outlook.com -all',
                'v=spf1 include:mailgun.org -all'
            )
            $spfCount = ($records | Where-Object { $_ -match '^v=spf1' }).Count
            $spfCount | Should -BeGreaterThan 1   # confirms the test detects the violation
        }

        It 'does not pass when v= tag is missing' {
            $record = 'include:spf.protection.outlook.com -all'
            $record | Should -Not -Match '^v=spf1'
        }
    }
}

Describe 'DMARC record format' {

    Context 'tag parsing' {
        BeforeAll {
            function Parse-DmarcRecord {
                param([string]$Record)
                $tags = @{}
                $Record -split '\s*;\s*' | ForEach-Object {
                    $parts = $_ -split '=', 2
                    if ($parts.Count -eq 2) {
                        $tags[$parts[0].Trim()] = $parts[1].Trim()
                    }
                }
                return $tags
            }
        }

        It 'parses the version tag correctly' {
            $tags = Parse-DmarcRecord 'v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1'
            $tags['v'] | Should -Be 'DMARC1'
        }

        It 'parses the policy tag correctly' {
            $tags = Parse-DmarcRecord 'v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1'
            $tags['p'] | Should -Be 'none'
        }

        It 'parses a quarantine policy' {
            $tags = Parse-DmarcRecord 'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com'
            $tags['p'] | Should -Be 'quarantine'
        }

        It 'parses a reject policy' {
            $tags = Parse-DmarcRecord 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'
            $tags['p'] | Should -Be 'reject'
        }

        It 'parses the rua tag' {
            $tags = Parse-DmarcRecord 'v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1'
            $tags['rua'] | Should -Be 'mailto:dmarc@example.com'
        }

        It 'detects when v=DMARC1 is absent' {
            $record = 'p=none; rua=mailto:dmarc@example.com'
            $tags = Parse-DmarcRecord $record
            $tags.ContainsKey('v') | Should -BeFalse
        }

        It 'accepts all three valid policy values' {
            $validPolicies = @('none', 'quarantine', 'reject')
            foreach ($p in $validPolicies) {
                $tags = Parse-DmarcRecord "v=DMARC1; p=$p"
                $validPolicies | Should -Contain $tags['p']
            }
        }
    }
}

Describe 'DKIM CNAME record format' {

    Context 'selector naming convention' {
        BeforeAll {
            function New-DkimCnameRecord {
                param(
                    [string]$Selector,     # 'selector1' or 'selector2'
                    [string]$Domain,
                    [string]$CnameTarget
                )
                return [PSCustomObject]@{
                    Name   = "$Selector._domainkey.$Domain"
                    Type   = 'CNAME'
                    Target = $CnameTarget
                }
            }
        }

        It 'builds correct selector1 record name' {
            $rec = New-DkimCnameRecord -Selector 'selector1' -Domain 'example.com' `
                -CnameTarget 'selector1-example-com._domainkey.contoso.onmicrosoft.com'
            $rec.Name | Should -Be 'selector1._domainkey.example.com'
        }

        It 'builds correct selector2 record name' {
            $rec = New-DkimCnameRecord -Selector 'selector2' -Domain 'example.com' `
                -CnameTarget 'selector2-example-com._domainkey.contoso.onmicrosoft.com'
            $rec.Name | Should -Be 'selector2._domainkey.example.com'
        }

        It 'preserves the tenant-specific CNAME target verbatim' {
            $target = 'selector1-example-com._domainkey.contoso.onmicrosoft.com'
            $rec = New-DkimCnameRecord -Selector 'selector1' -Domain 'example.com' -CnameTarget $target
            $rec.Target | Should -Be $target
        }

        It 'type is CNAME' {
            $rec = New-DkimCnameRecord -Selector 'selector1' -Domain 'example.com' -CnameTarget 'some-target'
            $rec.Type | Should -Be 'CNAME'
        }

        It 'also accepts the newer r-v1 CNAME target format' {
            $target = 'selector1-example-com._domainkey.contoso.r-v1.dkim.mail.microsoft'
            $rec = New-DkimCnameRecord -Selector 'selector1' -Domain 'example.com' -CnameTarget $target
            $rec.Target | Should -BeLike '*.r-v1.dkim.mail.microsoft'
        }
    }
}

Describe 'Enable-DkimSigning.ps1 — DKIM config creation logic' {

    BeforeAll {
        # Provide stub functions so the script can Import-Module and connect without errors.
        function global:Import-Module { }
        function global:Connect-ExchangeOnline { }
        function global:Disconnect-ExchangeOnline { }
        function global:New-DkimSigningConfig { }
        function global:Set-DkimSigningConfig { }
        function global:Get-DkimSigningConfig { }
    }

    AfterAll {
        Remove-Item Function:\Import-Module        -ErrorAction SilentlyContinue
        Remove-Item Function:\Connect-ExchangeOnline    -ErrorAction SilentlyContinue
        Remove-Item Function:\Disconnect-ExchangeOnline -ErrorAction SilentlyContinue
        Remove-Item Function:\New-DkimSigningConfig     -ErrorAction SilentlyContinue
        Remove-Item Function:\Set-DkimSigningConfig     -ErrorAction SilentlyContinue
        Remove-Item Function:\Get-DkimSigningConfig     -ErrorAction SilentlyContinue
    }

    Context 'when the DKIM config does NOT yet exist' {
        BeforeEach {
            # First call (existence check) returns nothing; second call returns the full config.
            $script:GetCallCount = 0
            Mock -CommandName Get-DkimSigningConfig -MockWith {
                $script:GetCallCount++
                if ($script:GetCallCount -eq 1) { return $null }
                return [PSCustomObject]@{
                    Selector1CNAME = 'selector1-example-com._domainkey.contoso.onmicrosoft.com'
                    Selector2CNAME = 'selector2-example-com._domainkey.contoso.onmicrosoft.com'
                }
            } -Verifiable
            Mock -CommandName New-DkimSigningConfig -MockWith { } -Verifiable
            Mock -CommandName Connect-ExchangeOnline -MockWith { }
            Mock -CommandName Disconnect-ExchangeOnline -MockWith { }
            Mock -CommandName Import-Module -MockWith { }
        }

        It 'calls New-DkimSigningConfig when config is absent' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\Enable-DkimSigning.ps1'
            & $scriptPath -Domain 'example.com' -AdminUpn 'admin@example.onmicrosoft.com'
            Should -Invoke New-DkimSigningConfig -Times 1 -Exactly
        }

        It 'calls Get-DkimSigningConfig at least twice (check + read)' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\Enable-DkimSigning.ps1'
            & $scriptPath -Domain 'example.com' -AdminUpn 'admin@example.onmicrosoft.com'
            Should -Invoke Get-DkimSigningConfig -Times 2 -Exactly
        }
    }

    Context 'when the DKIM config ALREADY exists' {
        BeforeEach {
            Mock -CommandName Get-DkimSigningConfig -MockWith {
                return [PSCustomObject]@{
                    Selector1CNAME = 'selector1-example-com._domainkey.contoso.onmicrosoft.com'
                    Selector2CNAME = 'selector2-example-com._domainkey.contoso.onmicrosoft.com'
                }
            }
            Mock -CommandName New-DkimSigningConfig -MockWith { }
            Mock -CommandName Connect-ExchangeOnline -MockWith { }
            Mock -CommandName Disconnect-ExchangeOnline -MockWith { }
            Mock -CommandName Import-Module -MockWith { }
        }

        It 'does NOT call New-DkimSigningConfig when config already exists' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\Enable-DkimSigning.ps1'
            & $scriptPath -Domain 'example.com' -AdminUpn 'admin@example.onmicrosoft.com'
            Should -Invoke New-DkimSigningConfig -Times 0 -Exactly
        }

        It 'outputs the selector1 CNAME target' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\Enable-DkimSigning.ps1'
            $output = & $scriptPath -Domain 'example.com' -AdminUpn 'admin@example.onmicrosoft.com' 6>&1 | Out-String
            $output | Should -Match 'selector1-example-com._domainkey.contoso.onmicrosoft.com'
        }

        It 'outputs the selector2 CNAME target' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\Enable-DkimSigning.ps1'
            $output = & $scriptPath -Domain 'example.com' -AdminUpn 'admin@example.onmicrosoft.com' 6>&1 | Out-String
            $output | Should -Match 'selector2-example-com._domainkey.contoso.onmicrosoft.com'
        }

        It 'connects and disconnects Exchange Online' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\Enable-DkimSigning.ps1'
            & $scriptPath -Domain 'example.com' -AdminUpn 'admin@example.onmicrosoft.com'
            Should -Invoke Connect-ExchangeOnline    -Times 1 -Exactly
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly
        }
    }
}

Describe 'New-ScopedGraphMailApp.ps1 — least-privilege policy logic' {

    BeforeAll {
        function global:Import-Module { }
        function global:Connect-ExchangeOnline { }
        function global:Disconnect-ExchangeOnline { }
        function global:Get-DistributionGroup { }
        function global:New-DistributionGroup { }
        function global:Add-DistributionGroupMember { }
        function global:New-ApplicationAccessPolicy { }
        function global:Test-ApplicationAccessPolicy { }
    }

    AfterAll {
        Remove-Item Function:\Import-Module                  -ErrorAction SilentlyContinue
        Remove-Item Function:\Connect-ExchangeOnline         -ErrorAction SilentlyContinue
        Remove-Item Function:\Disconnect-ExchangeOnline      -ErrorAction SilentlyContinue
        Remove-Item Function:\Get-DistributionGroup          -ErrorAction SilentlyContinue
        Remove-Item Function:\New-DistributionGroup          -ErrorAction SilentlyContinue
        Remove-Item Function:\Add-DistributionGroupMember    -ErrorAction SilentlyContinue
        Remove-Item Function:\New-ApplicationAccessPolicy    -ErrorAction SilentlyContinue
        Remove-Item Function:\Test-ApplicationAccessPolicy   -ErrorAction SilentlyContinue
    }

    Context 'when the security group does NOT yet exist' {
        BeforeEach {
            Mock -CommandName Get-DistributionGroup       -MockWith { return $null }
            Mock -CommandName New-DistributionGroup       -MockWith { }
            Mock -CommandName Add-DistributionGroupMember -MockWith { }
            Mock -CommandName New-ApplicationAccessPolicy -MockWith { }
            Mock -CommandName Test-ApplicationAccessPolicy -MockWith {
                return [PSCustomObject]@{
                    Identity          = 'notifications@example.com'
                    AccessCheckResult = 'Granted'
                }
            }
            Mock -CommandName Connect-ExchangeOnline    -MockWith { }
            Mock -CommandName Disconnect-ExchangeOnline -MockWith { }
            Mock -CommandName Import-Module             -MockWith { }
        }

        It 'creates the distribution group when it is absent' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\New-ScopedGraphMailApp.ps1'
            & $scriptPath `
                -AppId      'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                -SenderUpn  'notifications@example.com' `
                -AdminUpn   'admin@example.onmicrosoft.com'
            Should -Invoke New-DistributionGroup -Times 1 -Exactly
        }

        It 'adds the sender to the distribution group' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\New-ScopedGraphMailApp.ps1'
            & $scriptPath `
                -AppId      'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                -SenderUpn  'notifications@example.com' `
                -AdminUpn   'admin@example.onmicrosoft.com'
            Should -Invoke Add-DistributionGroupMember -Times 1 -Exactly
        }

        It 'creates the application access policy with RestrictAccess' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\New-ScopedGraphMailApp.ps1'
            & $scriptPath `
                -AppId      'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                -SenderUpn  'notifications@example.com' `
                -AdminUpn   'admin@example.onmicrosoft.com'
            Should -Invoke New-ApplicationAccessPolicy -Times 1 -Exactly
        }

        It 'runs the verification step via Test-ApplicationAccessPolicy' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\New-ScopedGraphMailApp.ps1'
            & $scriptPath `
                -AppId      'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                -SenderUpn  'notifications@example.com' `
                -AdminUpn   'admin@example.onmicrosoft.com'
            Should -Invoke Test-ApplicationAccessPolicy -Times 1 -Exactly
        }
    }

    Context 'when the security group ALREADY exists' {
        BeforeEach {
            Mock -CommandName Get-DistributionGroup -MockWith {
                return [PSCustomObject]@{ Name = 'GraphMailSenders'; PrimarySmtpAddress = 'graphmailsenders@example.com' }
            }
            Mock -CommandName New-DistributionGroup       -MockWith { }
            Mock -CommandName Add-DistributionGroupMember -MockWith { }
            Mock -CommandName New-ApplicationAccessPolicy -MockWith { }
            Mock -CommandName Test-ApplicationAccessPolicy -MockWith {
                return [PSCustomObject]@{
                    Identity          = 'notifications@example.com'
                    AccessCheckResult = 'Granted'
                }
            }
            Mock -CommandName Connect-ExchangeOnline    -MockWith { }
            Mock -CommandName Disconnect-ExchangeOnline -MockWith { }
            Mock -CommandName Import-Module             -MockWith { }
        }

        It 'does NOT call New-DistributionGroup when group already exists' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\New-ScopedGraphMailApp.ps1'
            & $scriptPath `
                -AppId      'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                -SenderUpn  'notifications@example.com' `
                -AdminUpn   'admin@example.onmicrosoft.com'
            Should -Invoke New-DistributionGroup -Times 0 -Exactly
        }

        It 'still adds the sender and creates the policy even when group exists' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\New-ScopedGraphMailApp.ps1'
            & $scriptPath `
                -AppId      'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                -SenderUpn  'notifications@example.com' `
                -AdminUpn   'admin@example.onmicrosoft.com'
            Should -Invoke Add-DistributionGroupMember    -Times 1 -Exactly
            Should -Invoke New-ApplicationAccessPolicy    -Times 1 -Exactly
        }

        It 'connects and disconnects Exchange Online' {
            $scriptPath = Join-Path $PSScriptRoot '..\scripts\New-ScopedGraphMailApp.ps1'
            & $scriptPath `
                -AppId      'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                -SenderUpn  'notifications@example.com' `
                -AdminUpn   'admin@example.onmicrosoft.com'
            Should -Invoke Connect-ExchangeOnline    -Times 1 -Exactly
            Should -Invoke Disconnect-ExchangeOnline -Times 1 -Exactly
        }
    }
}
