BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Resolve-ADGroupMembershipChain.ps1')

    function Get-ADGroup {
        param(
            [string]$Identity,
            [string[]]$Properties,
            [string]$ErrorAction
        )

        if ($Identity -eq 'CN=Domain Admins,DC=contoso,DC=local' -or $Identity -eq 'Domain Admins') {
            return [pscustomobject]@{
                Name = 'Domain Admins'
                DistinguishedName = 'CN=Domain Admins,DC=contoso,DC=local'
                objectClass = 'group'
            }
        }

        if ($Identity -eq 'CN=Legacy Operators,DC=contoso,DC=local' -or $Identity -eq 'Legacy Operators') {
            return [pscustomobject]@{
                Name = 'Legacy Operators'
                DistinguishedName = 'CN=Legacy Operators,DC=contoso,DC=local'
                objectClass = 'group'
                member = @(
                    'CN=Orphaned User,DC=contoso,DC=local',
                    'CN=S-1-5-21-555,CN=ForeignSecurityPrincipals,DC=contoso,DC=local'
                )
            }
        }

        $null
    }

    function Get-ADGroupMember {
        param(
            [string]$Identity,
            [string]$ErrorAction
        )

        switch ($Identity) {
            'CN=Domain Admins,DC=contoso,DC=local' {
                @(
                    [pscustomobject]@{
                        Name = 'Admin One'
                        SamAccountName = 'adm.one'
                        DistinguishedName = 'CN=Admin One,DC=contoso,DC=local'
                        objectClass = 'user'
                    },
                    [pscustomobject]@{
                        Name = 'Nested Admins'
                        SamAccountName = 'Nested Admins'
                        DistinguishedName = 'CN=Nested Admins,DC=contoso,DC=local'
                        objectClass = 'group'
                    }
                )
            }
            'CN=Nested Admins,DC=contoso,DC=local' {
                @(
                    [pscustomobject]@{
                        Name = 'Nested User'
                        SamAccountName = 'nested.user'
                        DistinguishedName = 'CN=Nested User,DC=contoso,DC=local'
                        objectClass = 'user'
                    },
                    [pscustomobject]@{
                        Name = 'Domain Admins'
                        SamAccountName = 'Domain Admins'
                        DistinguishedName = 'CN=Domain Admins,DC=contoso,DC=local'
                        objectClass = 'group'
                    }
                )
            }
            'CN=Legacy Operators,DC=contoso,DC=local' {
                throw 'An operations error occurred'
            }
            default { @() }
        }
    }

    function Get-ADObject {
        param(
            [string]$Identity,
            [string[]]$Properties,
            [string]$ErrorAction
        )

        if ($Identity -eq 'CN=Orphaned User,DC=contoso,DC=local') {
            return [pscustomobject]@{
                Name = 'Orphaned User'
                sAMAccountName = 'orphaned.user'
                DistinguishedName = 'CN=Orphaned User,DC=contoso,DC=local'
                ObjectClass = 'user'
                objectSid = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-7001' }
            }
        }

        throw "Cannot find an object with identity: '$Identity'."
    }

}

Describe 'Group membership chain resolution' {
    It 'preserves direct and indirect memberships without truncating normal paths' {
        $rows = Resolve-ADGroupMembershipChain -GroupIdentity 'Domain Admins' -MaxDepth 4

        @($rows | Where-Object { $_.Member.SamAccountName -eq 'adm.one' }).Count | Should -Be 1
        $direct = $rows | Where-Object { $_.Member.SamAccountName -eq 'adm.one' } | Select-Object -First 1
        $indirect = $rows | Where-Object { $_.Member.SamAccountName -eq 'nested.user' } | Select-Object -First 1
        $direct.IsDirectMembership | Should -Be $true
        $direct.DirectParentGroupName | Should -Be 'Domain Admins'
        $direct.DirectParentGroupDn | Should -Be 'CN=Domain Admins,DC=contoso,DC=local'
        $direct.CanGenerateRemediationScript | Should -Be $true
        $direct.MembershipEnumerationMode | Should -Be 'Standard'
        $indirect.NestingDepth | Should -Be 1
        $indirect.DirectParentGroupName | Should -Be 'Nested Admins'
        $indirect.DirectParentGroupDn | Should -Be 'CN=Nested Admins,DC=contoso,DC=local'
        $indirect.CanGenerateRemediationScript | Should -Be $true
        @($rows | Where-Object { $_.TruncatedNesting }).Count | Should -Be 1
    }

    It 'marks group rows as truncated when MaxDepth prevents expansion' {
        $rows = Resolve-ADGroupMembershipChain -GroupIdentity 'Domain Admins' -MaxDepth 1
        $nestedGroup = $rows | Where-Object { $_.Member.DistinguishedName -eq 'CN=Nested Admins,DC=contoso,DC=local' } | Select-Object -First 1

        $nestedGroup.TruncatedNesting | Should -Be $true
        $nestedGroup.CanGenerateRemediationScript | Should -Be $false
        $nestedGroup.RemediationBlockedReason | Should -Match 'truncated'
        @($rows | Where-Object { $_.Member.SamAccountName -eq 'nested.user' }).Count | Should -Be 0
    }

    It 'falls back to member-attribute enumeration instead of dropping the group' {
        $rows = Resolve-ADGroupMembershipChain -GroupIdentity 'Legacy Operators' -MaxDepth 4 -WarningAction SilentlyContinue

        @($rows).Count | Should -Be 2
        $resolved = $rows | Where-Object { $_.Member.SamAccountName -eq 'orphaned.user' } | Select-Object -First 1
        $resolved.MembershipEnumerationMode | Should -Be 'MemberAttributeFallback'
        $resolved.Member.SID.Value | Should -Be 'S-1-5-21-1-2-3-7001'

        $unresolved = $rows | Where-Object { $_.Member.DistinguishedName -like '*ForeignSecurityPrincipals*' } | Select-Object -First 1
        $unresolved | Should -Not -BeNullOrEmpty
        $unresolved.Member.objectClass | Should -Be 'unknown'
        $unresolved.MembershipEnumerationMode | Should -Be 'MemberAttributeFallback'
    }
}
