$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\Resolve-ADGroupMembershipChain.ps1')
. (Join-Path $repoRoot 'src\Private\Resolve-ADGroupMembershipChainSafe.ps1')

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
        default { @() }
    }
}

Describe 'Group membership chain resolution' {
    It 'preserves direct and indirect memberships without truncating normal paths' {
        $rows = Resolve-ADGroupMembershipChain -GroupIdentity 'Domain Admins' -MaxDepth 4

        @($rows | Where-Object { $_.Member.SamAccountName -eq 'adm.one' }).Count | Should Be 1
        $direct = $rows | Where-Object { $_.Member.SamAccountName -eq 'adm.one' } | Select-Object -First 1
        $indirect = $rows | Where-Object { $_.Member.SamAccountName -eq 'nested.user' } | Select-Object -First 1
        $direct.IsDirectMembership | Should Be $true
        $direct.DirectParentGroupName | Should Be 'Domain Admins'
        $direct.DirectParentGroupDn | Should Be 'CN=Domain Admins,DC=contoso,DC=local'
        $direct.CanGenerateRemediationScript | Should Be $true
        $indirect.NestingDepth | Should Be 1
        $indirect.DirectParentGroupName | Should Be 'Nested Admins'
        $indirect.DirectParentGroupDn | Should Be 'CN=Nested Admins,DC=contoso,DC=local'
        $indirect.CanGenerateRemediationScript | Should Be $true
        @($rows | Where-Object { $_.TruncatedNesting }).Count | Should Be 1
    }

    It 'marks group rows as truncated when MaxDepth prevents expansion' {
        $rows = Resolve-ADGroupMembershipChain -GroupIdentity 'Domain Admins' -MaxDepth 1
        $nestedGroup = $rows | Where-Object { $_.Member.DistinguishedName -eq 'CN=Nested Admins,DC=contoso,DC=local' } | Select-Object -First 1

        $nestedGroup.TruncatedNesting | Should Be $true
        $nestedGroup.CanGenerateRemediationScript | Should Be $false
        $nestedGroup.RemediationBlockedReason | Should Match 'truncated'
        @($rows | Where-Object { $_.Member.SamAccountName -eq 'nested.user' }).Count | Should Be 0
    }
}
