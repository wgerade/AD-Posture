BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ModuleConfig.ps1')
    . (Join-Path $repoRoot 'src\Private\Protect-ADPostureFile.ps1')
    . (Join-Path $repoRoot 'src\Private\Get-TieringModel.ps1')

}

Describe 'Automatic privilege tiering' {
    It 'classifies domain administrators as Tier 0' {
        $result = Resolve-ADPostureTier -GroupName 'Domain Admins' -AccountType 'User'

        $result.Tier | Should -Be 'Tier 0'
        $result.Reason | Should -Be 'Domain Admins'
    }

    It 'classifies server operators as Tier 1' {
        $result = Resolve-ADPostureTier -GroupName 'Server Operators' -AccountType 'User'

        $result.Tier | Should -Be 'Tier 1'
    }

    It 'classifies workstation/user access groups as Tier 2' {
        $result = Resolve-ADPostureTier -GroupName 'Remote Desktop Users' -AccountType 'User'

        $result.Tier | Should -Be 'Tier 2'
    }

    It 'always classifies domain controller accounts as Tier 0' {
        $result = Resolve-ADPostureTier -GroupName 'Any Group' -AccountType 'Computer' -IsDomainController:$true

        $result.Tier | Should -Be 'Tier 0'
        $result.Reason | Should -Be 'Domain controller account'
    }

    It 'classifies gMSA accounts as Tier 1 service accounts by type' {
        $result = Resolve-ADPostureTier -GroupName 'Custom Sensitive Group' -AccountType 'ServiceAccount (gMSA)'

        $result.Tier | Should -Be 'Tier 1'
        $result.Reason | Should -Be 'Account type: ServiceAccount'
    }
}
