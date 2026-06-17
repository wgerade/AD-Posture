BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ModuleConfig.ps1')
    . (Join-Path $repoRoot 'src\Private\Protect-ADPostureFile.ps1')
    . (Join-Path $repoRoot 'src\Private\Get-UacFlagCatalog.ps1')

}

Describe 'User account control friendly labels' {
    It 'returns friendly comma-separated account control labels' {
        $uac = 0x0200 -bor 0x200000 -bor 0x100000

        $result = Get-UserAccountControlFriendly -Uac $uac

        $result.Summary | Should -Be 'Normal Account, Cannot Be Delegated (Hardening), Weak Kerberos (DES)'
        ($result.Notes -join ', ') | Should -Be 'Cannot Be Delegated (Hardening), Weak Kerberos (DES)'
        $result.UacRiskBonus | Should -Be 0.55
    }

    It 'hides duplicate disabled and password-never-expires labels from dashboard notes' {
        $uac = 0x0200 -bor 0x0002 -bor 0x10000

        $result = Get-UserAccountControlFriendly -Uac $uac -IsDisabled:$true -PasswordNeverExpires:$true

        $result.Summary | Should -Be 'Normal Account'
        $result.UacRiskBonus | Should -Be 0.65
    }
}
