BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ModuleConfig.ps1')
    . (Join-Path $repoRoot 'src\Private\Protect-ADPostureFile.ps1')
    . (Join-Path $repoRoot 'src\Public\Get-ADSensitiveGroupCatalog.ps1')

}

Describe 'Sensitive group catalog exclusions' {
    It 'excludes Enterprise Domain Controllers by well-known SID' {
        $catalog = Get-ADSensitiveGroupCatalog -ConfigPath (Join-Path $repoRoot 'config\SensitiveGroups.json')

        ($catalog.ExcludedSids -contains 'S-1-5-9') | Should -Be $true
    }

    It 'excludes Enterprise Domain Controllers by friendly name fallback' {
        $catalog = Get-ADSensitiveGroupCatalog -ConfigPath (Join-Path $repoRoot 'config\SensitiveGroups.json')

        ($catalog.ExcludedAccounts -contains 'ENTERPRISE DOMAIN CONTROLLERS') | Should -Be $true
        ($catalog.ExcludedAccounts -contains 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS') | Should -Be $true
    }
}
