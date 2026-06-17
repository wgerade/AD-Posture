BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ModuleConfig.ps1')

}

Describe 'Module configuration output paths' {
    AfterEach {
        $env:ADPOSTURE_OUTPUT_ROOT = $null
    }

    It 'defaults generated artifact paths to the module folder' {
        $env:ADPOSTURE_OUTPUT_ROOT = $null
        $cfg = Get-ModuleConfig

        $cfg.DataPath | Should -Be ([System.IO.Path]::Combine($cfg.ModuleRoot, 'data'))
        $cfg.ReportPath | Should -Be ([System.IO.Path]::Combine($cfg.ModuleRoot, 'reports'))
        $cfg.DashboardPath | Should -Be ([System.IO.Path]::Combine($cfg.ModuleRoot, 'dashboard'))
        $cfg.DashboardSourcePath | Should -Be $cfg.DashboardPath
    }

    It 'honors ADPOSTURE_OUTPUT_ROOT for writable artifact locations' {
        $outputRoot = Join-Path $TestDrive 'adposture-output'
        $env:ADPOSTURE_OUTPUT_ROOT = $outputRoot
        $cfg = Get-ModuleConfig

        $cfg.DataPath | Should -Be ([System.IO.Path]::Combine($outputRoot, 'data'))
        $cfg.ReportPath | Should -Be ([System.IO.Path]::Combine($outputRoot, 'reports'))
        $cfg.DashboardPath | Should -Be ([System.IO.Path]::Combine($outputRoot, 'dashboard'))
        $cfg.ApprovedExceptionsPath | Should -Be ([System.IO.Path]::Combine($outputRoot, 'config', 'ApprovedExceptions.json'))
    }

    It 'keeps static catalogs in the module folder even with an output root override' {
        $env:ADPOSTURE_OUTPUT_ROOT = Join-Path $TestDrive 'adposture-output'
        $cfg = Get-ModuleConfig

        $cfg.ConfigPath | Should -Be ([System.IO.Path]::Combine($cfg.ModuleRoot, 'config', 'SensitiveGroups.json'))
        $cfg.TieringModelPath | Should -Be ([System.IO.Path]::Combine($cfg.ModuleRoot, 'config', 'TieringModel.json'))
        $cfg.DashboardSourcePath | Should -Be ([System.IO.Path]::Combine($cfg.ModuleRoot, 'dashboard'))
    }
}
