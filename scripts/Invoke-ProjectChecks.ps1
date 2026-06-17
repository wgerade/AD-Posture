[CmdletBinding()]
param(
    [switch]$SkipAnalyzer,
    [switch]$SkipTests,
    [switch]$SkipReadiness
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$failed = $false

if (-not $SkipAnalyzer) {
    $fallbackModuleRoots = @(
        (Join-Path $HOME 'Documents\WindowsPowerShell\Modules'),
        (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($moduleRoot in $fallbackModuleRoots) {
        if (($env:PSModulePath -split ';') -notcontains $moduleRoot) {
            $env:PSModulePath = "$moduleRoot;$env:PSModulePath"
        }
    }

    $analyzer = Get-Module -ListAvailable -Name PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1
    if ($analyzer) {
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        $settingsPath = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
        $results = Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -Settings $settingsPath
        if ($results) {
            $results | Format-Table -AutoSize
            if ($results | Where-Object { $_.Severity -eq 'Error' }) {
                $failed = $true
            }
            else {
                Write-Warning 'PSScriptAnalyzer returned warnings. Review them before release; warnings do not fail local project checks.'
            }
        }
        else {
            Write-Host 'PSScriptAnalyzer: OK' -ForegroundColor Green
        }
    }
    else {
        Write-Warning 'PSScriptAnalyzer is not installed. Install-Module PSScriptAnalyzer -Scope CurrentUser'
    }
}

if (-not $SkipTests) {
    $availablePester = @(Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending)
    $pester = @($availablePester | Where-Object { $_.Version.Major -ge 5 } | Select-Object -First 1)
    if (-not $pester) {
        Write-Warning 'Pester 5+ is required (the test suite uses Pester 5 discovery semantics). Install-Module Pester -Scope CurrentUser'
        $failed = $true
    }
    else {
        Import-Module Pester -RequiredVersion $pester.Version -ErrorAction Stop
        $testsPath = Join-Path $repoRoot 'tests'
        $config = New-PesterConfiguration
        $config.Run.Path = $testsPath
        $config.Run.PassThru = $true
        $config.Output.Verbosity = 'Detailed'
        $result = Invoke-Pester -Configuration $config
        if ($result.FailedCount -gt 0) {
            $failed = $true
        }
    }
}

if (-not $SkipReadiness) {
    $readinessScript = Join-Path $PSScriptRoot 'Test-GitHubReadiness.ps1'
    if (Test-Path -LiteralPath $readinessScript) {
        try {
            & $readinessScript
        }
        catch {
            Write-Error $_
            $failed = $true
        }
    }
    else {
        Write-Warning 'GitHub readiness script was not found.'
        $failed = $true
    }
}

if ($failed) {
    throw 'Project checks failed.'
}
