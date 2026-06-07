[CmdletBinding()]
param()

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$failed = $false

function Write-ReadinessResult {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Pass', 'Warn', 'Fail')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    switch ($Status) {
        'Pass' { Write-Host "[OK] $Message" -ForegroundColor Green }
        'Warn' { Write-Warning $Message }
        'Fail' {
            Write-Host "[FAIL] $Message" -ForegroundColor Red
            $script:failed = $true
        }
    }
}

function Test-RequiredPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $path = Join-Path $repoRoot $RelativePath
    if (Test-Path -LiteralPath $path) {
        Write-ReadinessResult -Status Pass -Message "Required path exists: $RelativePath"
    }
    else {
        Write-ReadinessResult -Status Fail -Message "Missing required path: $RelativePath"
    }
}

$requiredPaths = @(
    'README.md',
    'CHANGELOG.md',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'LICENSE',
    '.gitignore',
    '.gitattributes',
    '.editorconfig',
    '.github\workflows\ci.yml',
    '.github\pull_request_template.md',
    '.github\ISSUE_TEMPLATE\bug_report.md',
    '.github\ISSUE_TEMPLATE\feature_request.md',
    'docs\ARCHITECTURE.md',
    'docs\ROADMAP.md',
    'docs\assets\operations-dashboard.png',
    'docs\assets\objects-dashboard.png',
    'docs\assets\auth-dashboard.png',
    'docs\assets\acl-dashboard.png',
    'docs\assets\gpo-dashboard.png',
    'docs\assets\adcs-dashboard.png',
    'docs\assets\trust-dashboard.png',
    'docs\assets\dns-dashboard.png',
    'docs\assets\executive-dashboard.png',
    'docs\assets\exceptions-dashboard.png',
    'docs\assets\timeline-dashboard.png',
    'docs\assets\powershell-import.png',
    'docs\assets\powershell-focused-audit.png',
    'docs\assets\powershell-planned-full.png',
    'docs\assets\powershell-open-dashboard.png',
    'docs\assets\powershell-retention-dry-run.png',
    'docs\assets\demo.gif',
    'reports\.gitkeep',
    'data\.gitkeep'
)

foreach ($path in $requiredPaths) {
    Test-RequiredPath -RelativePath $path
}

$manifestPath = Join-Path $repoRoot 'ADPosture.psd1'
try {
    $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
    Write-ReadinessResult -Status Pass -Message "Module manifest is valid: $($manifest.Name) $($manifest.Version)"
}
catch {
    Write-ReadinessResult -Status Fail -Message "Module manifest is invalid: $($_.Exception.Message)"
}

$readmePath = Join-Path $repoRoot 'README.md'
if (Test-Path -LiteralPath $readmePath) {
    $readme = Get-Content -LiteralPath $readmePath -Raw
    $requiredReadmeTerms = @(
        'Risk Score',
        'Baseline Exceptions',
        'Dashboards',
        'Quality Checks',
        'Safety',
        'Roadmap'
    )

    foreach ($term in $requiredReadmeTerms) {
        if ($readme -match [regex]::Escape($term)) {
            Write-ReadinessResult -Status Pass -Message "README documents: $term"
        }
        else {
            Write-ReadinessResult -Status Fail -Message "README is missing section or term: $term"
        }
    }
}

$publicDocFiles = @(
    'README.md',
    'docs\ARCHITECTURE.md',
    'docs\CURRENT_STATE.md',
    'docs\GOVERNED-REMEDIATION.md',
    'docs\OPERATIONS-WALKTHROUGH.md',
    'docs\ROADMAP.md'
)

$publicDocForbiddenTerms = @(
    ('wsg' + '.local'),
    ('New-' + 'WSG' + 'LabData'),
    ('Test-' + 'WSG' + 'LabData'),
    ('CreateDangerous' + 'AclScenarios'),
    ('HRD / ' + 'Hardening')
)

foreach ($relativeDoc in $publicDocFiles) {
    $docPath = Join-Path $repoRoot $relativeDoc
    if (Test-Path -LiteralPath $docPath) {
        $content = Get-Content -LiteralPath $docPath -Raw
        foreach ($term in $publicDocForbiddenTerms) {
            if ($content -match [regex]::Escape($term)) {
                Write-ReadinessResult -Status Fail -Message "Public documentation contains forbidden release term '$term' in $relativeDoc"
            }
        }
    }
}

$gitIgnorePath = Join-Path $repoRoot '.gitignore'
if (Test-Path -LiteralPath $gitIgnorePath) {
    $gitIgnore = Get-Content -LiteralPath $gitIgnorePath -Raw
    $requiredIgnorePatterns = @(
        'reports/*',
        'data/*',
        'dashboard/dashboard-data.js',
        'dashboard/latest-dashboard.json',
        'config/ApprovedExceptions.json',
        '*.key',
        '*.pfx',
        '*.kdbx'
    )

    foreach ($pattern in $requiredIgnorePatterns) {
        if ($gitIgnore -match [regex]::Escape($pattern)) {
            Write-ReadinessResult -Status Pass -Message ".gitignore protects: $pattern"
        }
        else {
            Write-ReadinessResult -Status Fail -Message ".gitignore is missing sensitive pattern: $pattern"
        }
    }
}

$gitCommand = Get-Command git -ErrorAction SilentlyContinue
if ($gitCommand) {
    $trackedFiles = & $gitCommand.Source -C $repoRoot ls-files 2>$null
    if ($LASTEXITCODE -eq 0) {
        $sensitiveTrackedPatterns = @(
            '^reports/(?!\.gitkeep$)',
            '^data/(?!\.gitkeep$)',
            '^dashboard/(dashboard-data\.js|latest-dashboard\.json|timeline-data\.js|timeline-comparison\.json)$',
            '^config/ApprovedExceptions\.json$',
            '\.(key|pfx|pem|kdbx)$'
        )

        foreach ($pattern in $sensitiveTrackedPatterns) {
            $trackedMatches = $trackedFiles | Where-Object { $_ -match $pattern }
            if ($trackedMatches) {
                Write-ReadinessResult -Status Fail -Message "Sensitive files are tracked by Git: $($trackedMatches -join ', ')"
            }
        }

        Write-ReadinessResult -Status Pass -Message 'Git tracked-file sensitive artifact check completed.'
    }
    else {
        Write-ReadinessResult -Status Warn -Message 'Git is available, but this directory is not a readable Git worktree.'
    }
}
else {
    Write-ReadinessResult -Status Warn -Message 'Git was not found; skipping tracked-file sensitive artifact check.'
}

if ($failed) {
    throw 'GitHub readiness checks failed.'
}
