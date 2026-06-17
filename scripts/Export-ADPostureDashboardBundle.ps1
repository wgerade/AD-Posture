<#
.SYNOPSIS
    Packages the AD Posture module code (module, src, dashboard, config, scripts, docs) into a ZIP
    so it can be copied to a lab/management workstation without using Git.
.DESCRIPTION
    The bundle contains only code and static catalogs. Generated audit artifacts and any sensitive
    data are explicitly excluded: data\, reports\, generated dashboard bundles
    (dashboard-data.js / timeline-data.js / latest-dashboard.json / timeline-comparison.json),
    local ApprovedExceptions.json, logs, and key/cert material.

    Copy the resulting ZIP to the target machine, extract it, then:
        Import-Module .\ADPosture.psd1 -Force
        Invoke-ADPostureAudit
        Open-ADPostureDashboard -View Current

    In the browser, use Ctrl+Shift+R the first time to bypass cached CSS/JS.
.PARAMETER OutputPath
    Destination .zip path. Defaults to .\ADPosture-bundle-<timestamp>.zip in the repo root.
#>
[CmdletBinding()]
param(
    [string]$OutputPath
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
if (-not $OutputPath) {
    $OutputPath = Join-Path $repoRoot ("ADPosture-bundle-{0}.zip" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

$includeRoots = @('src', 'dashboard', 'config', 'scripts', 'docs', '.github')
$includeFiles = @('ADPosture.psd1', 'ADPosture.psm1', 'README.md', 'CHANGELOG.md', 'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md', 'PSScriptAnalyzerSettings.psd1')

# Sensitive or generated content that must never be bundled.
$excludePatterns = @(
    '\\data\\',
    '\\reports\\',
    '\\dashboard\\dashboard-data\.js$',
    '\\dashboard\\timeline-data\.js$',
    '\\dashboard\\latest-dashboard\.json$',
    '\\dashboard\\timeline-comparison\.json$',
    '\\config\\ApprovedExceptions\.json$',
    '\.(log|key|pfx|pem|cer|kdbx)$',
    '\\docs\\assets\\'
)

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("adposture-bundle-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

function Test-ShouldExclude {
    param([string]$FullPath)
    foreach ($pattern in $excludePatterns) {
        if ($FullPath -match $pattern) { return $true }
    }
    $false
}

try {
    $copied = 0
    foreach ($root in $includeRoots) {
        $sourceRoot = Join-Path $repoRoot $root
        if (-not (Test-Path -LiteralPath $sourceRoot)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File)) {
            if (Test-ShouldExclude -FullPath $item.FullName) { continue }
            $relative = $item.FullName.Substring($repoRoot.Path.Length).TrimStart('\')
            $destination = Join-Path $staging $relative
            $destinationDir = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $destinationDir)) {
                New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
            }
            Copy-Item -LiteralPath $item.FullName -Destination $destination -Force
            $copied++
        }
    }

    foreach ($file in $includeFiles) {
        $sourceFile = Join-Path $repoRoot $file
        if (Test-Path -LiteralPath $sourceFile) {
            Copy-Item -LiteralPath $sourceFile -Destination (Join-Path $staging $file) -Force
            $copied++
        }
    }

    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
    Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $OutputPath -Force

    Write-Host "Bundle created: $OutputPath" -ForegroundColor Green
    Write-Host "  Files packaged: $copied"
    Write-Host "  Excluded: generated data, reports, local exceptions, logs, key/cert material, doc image assets."
    Write-Host ""
    Write-Host "On the lab machine: extract, then Import-Module .\ADPosture.psd1 -Force; Invoke-ADPostureAudit; Open-ADPostureDashboard -View Current (Ctrl+Shift+R on first open)."
    return $OutputPath
}
finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}
