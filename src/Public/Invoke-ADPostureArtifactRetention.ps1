function Invoke-ADPostureArtifactRetention {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateRange(1, 3650)]
        [int] $RetentionDays = 180,

        [switch] $Remove,

        [string[]] $RootPath
    )

    $config = Get-ModuleConfig
    $roots = if ($RootPath) { @($RootPath) } else { @($config.DataPath, $config.ReportPath) }
    $allowedNames = @('snapshot-*.json', 'snapshot-*.json.sha256', 'audit-*', 'timeline-*.json', 'retention-*.json')
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $rootFull = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $root).Path).TrimEnd('\') + '\'
        foreach ($item in @(Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction Stop)) {
            $matchesPattern = @($allowedNames | Where-Object { $item.Name -like $_ }).Count -gt 0
            if (-not $matchesPattern -or $item.Name -like 'latest-*' -or $item.LastWriteTime -ge $cutoff) { continue }

            $candidate = [System.IO.Path]::GetFullPath($item.FullName)
            $withinRoot = $candidate.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
            $status = if (-not $withinRoot) { 'BlockedOutsideRoot' } elseif (-not $Remove) { 'DryRun' } else { 'Pending' }

            if ($Remove -and $withinRoot) {
                if ($PSCmdlet.ShouldProcess($candidate, 'Remove expired AD Posture artifact')) {
                    try {
                        Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop
                        $status = 'Removed'
                    }
                    catch {
                        $status = "Failed: $($_.Exception.Message)"
                    }
                }
                else { $status = 'WhatIf' }
            }

            $results.Add([pscustomobject]@{
                Path = $candidate; Root = $rootFull.TrimEnd('\'); LastWriteTime = $item.LastWriteTime
                AgeDays = [Math]::Floor(((Get-Date) - $item.LastWriteTime).TotalDays)
                RetentionDays = $RetentionDays; Status = $status
            })
        }
    }

    if ($Remove -and @($results | Where-Object Status -eq 'Removed').Count -gt 0) {
        if (-not (Test-Path -LiteralPath $config.ReportPath)) { New-Item -ItemType Directory -Path $config.ReportPath -Force | Out-Null }
        $logPath = Join-Path $config.ReportPath ("retention-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        @($results) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $logPath -Encoding UTF8
    }

    @($results)
}
