function New-ADPostureTimelineHistory {
    [CmdletBinding()]
    param([string]$DataDirectory)

    $cfg = Get-ModuleConfig
    if (-not $DataDirectory) { $DataDirectory = $cfg.DataPath }

    $history = Get-ChildItem -Path $DataDirectory -Filter 'snapshot-*.json' |
        Sort-Object LastWriteTime |
        ForEach-Object {
            $integrity = Test-ADPostureFileHashSidecar -Path $_.FullName
            if ($integrity.Status -eq 'Mismatch') {
                Write-Warning "Snapshot integrity warning for '$($integrity.Path)': $($integrity.Message)"
            }
            $s = Get-Content $_.FullName -Raw | ConvertFrom-Json
            [PSCustomObject]@{
                Timestamp       = $s.Timestamp
                OverallRiskScore = $s.OverallRiskScore
                ActionableCount = $s.ActionableCount
                File            = $_.Name
                IntegrityStatus = $integrity.Status
            }
        }

    $out = Join-Path $cfg.ModuleRoot 'reports\timeline-history.json'
    Write-ADPostureAtomicTextFile -Path $out -Value (@{ points = @($history) } | ConvertTo-Json -Depth 4)
    Protect-ADPostureSensitiveFile -Path $out
    return $history
}
