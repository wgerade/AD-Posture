$script:CompareADPostureSnapshotsV11 = ${function:Compare-ADPostureSnapshots}

function Compare-ADPostureSnapshots {
    <#
    .SYNOPSIS
    Compares snapshots and refreshes the static timeline with all valid history.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Files')]
        [string]$BaselinePath,
        [string]$CurrentPath,
        [Parameter(ParameterSetName = 'Auto')]
        [switch]$UseLatestTwo,
        [string]$DataDirectory
    )

    $timeline = & $script:CompareADPostureSnapshotsV11 @PSBoundParameters
    $cfg = Get-ModuleConfig
    $effectiveDataDirectory = if ($DataDirectory) { $DataDirectory } else { $cfg.DataPath }

    if ($UseLatestTwo) {
        $files = @(Get-ChildItem -Path $effectiveDataDirectory -Filter 'snapshot-*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
        if ($files.Count -ge 2) {
            $CurrentPath = $files[0].FullName
            $BaselinePath = $files[1].FullName
        }
    }

    $baseline = $null
    $current = $null
    try {
        if ($BaselinePath) { $baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json }
        if ($CurrentPath) { $current = Get-Content -LiteralPath $CurrentPath -Raw | ConvertFrom-Json }
    }
    catch {
        Write-Warning "Timeline metadata could not be enriched: $($_.Exception.Message)"
    }

    $history = @(Get-ADPostureTimelineHistoryPoints -DataDirectory $effectiveDataDirectory)
    if ($history.Count -gt 0) {
        $timeline | Add-Member -NotePropertyName History -NotePropertyValue $history -Force
    }

    $timeline | Add-Member -NotePropertyName Domain -NotePropertyValue $current.Domain -Force
    $timeline | Add-Member -NotePropertyName Forest -NotePropertyValue $current.Forest -Force
    $timeline | Add-Member -NotePropertyName TargetScore -NotePropertyValue $current.TargetScore -Force
    $timeline | Add-Member -NotePropertyName SchemaVersion -NotePropertyValue $current.SchemaVersion -Force
    $timeline | Add-Member -NotePropertyName BaselineAuditId -NotePropertyValue $baseline.AuditId -Force
    $timeline | Add-Member -NotePropertyName CurrentAuditId -NotePropertyValue $current.AuditId -Force

    Write-ADPostureTimelineDashboardData -TimelineData $timeline
    $timeline
}
