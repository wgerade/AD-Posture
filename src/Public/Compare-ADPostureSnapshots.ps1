function Compare-ADPostureSnapshots {
    <#
    .SYNOPSIS
    Compares two snapshots and refreshes the static timeline with all valid history.
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

    $cfg = Get-ModuleConfig
    if (-not $DataDirectory) { $DataDirectory = $cfg.DataPath }

    if ($UseLatestTwo) {
        $files = Get-ChildItem -Path $DataDirectory -Filter 'snapshot-*.json' | Sort-Object LastWriteTime -Descending
        if ($files.Count -lt 2) {
            throw 'At least 2 snapshots in data/ are required for automatic comparison.'
        }
        $CurrentPath = $files[0].FullName
        $BaselinePath = $files[1].FullName
    }

    $baselineIntegrity = Test-ADPostureFileHashSidecar -Path $BaselinePath
    $currentIntegrity = Test-ADPostureFileHashSidecar -Path $CurrentPath
    $integrityWarnings = @()
    foreach ($integrity in @($baselineIntegrity, $currentIntegrity)) {
        if ($integrity.Status -eq 'Mismatch') {
            $message = "Snapshot integrity warning for '$($integrity.Path)': $($integrity.Message)"
            Write-Warning $message
            $integrityWarnings += $message
        }
    }

    $baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $current = Get-Content $CurrentPath -Raw | ConvertFrom-Json

    function Get-FindingKey($f) {
        "$($f.SensitiveGroup)|$($f.MemberSam)|$($f.MembershipChain)"
    }

    function Get-AclFindingKey($f) {
        @(
            $f.Domain
            $f.NormalizedRight
            $f.TrusteeSid
            $f.TrusteeDistinguishedName
            $f.TrusteeName
            $f.TargetObjectSid
            $f.TargetDistinguishedName
            $f.TargetName
            $f.ObjectType
            $f.InheritedObjectType
            [bool]$f.IsInherited
        ) -join '|'
    }

    function Copy-WithDriftState {
        param(
            [Parameter(Mandatory)]
            $InputObject,
            [Parameter(Mandatory)]
            [string]$DriftState
        )

        $copy = $InputObject.PSObject.Copy()
        $copy | Add-Member -MemberType NoteProperty -Name DriftState -Value $DriftState -Force
        $copy
    }

    $baseMap = @{}
    foreach ($f in $baseline.Findings) { $baseMap[(Get-FindingKey $f)] = $f }

    $currMap = @{}
    foreach ($f in $current.Findings) { $currMap[(Get-FindingKey $f)] = $f }

    $added = @()
    $removed = @()
    $changed = @()

    foreach ($k in $currMap.Keys) {
        if (-not $baseMap.ContainsKey($k)) {
            $added += $currMap[$k]
        }
        elseif ($baseMap[$k].RiskScore -ne $currMap[$k].RiskScore) {
            $changed += [PSCustomObject]@{
                Key = $k
                Before = $baseMap[$k].RiskScore
                After = $currMap[$k].RiskScore
                Finding = $currMap[$k]
            }
        }
    }

    foreach ($k in $baseMap.Keys) {
        if (-not $currMap.ContainsKey($k)) { $removed += $baseMap[$k] }
    }

    $baseAclMap = @{}
    foreach ($f in @($baseline.AclFindings)) { $baseAclMap[(Get-AclFindingKey $f)] = $f }

    $currAclMap = @{}
    foreach ($f in @($current.AclFindings)) { $currAclMap[(Get-AclFindingKey $f)] = $f }

    $aclAdded = @()
    $aclRemoved = @()
    $aclChanged = @()
    $aclUnchanged = @()
    $aclCurrentWithDrift = @()

    foreach ($k in $currAclMap.Keys) {
        if (-not $baseAclMap.ContainsKey($k)) {
            $marked = Copy-WithDriftState -InputObject $currAclMap[$k] -DriftState 'New'
            $aclAdded += $marked
            $aclCurrentWithDrift += $marked
        }
        elseif ($baseAclMap[$k].RiskScore -ne $currAclMap[$k].RiskScore -or $baseAclMap[$k].Severity -ne $currAclMap[$k].Severity) {
            $marked = Copy-WithDriftState -InputObject $currAclMap[$k] -DriftState 'Changed'
            $aclChanged += [PSCustomObject]@{
                Key = $k
                Before = $baseAclMap[$k].RiskScore
                After = $currAclMap[$k].RiskScore
                BeforeSeverity = $baseAclMap[$k].Severity
                AfterSeverity = $currAclMap[$k].Severity
                Finding = $marked
            }
            $aclCurrentWithDrift += $marked
        }
        else {
            $marked = Copy-WithDriftState -InputObject $currAclMap[$k] -DriftState 'Unchanged'
            $aclUnchanged += $marked
            $aclCurrentWithDrift += $marked
        }
    }

    foreach ($k in $baseAclMap.Keys) {
        if (-not $currAclMap.ContainsKey($k)) {
            $aclRemoved += (Copy-WithDriftState -InputObject $baseAclMap[$k] -DriftState 'Missing')
        }
    }

    $aclNewCriticalHigh = @($aclAdded | Where-Object { $_.Severity -in @('Critical', 'High') })

    $timeline = [PSCustomObject]@{
        BaselineTimestamp = $baseline.Timestamp
        CurrentTimestamp  = $current.Timestamp
        ScoreBefore       = $baseline.OverallRiskScore
        ScoreAfter        = $current.OverallRiskScore
        ScoreDelta        = [Math]::Round($current.OverallRiskScore - $baseline.OverallRiskScore, 2)
        AddedCount        = $added.Count
        RemovedCount      = $removed.Count
        ChangedCount      = $changed.Count
        AclAddedCount     = $aclAdded.Count
        AclRemovedCount   = $aclRemoved.Count
        AclChangedCount   = $aclChanged.Count
        AclUnchangedCount = $aclUnchanged.Count
        AclNewCriticalHighCount = $aclNewCriticalHigh.Count
        Added             = $added
        Removed           = $removed
        Changed           = $changed
        AclAdded          = $aclAdded
        AclRemoved        = $aclRemoved
        AclChanged        = $aclChanged
        AclUnchanged      = $aclUnchanged
        AclCurrent        = $aclCurrentWithDrift
        IntegrityStatus   = if ($integrityWarnings.Count -gt 0) { 'Warning' } elseif ($baselineIntegrity.Status -eq 'Valid' -and $currentIntegrity.Status -eq 'Valid') { 'Valid' } else { 'NotAvailable' }
        IntegrityWarnings = @($integrityWarnings)
        Integrity         = [pscustomobject]@{
            Baseline = $baselineIntegrity
            Current  = $currentIntegrity
        }
        History           = @(
            @{ timestamp = $baseline.Timestamp; score = $baseline.OverallRiskScore; actionable = $baseline.ActionableCount; aclFindings = @($baseline.AclFindings).Count }
            @{ timestamp = $current.Timestamp; score = $current.OverallRiskScore; actionable = $current.ActionableCount; aclFindings = @($current.AclFindings).Count; aclNewCriticalHigh = $aclNewCriticalHigh.Count }
        )
    }

    $fullHistory = @(Get-ADPostureTimelineHistoryPoints -DataDirectory $DataDirectory)
    if ($fullHistory.Count -gt 0) {
        $timeline | Add-Member -NotePropertyName History -NotePropertyValue $fullHistory -Force
    }

    $timeline | Add-Member -NotePropertyName Domain -NotePropertyValue $current.Domain -Force
    $timeline | Add-Member -NotePropertyName Forest -NotePropertyValue $current.Forest -Force
    $timeline | Add-Member -NotePropertyName TargetScore -NotePropertyValue $current.TargetScore -Force
    $timeline | Add-Member -NotePropertyName SchemaVersion -NotePropertyValue $current.SchemaVersion -Force
    $timeline | Add-Member -NotePropertyName BaselineAuditId -NotePropertyValue $baseline.AuditId -Force
    $timeline | Add-Member -NotePropertyName CurrentAuditId -NotePropertyValue $current.AuditId -Force

    Write-ADPostureTimelineDashboardData -TimelineData $timeline

    return $timeline
}
