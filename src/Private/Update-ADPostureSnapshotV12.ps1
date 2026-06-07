function Update-ADPostureSnapshotV12 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Snapshot
    )

    $orphanFindings = @($Snapshot.GroupSummaries | ForEach-Object {
        New-ADPostureOrphanedSensitiveGroupFinding -GroupSummary $_ -Domain $Snapshot.Domain
    } | Where-Object { $_ })
    if ($orphanFindings.Count) {
        $orphanFindings = @(Add-ADPostureApprovedFindingExceptions -Findings $orphanFindings)
        $Snapshot.Findings = @($Snapshot.Findings) + $orphanFindings
    }

    foreach ($finding in @($Snapshot.Findings)) {
        $metadata = $null
        if ($script:ADPostureMembershipRemediationMap) {
            $key = Get-ADPostureMembershipRemediationMetadataKey `
                -SensitiveGroup $finding.SensitiveGroup `
                -MemberDn $finding.MemberDn `
                -MembershipChain $finding.MembershipChain
            $metadata = $script:ADPostureMembershipRemediationMap[$key]
        }

        $directParentName = if ($metadata) { $metadata.DirectParentGroupName } elseif ($finding.IsDirect) { $finding.SensitiveGroup } else { $null }
        $directParentDn = if ($metadata) { $metadata.DirectParentGroupDn } else { $null }
        $blockedReason = if ($metadata) {
            $metadata.RemediationBlockedReason
        }
        elseif ($finding.TruncatedNesting) {
            'Membership chain is truncated, cyclic, or incomplete.'
        }
        elseif (-not $finding.IsDirect) {
            'Direct parent group is unavailable in this older snapshot membership path.'
        }
        else {
            $null
        }

        $canGenerate = if ($metadata) {
            [bool]$metadata.CanGenerateRemediationScript
        }
        else {
            [bool]$finding.IsDirect -and -not [bool]$finding.TruncatedNesting
        }

        $finding | Add-Member -NotePropertyName DirectParentGroupName -NotePropertyValue $directParentName -Force
        $finding | Add-Member -NotePropertyName DirectParentGroupDn -NotePropertyValue $directParentDn -Force
        $finding | Add-Member -NotePropertyName CanGenerateRemediationScript -NotePropertyValue $canGenerate -Force
        $finding | Add-Member -NotePropertyName RemediationBlockedReason -NotePropertyValue $blockedReason -Force
    }

    $findingProperties = @(
        'Findings', 'AclFindings', 'GpoFindings', 'AdcsFindings', 'KerberosAuthFindings',
        'TrustFindings', 'DnsFindings', 'IdentityRiskFindings'
    )
    $allFindings = @($findingProperties | ForEach-Object { @($Snapshot.$_) } | Where-Object { $null -ne $_ })
    $catalog = Get-ADPostureFrameworkCrosswalkCatalog
    $playbooks = @()
    foreach ($finding in $allFindings) {
        if ([string]::IsNullOrWhiteSpace([string]$finding.FindingId)) {
            $finding | Add-Member -NotePropertyName FindingId -NotePropertyValue ([guid]::NewGuid().ToString('N')) -Force
        }
        $finding | Add-Member -NotePropertyName PostureDomain -NotePropertyValue (Get-ADPostureFindingDomain -Finding $finding) -Force
        $finding | Add-Member -NotePropertyName FrameworkMappings -NotePropertyValue @(Get-ADPostureFrameworkMappings -Finding $finding -Catalog $catalog) -Force
        $playbook = New-ADPostureRemediationPlaybook -Finding $finding
        $finding | Add-Member -NotePropertyName PlaybookId -NotePropertyValue $playbook.PlaybookId -Force
        $playbooks += $playbook
    }

    $activeFindings = @($allFindings | Where-Object { -not $_.IsExcluded -and [double]$_.RiskScore -gt 0 })
    $overall = if ($activeFindings.Count) { [Math]::Round(($activeFindings | Measure-Object RiskScore -Sum).Sum, 2) } else { 0.0 }
    $approved = @($allFindings | Where-Object { $_.IsApprovedException -and $_.ApprovedExceptionStatus -eq 'Active' })
    $expired = @($allFindings | Where-Object { $_.IsApprovedException -and $_.ApprovedExceptionStatus -eq 'Expired' })
    $Snapshot | Add-Member -NotePropertyName OverallRiskScore -NotePropertyValue $overall -Force
    $Snapshot | Add-Member -NotePropertyName FindingsCount -NotePropertyValue @($Snapshot.Findings).Count -Force
    $Snapshot | Add-Member -NotePropertyName ActionableCount -NotePropertyValue $activeFindings.Count -Force
    $Snapshot | Add-Member -NotePropertyName ApprovedExceptionCount -NotePropertyValue $approved.Count -Force
    $Snapshot | Add-Member -NotePropertyName ExpiredExceptionCount -NotePropertyValue $expired.Count -Force

    foreach ($orphan in $orphanFindings) {
        $objectId = "orphan-object-$($orphan.FindingId)"
        $evidenceId = "orphan-evidence-$($orphan.FindingId)"
        $Snapshot.Objects = @($Snapshot.Objects) + [pscustomobject]@{
            ObjectId = $objectId; ObjectType = 'Group'; DisplayName = $orphan.SensitiveGroup
            SamAccountName = $orphan.SensitiveGroup; DistinguishedName = $orphan.MemberDn
            Domain = $orphan.Domain; RiskScore = $orphan.RiskScore; Severity = $orphan.Severity
            PrivilegeTier = $orphan.PrivilegeTier; EvidenceIds = @($evidenceId)
            IsApprovedException = [bool]$orphan.IsApprovedException
        }
        $Snapshot.ObjectEvidence = @($Snapshot.ObjectEvidence) + [pscustomobject]@{
            EvidenceId = $evidenceId; ObjectId = $objectId; EvidenceType = 'OrphanedSensitiveGroup'
            FindingId = $orphan.FindingId; Score = $orphan.RiskScore; Severity = $orphan.Severity
            Reason = $orphan.CleanupActions
        }
    }

    $requested = $script:ADPostureRequestedPosture
    $postureSummary = New-ADPosturePostureSummary `
        -SensitiveGroupFindings @($Snapshot.Findings) `
        -IdentityRiskFindings @($Snapshot.IdentityRiskFindings) `
        -AclFindings @($Snapshot.AclFindings) `
        -GpoFindings @($Snapshot.GpoFindings) `
        -AdcsFindings @($Snapshot.AdcsFindings) `
        -KerberosAuthFindings @($Snapshot.KerberosAuthFindings) `
        -TrustFindings @($Snapshot.TrustFindings) `
        -DnsFindings @($Snapshot.DnsFindings) `
        -IncludeAclPosture:([bool]$requested.Acl) `
        -IncludeGpoPosture:([bool]$requested.Gpo) `
        -IncludeAdcsPosture:([bool]$requested.Adcs) `
        -IncludeKerberosAuthPosture:([bool]$requested.Kerberos) `
        -IncludeTrustPosture:([bool]$requested.Trust) `
        -IncludeDnsPosture:([bool]$requested.Dns)

    $Snapshot | Add-Member -NotePropertyName SchemaVersion -NotePropertyValue '1.3' -Force
    $Snapshot | Add-Member -NotePropertyName PostureSummary -NotePropertyValue @($postureSummary) -Force
    $Snapshot | Add-Member -NotePropertyName OrphanedSensitiveGroupFindings -NotePropertyValue @($orphanFindings) -Force
    $Snapshot | Add-Member -NotePropertyName FrameworkCatalogVersion -NotePropertyValue ([string]$catalog.CatalogVersion) -Force
    $Snapshot | Add-Member -NotePropertyName FrameworkSummary -NotePropertyValue @(Get-ADPostureFrameworkSummary -Findings $allFindings) -Force
    $Snapshot | Add-Member -NotePropertyName RemediationPlaybooks -NotePropertyValue @($playbooks) -Force
    $Snapshot
}

function Update-ADPosturePrimarySnapshotArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Snapshot
    )

    $cfg = Get-ModuleConfig
    $candidate = Get-ChildItem -LiteralPath $cfg.DataPath -Filter 'snapshot-*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $candidate) { return }

    try {
        $existing = Get-Content -LiteralPath $candidate.FullName -Raw | ConvertFrom-Json
        if ($existing.AuditId -ne $Snapshot.AuditId) { return }
        Write-ADPostureAtomicTextFile -Path $candidate.FullName -Value ($Snapshot | ConvertTo-Json -Depth 12)
        Protect-ADPostureSensitiveFile -Path $candidate.FullName
        [void](Write-ADPostureFileHashSidecar -Path $candidate.FullName)
    }
    catch {
        Write-Warning "Could not update the schema 1.3 primary snapshot artifact: $($_.Exception.Message)"
    }
}
