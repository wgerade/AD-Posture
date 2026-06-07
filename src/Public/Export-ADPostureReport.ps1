function ConvertTo-ADPostureAclEffectiveTrusteeExportRows {
    [CmdletBinding()]
    param(
        [object[]]$AclFindings = @()
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($finding in @($AclFindings)) {
        $effectiveTrustees = @()
        foreach ($propertyName in @('EffectiveTrustees', 'EffectiveMembers')) {
            if ($finding.PSObject.Properties[$propertyName] -and $finding.$propertyName) {
                $effectiveTrustees += @($finding.$propertyName)
            }
        }

        foreach ($effective in @($effectiveTrustees)) {
            if (-not $effective) { continue }
            $rows.Add([pscustomobject]@{
                AclFindingId = $finding.AclFindingId
                Domain = $finding.Domain
                NormalizedRight = $finding.NormalizedRight
                Severity = $finding.Severity
                RiskScore = $finding.RiskScore
                TrusteeName = $finding.TrusteeName
                TrusteeSid = $finding.TrusteeSid
                TrusteeDistinguishedName = $finding.TrusteeDistinguishedName
                TargetName = $finding.TargetName
                TargetDistinguishedName = $finding.TargetDistinguishedName
                TargetObjectSid = $finding.TargetObjectSid
                TargetObjectClass = $finding.TargetObjectClass
                EffectiveTrusteeName = if ($effective.Name) { [string]$effective.Name } elseif ($effective.SamAccountName) { [string]$effective.SamAccountName } else { $null }
                EffectiveTrusteeSid = if ($effective.Sid) { [string]$effective.Sid } elseif ($effective.ObjectSid) { [string]$effective.ObjectSid } else { $null }
                EffectiveTrusteeDistinguishedName = if ($effective.DistinguishedName) { [string]$effective.DistinguishedName } else { $null }
                EffectiveTrusteeObjectClass = if ($effective.ObjectClass) { [string]$effective.ObjectClass } elseif ($effective.AccountType) { [string]$effective.AccountType } else { $null }
                EffectiveTrusteeNestingDepth = if ($null -ne $effective.NestingDepth) { [int]$effective.NestingDepth } else { $null }
                EffectiveTrusteePath = if ($effective.Path) { [string]$effective.Path } else { $null }
                Reason = $finding.Reason
                Remediation = $finding.Remediation
            })
        }
    }

    @($rows)
}

function Export-ADPostureReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Snapshot,
        [Parameter(Mandatory)]
        [string]$OutputBasePath,
        [switch]$RedactSensitiveAclEvidence
    )
    Write-Warning "Generated AD Posture reports contain sensitive topology, DNs, SIDs, account metadata, and remediation context. Store them in a restricted location and do not commit them."
    [void](Update-ADPostureSnapshotV12 -Snapshot $Snapshot)

    $progressId = 7401
    $started = Get-Date
    $steps = [System.Collections.Generic.List[object]]::new()
    $steps.Add([pscustomobject]@{ Name = 'membership findings CSV'; Path = "$OutputBasePath-findings.csv"; Data = @($Snapshot.Findings); Kind = 'Csv' })
    $steps.Add([pscustomobject]@{ Name = 'group summaries CSV'; Path = "$OutputBasePath-groups.csv"; Data = @($Snapshot.GroupSummaries); Kind = 'Csv' })
    foreach ($entry in @(
        @{ Property = 'GpoFindings'; Suffix = 'gpo-findings'; Name = 'GPO findings CSV' },
        @{ Property = 'AclFindings'; Suffix = 'acl-findings'; Name = 'ACL findings CSV' },
        @{ Property = 'AdcsFindings'; Suffix = 'adcs-findings'; Name = 'ADCS findings CSV' },
        @{ Property = 'AdcsCas'; Suffix = 'adcs-cas'; Name = 'ADCS CAs CSV' },
        @{ Property = 'KerberosAuthFindings'; Suffix = 'kerberos-auth-findings'; Name = 'Kerberos/Auth findings CSV' },
        @{ Property = 'KerberosAuthPrincipals'; Suffix = 'kerberos-auth-principals'; Name = 'Kerberos/Auth principals CSV' },
        @{ Property = 'TrustFindings'; Suffix = 'trust-findings'; Name = 'Trust findings CSV' },
        @{ Property = 'Trusts'; Suffix = 'trusts'; Name = 'Trust inventory CSV' },
        @{ Property = 'DnsFindings'; Suffix = 'dns-findings'; Name = 'DNS findings CSV' },
        @{ Property = 'DnsZones'; Suffix = 'dns-zones'; Name = 'DNS zones CSV' },
        @{ Property = 'DnsRecords'; Suffix = 'dns-records'; Name = 'DNS records CSV' },
        @{ Property = 'IdentityRiskFindings'; Suffix = 'identity-risk-findings'; Name = 'Identity risk findings CSV' }
    )) {
        $propertyName = [string]$entry.Property
        if ($Snapshot.PSObject.Properties[$propertyName]) {
            $steps.Add([pscustomobject]@{ Name = $entry.Name; Path = "$OutputBasePath-$($entry.Suffix).csv"; Data = @($Snapshot.PSObject.Properties[$propertyName].Value); Kind = 'Csv' })
        }
    }
    if ($Snapshot.PSObject.Properties['AclFindings']) {
        $steps.Add([pscustomobject]@{ Name = 'ACL effective trustees CSV'; Path = "$OutputBasePath-acl-effective-trustees.csv"; Data = @($Snapshot.AclFindings); Kind = 'AclEffectiveTrusteesCsv' })
    }
    $steps.Add([pscustomobject]@{ Name = 'dashboard payload build'; Path = $null; Data = $null; Kind = 'DashboardBuild' })
    $steps.Add([pscustomobject]@{ Name = 'dashboard JSON export'; Path = "$OutputBasePath-dashboard.json"; Data = $null; Kind = 'DashboardJson' })
    $steps.Add([pscustomobject]@{ Name = 'latest dashboard files'; Path = $null; Data = $null; Kind = 'LatestDashboard' })
    $steps.Add([pscustomobject]@{ Name = 'full snapshot JSON export'; Path = "$OutputBasePath-full.json"; Data = $Snapshot; Kind = 'Json' })

    $total = [Math]::Max(1, $steps.Count)
    $dashboardData = $null
    $dashboardJson = $null
    for ($i = 0; $i -lt $steps.Count; $i++) {
        $step = $steps[$i]
        $percent = [int](($i / $total) * 100)
        $elapsed = [int]((Get-Date) - $started).TotalSeconds
        $eta = $null
        if ($i -gt 0) {
            $secondsPerStep = $elapsed / $i
            $remainingSteps = $total - $i
            $eta = [int]($secondsPerStep * $remainingSteps)
        }
        $etaText = if ($null -ne $eta) { " ETA ${eta}s." } else { ' ETA calculating.' }
        $status = "Step {0}/{1}: {2}. Elapsed {3}s.{4}" -f ($i + 1), $total, $step.Name, $elapsed, $etaText
        Write-Progress -Id $progressId -Activity 'Exporting AD Posture report' -Status $status -PercentComplete $percent
        Write-Host ("Report export [{0}/{1}] {2} ({3}% complete, elapsed {4}s{5})..." -f ($i + 1), $total, $step.Name, $percent, $elapsed, $(if ($null -ne $eta) { ", ETA ${eta}s" } else { '' }))

        switch ($step.Kind) {
            'Csv' {
                @($step.Data) | Export-Csv -Path $step.Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            }
            'AclEffectiveTrusteesCsv' {
                ConvertTo-ADPostureAclEffectiveTrusteeExportRows -AclFindings @($step.Data) |
                    Export-Csv -Path $step.Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            }
            'DashboardBuild' {
                $dashboardData = Get-ADPostureDashboardPayload -Snapshot $Snapshot -RedactSensitiveAclEvidence:$RedactSensitiveAclEvidence
            }
            'DashboardJson' {
                Write-Host '  Converting dashboard payload to JSON...'
                $dashboardJson = $dashboardData | ConvertTo-Json -Depth 12 -Compress
                Write-ADPostureAtomicTextFile -Path $step.Path -Value $dashboardJson
                Protect-ADPostureSensitiveFile -Path $step.Path
            }
            'LatestDashboard' {
                Write-ADPostureDashboardData -DashboardData $dashboardData -SerializedJson $dashboardJson
            }
            'Json' {
                Write-Host '  Converting full snapshot to JSON...'
                $step.Data | ConvertTo-Json -Depth 12 | Set-Content -Path $step.Path -Encoding UTF8 -ErrorAction Stop
            }
        }
    }

    Write-Progress -Id $progressId -Activity 'Exporting AD Posture report' -Completed
    Update-ADPosturePrimarySnapshotArtifact -Snapshot $Snapshot

    if (-not $script:ADPostureSkipTimelineRefresh) {
        try {
            $cfg = Get-ModuleConfig
            if (@(Get-ChildItem -LiteralPath $cfg.DataPath -Filter 'snapshot-*.json' -ErrorAction SilentlyContinue).Count -ge 2) {
                Compare-ADPostureSnapshots -UseLatestTwo -DataDirectory $cfg.DataPath | Out-Null
            }
        }
        catch {
            Write-Warning "Audit completed, but the automatic timeline refresh failed: $($_.Exception.Message)"
        }
    }

    Write-Host ("Report export complete in {0}s." -f ([int]((Get-Date) - $started).TotalSeconds)) -ForegroundColor Green
}
