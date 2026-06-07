function Get-ADPostureReadinessScorecard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,
        [Parameter(Mandatory)]
        [double]$OverallRiskScore,
        [object[]]$KerberosAuthFindings = @(),
        [object[]]$TrustFindings = @(),
        [object[]]$DnsFindings = @(),
        [int]$ExpiredExceptionCount = 0
    )

    $active = @($Findings | Where-Object { -not $_.IsExcluded })
    $activeAuth = @($KerberosAuthFindings | Where-Object { -not $_.IsExcluded })
    $activeTrust = @($TrustFindings | Where-Object { -not $_.IsExcluded })
    $activeDns = @($DnsFindings | Where-Object { -not $_.IsExcluded })
    $tier0 = @($active | Where-Object { $_.PrivilegeTier -eq 'Tier 0' })
    $high = @($active | Where-Object { $_.RemediationDifficulty -eq 'High' -or $_.RiskScore -ge 5 })
    $stale = @($active | Where-Object { $_.IsStale -and -not $_.IsDisabled })
    $uac = @($active | Where-Object { $_.UacPrivilegedConcernCount -gt 0 })
    $nested = @($active | Where-Object { $_.NestingDepth -gt 0 -or $_.IsDirect -eq $false })
    $roastable = @($activeAuth | Where-Object { $_.FindingType -in @('KerberosAsRepRoastableAccount', 'KerberosRoastableServiceAccount') })
    $delegation = @($activeAuth | Where-Object { $_.Tags -contains 'Delegation' -or $_.DelegationType })
    $weakCrypto = @($activeAuth | Where-Object { $_.Tags -contains 'WeakEncryption' })
    $protectedGap = @($activeAuth | Where-Object { $_.FindingType -eq 'KerberosSensitiveAccountDelegable' })
    $trustBoundary = @($activeTrust | Where-Object { $_.FindingType -in @('TrustSidFilteringDisabled', 'TrustSelectiveAuthenticationDisabled', 'TrustTgtDelegationEnabled') })
    $trustBlastRadius = @($activeTrust | Where-Object { $_.Tags -contains 'BlastRadius' -or $_.Tags -contains 'TransitiveTrust' -or $_.ForestTransitive -or $_.IsTransitive })
    $staleTrust = @($activeTrust | Where-Object { $_.FindingType -eq 'TrustStaleOrUnvalidated' })
    $dnsControl = @($activeDns | Where-Object { $_.FindingType -in @('DnsZoneInsecureDynamicUpdate', 'DnsAclControlDelegation', 'DnsAdminsExposure') })
    $dnsHygiene = @($activeDns | Where-Object { $_.FindingType -in @('DnsWildcardRecord', 'DnsDanglingRecordCandidate', 'DnsStaleRecord', 'DnsZoneNoAgingScavenging') })
    $deductions = 0
    $deductions += [Math]::Min(35, [Math]::Floor($OverallRiskScore * 0.8))
    $deductions += [Math]::Min(20, $tier0.Count * 2)
    $deductions += [Math]::Min(15, $high.Count * 2)
    $deductions += [Math]::Min(10, $stale.Count)
    $deductions += [Math]::Min(10, $uac.Count)
    $deductions += [Math]::Min(10, $nested.Count)
    $deductions += [Math]::Min(15, $roastable.Count * 2)
    $deductions += [Math]::Min(15, $delegation.Count * 2)
    $deductions += [Math]::Min(10, $weakCrypto.Count)
    $deductions += [Math]::Min(10, $protectedGap.Count * 2)
    $deductions += [Math]::Min(15, $trustBoundary.Count * 3)
    $deductions += [Math]::Min(10, $trustBlastRadius.Count * 2)
    $deductions += [Math]::Min(8, $staleTrust.Count)
    $deductions += [Math]::Min(15, $dnsControl.Count * 3)
    $deductions += [Math]::Min(10, $dnsHygiene.Count)
    $deductions += [Math]::Min(10, $ExpiredExceptionCount * 2)

    $score = [Math]::Max(0, 100 - $deductions)
    $level = if ($score -ge 90) { 'Ready' } elseif ($score -ge 70) { 'Needs review' } elseif ($score -ge 50) { 'At risk' } else { 'Critical' }

    $controls = @(
        [PSCustomObject]@{
            Name = 'Tier 0 exposure'
            Status = if ($tier0.Count -eq 0) { 'Pass' } elseif ($tier0.Count -le 3) { 'Review' } else { 'Fail' }
            Count = $tier0.Count
            Target = 0
            Detail = 'No unapproved Tier 0 memberships in the actionable queue'
        },
        [PSCustomObject]@{
            Name = 'High priority findings'
            Status = if ($high.Count -eq 0) { 'Pass' } elseif ($high.Count -le 5) { 'Review' } else { 'Fail' }
            Count = $high.Count
            Target = 0
            Detail = 'No high difficulty or score >= 5 finding remains open'
        },
        [PSCustomObject]@{
            Name = 'Privileged UAC hygiene'
            Status = if ($uac.Count -eq 0) { 'Pass' } elseif ($uac.Count -le 5) { 'Review' } else { 'Fail' }
            Count = $uac.Count
            Target = 0
            Detail = 'Privileged accounts avoid risky UAC flags'
        },
        [PSCustomObject]@{
            Name = 'Stale privileged identities'
            Status = if ($stale.Count -eq 0) { 'Pass' } elseif ($stale.Count -le 5) { 'Review' } else { 'Fail' }
            Count = $stale.Count
            Target = 0
            Detail = 'No unused enabled account remains in sensitive groups'
        },
        [PSCustomObject]@{
            Name = 'Nested access paths'
            Status = if ($nested.Count -eq 0) { 'Pass' } elseif ($nested.Count -le 5) { 'Review' } else { 'Fail' }
            Count = $nested.Count
            Target = 0
            Detail = 'Sensitive access is direct and easy to review'
        },
        [PSCustomObject]@{
            Name = 'Expired approvals'
            Status = if ($ExpiredExceptionCount -eq 0) { 'Pass' } else { 'Fail' }
            Count = $ExpiredExceptionCount
            Target = 0
            Detail = 'Expired exceptions are revalidated or removed'
        },
        [PSCustomObject]@{
            Name = 'Roastable identities'
            Status = if ($roastable.Count -eq 0) { 'Pass' } elseif ($roastable.Count -le 3) { 'Review' } else { 'Fail' }
            Count = $roastable.Count
            Target = 0
            Detail = 'No AS-REP roastable or unnecessary SPN-bearing service identities remain open'
        },
        [PSCustomObject]@{
            Name = 'Kerberos delegation exposure'
            Status = if ($delegation.Count -eq 0) { 'Pass' } elseif ($delegation.Count -le 3) { 'Review' } else { 'Fail' }
            Count = $delegation.Count
            Target = 0
            Detail = 'Delegation paths are explicitly approved and least privilege'
        },
        [PSCustomObject]@{
            Name = 'Kerberos encryption hygiene'
            Status = if ($weakCrypto.Count -eq 0) { 'Pass' } elseif ($weakCrypto.Count -le 5) { 'Review' } else { 'Fail' }
            Count = $weakCrypto.Count
            Target = 0
            Detail = 'Service principals avoid DES/RC4-only or no-AES Kerberos posture'
        },
        [PSCustomObject]@{
            Name = 'Privileged delegation protection'
            Status = if ($protectedGap.Count -eq 0) { 'Pass' } elseif ($protectedGap.Count -le 3) { 'Review' } else { 'Fail' }
            Count = $protectedGap.Count
            Target = 0
            Detail = 'Privileged identities are protected from delegation where compatible'
        },
        [PSCustomObject]@{
            Name = 'Trust boundary controls'
            Status = if ($trustBoundary.Count -eq 0) { 'Pass' } elseif ($trustBoundary.Count -le 2) { 'Review' } else { 'Fail' }
            Count = $trustBoundary.Count
            Target = 0
            Detail = 'External and forest trusts enforce SID filtering, selective authentication, and no unnecessary TGT delegation'
        },
        [PSCustomObject]@{
            Name = 'Trust blast radius'
            Status = if ($trustBlastRadius.Count -eq 0) { 'Pass' } elseif ($trustBlastRadius.Count -le 3) { 'Review' } else { 'Fail' }
            Count = $trustBlastRadius.Count
            Target = 0
            Detail = 'Transitive and forest trust scope is minimized and explicitly owned'
        },
        [PSCustomObject]@{
            Name = 'Trust governance freshness'
            Status = if ($staleTrust.Count -eq 0) { 'Pass' } elseif ($staleTrust.Count -le 3) { 'Review' } else { 'Fail' }
            Count = $staleTrust.Count
            Target = 0
            Detail = 'Long-lived trusts have current owner, business justification, and review evidence'
        },
        [PSCustomObject]@{
            Name = 'DNS control plane'
            Status = if ($dnsControl.Count -eq 0) { 'Pass' } elseif ($dnsControl.Count -le 3) { 'Review' } else { 'Fail' }
            Count = $dnsControl.Count
            Target = 0
            Detail = 'DNS zones, DnsAdmins, and DNS object ACLs are least privilege and secure-update only'
        },
        [PSCustomObject]@{
            Name = 'DNS record hygiene'
            Status = if ($dnsHygiene.Count -eq 0) { 'Pass' } elseif ($dnsHygiene.Count -le 5) { 'Review' } else { 'Fail' }
            Count = $dnsHygiene.Count
            Target = 0
            Detail = 'Wildcard, stale, and dangling DNS records are reviewed or removed'
        }
    )

    [PSCustomObject]@{
        Score = [int]$score
        Level = $level
        Controls = $controls
    }
}
