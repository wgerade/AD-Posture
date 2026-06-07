function New-ADPosturePostureSummary {
    [CmdletBinding()]
    param(
        [object[]]$SensitiveGroupFindings = @(),
        [object[]]$IdentityRiskFindings = @(),
        [object[]]$AclFindings = @(),
        [object[]]$GpoFindings = @(),
        [object[]]$AdcsFindings = @(),
        [object[]]$KerberosAuthFindings = @(),
        [object[]]$TrustFindings = @(),
        [object[]]$DnsFindings = @(),
        [switch]$IncludeAclPosture,
        [switch]$IncludeGpoPosture,
        [switch]$IncludeAdcsPosture,
        [switch]$IncludeKerberosAuthPosture,
        [switch]$IncludeTrustPosture,
        [switch]$IncludeDnsPosture
    )

    function New-SummaryRow {
        param(
            [string]$PostureDomain,
            [object[]]$Findings,
            [bool]$Collected
        )

        $rows = @($Findings | Where-Object { $null -ne $_ })
        $active = @($rows | Where-Object { -not $_.IsExcluded -and [double]$_.RiskScore -gt 0 })
        $criticalHigh = @($active | Where-Object {
            $_.Severity -in @('Critical', 'High') -or [double]$_.RiskScore -ge 10
        })

        [pscustomobject]@{
            PostureDomain     = $PostureDomain
            CollectionStatus  = if ($Collected) { 'Collected' } else { 'NotRequested' }
            FindingCount      = $rows.Count
            ActiveFindingCount = $active.Count
            CriticalHighCount = $criticalHigh.Count
            RiskScore         = if ($active.Count) {
                [Math]::Round(($active | Measure-Object -Property RiskScore -Sum).Sum, 2)
            }
            else {
                0.0
            }
        }
    }

    @(
        New-SummaryRow -PostureDomain 'Sensitive Groups' -Findings @($SensitiveGroupFindings) -Collected $true
        New-SummaryRow -PostureDomain 'Identity Risk' -Findings @($IdentityRiskFindings) -Collected $true
        New-SummaryRow -PostureDomain 'ACL' -Findings @($AclFindings) -Collected ([bool]$IncludeAclPosture)
        New-SummaryRow -PostureDomain 'GPO' -Findings @($GpoFindings) -Collected ([bool]$IncludeGpoPosture)
        New-SummaryRow -PostureDomain 'ADCS' -Findings @($AdcsFindings) -Collected ([bool]$IncludeAdcsPosture)
        New-SummaryRow -PostureDomain 'Kerberos' -Findings @($KerberosAuthFindings) -Collected ([bool]$IncludeKerberosAuthPosture)
        New-SummaryRow -PostureDomain 'Trust' -Findings @($TrustFindings) -Collected ([bool]$IncludeTrustPosture)
        New-SummaryRow -PostureDomain 'DNS' -Findings @($DnsFindings) -Collected ([bool]$IncludeDnsPosture)
    )
}
