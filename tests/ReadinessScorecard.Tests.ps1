$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\Get-ADPostureReadinessScorecard.ps1')

Describe 'Readiness scorecard' {
    It 'creates readiness controls from active findings' {
        $findings = @(
            [pscustomobject]@{
                IsExcluded = $false
                PrivilegeTier = 'Tier 0'
                RemediationDifficulty = 'High'
                RiskScore = 6
                IsStale = $true
                IsDisabled = $false
                UacPrivilegedConcernCount = 1
                NestingDepth = 1
                IsDirect = $false
            },
            [pscustomobject]@{
                IsExcluded = $true
                PrivilegeTier = 'Tier 0'
                RemediationDifficulty = 'High'
                RiskScore = 6
                IsStale = $true
                IsDisabled = $false
                UacPrivilegedConcernCount = 1
                NestingDepth = 1
                IsDirect = $false
            }
        )

        $authFindings = @(
            [pscustomobject]@{
                IsExcluded = $false
                FindingType = 'KerberosRoastableServiceAccount'
                Tags = @('KerberosAuth', 'Kerberoast', 'WeakEncryption')
                DelegationType = ''
            },
            [pscustomobject]@{
                IsExcluded = $false
                FindingType = 'KerberosSensitiveAccountDelegable'
                Tags = @('KerberosAuth', 'Delegation')
                DelegationType = 'Constrained'
            }
        )

        $trustFindings = @(
            [pscustomobject]@{
                IsExcluded = $false
                FindingType = 'TrustSidFilteringDisabled'
                Tags = @('TrustPosture', 'TrustBoundary', 'Tier0Exposure')
                IsTransitive = $false
                ForestTransitive = $false
            },
            [pscustomobject]@{
                IsExcluded = $false
                FindingType = 'TrustExternalTransitive'
                Tags = @('TrustPosture', 'TransitiveTrust')
                IsTransitive = $true
                ForestTransitive = $false
            },
            [pscustomobject]@{
                IsExcluded = $false
                FindingType = 'TrustStaleOrUnvalidated'
                Tags = @('TrustPosture', 'StaleTrust')
                IsTransitive = $false
                ForestTransitive = $false
            }
        )

        $dnsFindings = @(
            [pscustomobject]@{ IsExcluded = $false; FindingType = 'DnsZoneInsecureDynamicUpdate'; Tags = @('DnsPosture', 'DynamicUpdate') },
            [pscustomobject]@{ IsExcluded = $false; FindingType = 'DnsWildcardRecord'; Tags = @('DnsPosture', 'Wildcard') }
        )

        $scorecard = Get-ADPostureReadinessScorecard -Findings $findings -KerberosAuthFindings $authFindings -TrustFindings $trustFindings -DnsFindings $dnsFindings -OverallRiskScore 6 -ExpiredExceptionCount 1

        $scorecard.Score | Should BeLessThan 100
        $scorecard.Level | Should Not BeNullOrEmpty
        @($scorecard.Controls).Count | Should Be 15
        ($scorecard.Controls | Where-Object Name -eq 'Tier 0 exposure').Count | Should Be 1
        ($scorecard.Controls | Where-Object Name -eq 'Roastable identities').Count | Should Be 1
        ($scorecard.Controls | Where-Object Name -eq 'Kerberos delegation exposure').Count | Should Be 1
        ($scorecard.Controls | Where-Object Name -eq 'Kerberos encryption hygiene').Count | Should Be 1
        ($scorecard.Controls | Where-Object Name -eq 'Privileged delegation protection').Count | Should Be 1
        ($scorecard.Controls | Where-Object { $_.Name -eq 'Trust boundary controls' }).Count | Should Be 1
        ($scorecard.Controls | Where-Object { $_.Name -eq 'Trust blast radius' }).Count | Should Be 1
        ($scorecard.Controls | Where-Object { $_.Name -eq 'Trust governance freshness' }).Count | Should Be 1
        ($scorecard.Controls | Where-Object { $_.Name -eq 'DNS control plane' }).Count | Should Be 1
        ($scorecard.Controls | Where-Object { $_.Name -eq 'DNS record hygiene' }).Count | Should Be 1
    }
}
