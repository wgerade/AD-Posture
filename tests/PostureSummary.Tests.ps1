$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\New-ADPosturePostureSummary.ps1')

Describe 'Posture summary' {
    It 'reports collection status and active risk by domain' {
        $summary = New-ADPosturePostureSummary `
            -SensitiveGroupFindings @(
                [pscustomobject]@{ RiskScore = 12; Severity = 'High'; IsExcluded = $false },
                [pscustomobject]@{ RiskScore = 5; Severity = 'Medium'; IsExcluded = $true }
            ) `
            -DnsFindings @([pscustomobject]@{ RiskScore = 4; Severity = 'Medium'; IsExcluded = $false }) `
            -IncludeDnsPosture

        $sensitive = $summary | Where-Object PostureDomain -eq 'Sensitive Groups'
        $dns = $summary | Where-Object PostureDomain -eq 'DNS'
        $acl = $summary | Where-Object PostureDomain -eq 'ACL'

        $sensitive.CollectionStatus | Should Be 'Collected'
        $sensitive.FindingCount | Should Be 2
        $sensitive.ActiveFindingCount | Should Be 1
        $sensitive.CriticalHighCount | Should Be 1
        $sensitive.RiskScore | Should Be 12
        $dns.CollectionStatus | Should Be 'Collected'
        $dns.RiskScore | Should Be 4
        $acl.CollectionStatus | Should Be 'NotRequested'
        $acl.FindingCount | Should Be 0
    }
}
