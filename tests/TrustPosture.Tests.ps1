BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ADPostureTrustPosture.ps1')

}

Describe 'Trust posture risk model' {
    It 'reports SID filtering and selective-authentication gaps on inbound external trusts' {
        $trust = [pscustomobject]@{
            Name = 'legacy.corp'
            Target = 'legacy.corp'
            Direction = 'Inbound'
            TrustType = 'External'
            TrustAttributes = 0
            SelectiveAuthentication = $false
            SIDFilteringQuarantined = $false
            SIDFilteringForestAware = $false
            IntraForest = $false
            IsTransitive = $false
            WhenChanged = (Get-Date)
        }

        $model = ConvertTo-ADPostureTrustRiskModel -Domain 'corp.example' -Trusts @($trust)

        @($model.Trusts).Count | Should -Be 1
        @($model.TrustFindings | Where-Object FindingType -eq 'TrustSidFilteringDisabled').Count | Should -Be 1
        @($model.TrustFindings | Where-Object FindingType -eq 'TrustSelectiveAuthenticationDisabled').Count | Should -Be 1
        ($model.TrustFindings | Where-Object FindingType -eq 'TrustSidFilteringDisabled').Severity | Should -Be 'Critical'
    }

    It 'reports transitive, forest, and TGT delegation trust exposure' {
        $trust = [pscustomobject]@{
            Name = 'partner.forest'
            Target = 'partner.forest'
            Direction = 'Bidirectional'
            TrustType = 'Forest'
            TrustAttributes = 8
            SelectiveAuthentication = $true
            SIDFilteringForestAware = $true
            ForestTransitive = $true
            IntraForest = $false
            IsTransitive = $true
            TGTDelegation = $true
            WhenChanged = (Get-Date)
        }

        $model = ConvertTo-ADPostureTrustRiskModel -Domain 'corp.example' -Trusts @($trust)

        @($model.TrustFindings | Where-Object FindingType -eq 'TrustExternalTransitive').Count | Should -Be 1
        @($model.TrustFindings | Where-Object FindingType -eq 'TrustForestTransitiveExposure').Count | Should -Be 1
        @($model.TrustFindings | Where-Object FindingType -eq 'TrustTgtDelegationEnabled').Count | Should -Be 1
        ($model.TrustFindings | Where-Object FindingType -eq 'TrustTgtDelegationEnabled').Severity | Should -Be 'Critical'
    }

    It 'reports stale trust governance without active boundary gaps' {
        $trust = [pscustomobject]@{
            Name = 'vendor.example'
            Target = 'vendor.example'
            Direction = 'Outbound'
            TrustType = 'External'
            TrustAttributes = 4
            SelectiveAuthentication = $true
            SIDFilteringQuarantined = $true
            IntraForest = $false
            IsTransitive = $false
            WhenChanged = (Get-Date).AddDays(-500)
        }

        $model = ConvertTo-ADPostureTrustRiskModel -Domain 'corp.example' -Trusts @($trust) -StaleDays 365

        @($model.TrustFindings | Where-Object FindingType -eq 'TrustStaleOrUnvalidated').Count | Should -Be 1
        @($model.TrustFindings | Where-Object FindingType -eq 'TrustSidFilteringDisabled').Count | Should -Be 0
    }
}
