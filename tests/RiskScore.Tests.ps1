BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Protect-ADPostureFile.ps1')
    . (Join-Path $repoRoot 'src\Private\Get-UacFlagCatalog.ps1')
    . (Join-Path $repoRoot 'src\Private\Get-MembershipRiskScore.ps1')

}

Describe 'Membership risk scoring' {
    It 'returns zero for excluded accounts' {
        $group = [pscustomobject]@{ RiskWeight = 5; ExcludeExpectedMembers = $false; DifficultyDefault = 'High' }
        $enrichment = [pscustomobject]@{
            AccountType = 'User'
            IsDisabled = $false
            IsStale = $false
            IsExcluded = $true
            IsDomainController = $false
            UacRiskBonus = 1.0
        }

        Get-MembershipRiskScore -GroupCatalogEntry $group -Enrichment $enrichment | Should -Be 0
    }

    It 'returns zero for well-known authority principals excluded by SID' {
        $group = [pscustomobject]@{ RiskWeight = 5; ExcludeExpectedMembers = $false; DifficultyDefault = 'High' }
        $enrichment = [pscustomobject]@{
            AccountType = 'Unknown'
            IsDisabled = $false
            IsStale = $false
            IsExcluded = $true
            IsDomainController = $false
            ObjectSid = 'S-1-5-9'
            UacRiskBonus = 0
        }

        Get-MembershipRiskScore -GroupCatalogEntry $group -Enrichment $enrichment | Should -Be 0
    }

    It 'adds nesting and UAC risk without capping the score' {
        $group = [pscustomobject]@{ RiskWeight = 4; ExcludeExpectedMembers = $false; DifficultyDefault = 'Medium' }
        $enrichment = [pscustomobject]@{
            AccountType = 'ServiceAccount'
            IsDisabled = $false
            IsStale = $false
            IsExcluded = $false
            IsDomainController = $false
            UacRiskBonus = 0.75
        }

        Get-MembershipRiskScore -GroupCatalogEntry $group -Enrichment $enrichment -NestingDepth 2 -IsDirect:$false | Should -Be 6.91
    }

    It 'explains score components and technical risk' {
        $group = [pscustomobject]@{ Name = 'Domain Admins'; RiskWeight = 5; ExcludeExpectedMembers = $false; DifficultyDefault = 'High' }
        $enrichment = [pscustomobject]@{
            AccountType = 'ServiceAccount'
            IsServiceAccount = $true
            IsComputer = $false
            IsDomainController = $false
            IsGroup = $false
            IsDisabled = $false
            IsStale = $false
            IsExcluded = $false
            UacRiskBonus = 1.5
            UacPrivilegedConcernCount = 1
            UacActiveFlagNames = 'TRUSTED_FOR_DELEGATION'
            UserAccountControlSummary = 'Normal Account, Unconstrained Delegation'
        }

        $assessment = Get-MembershipRiskAssessment -GroupCatalogEntry $group -Enrichment $enrichment -NestingDepth 1 -IsDirect:$false

        $assessment.Score | Should -BeGreaterThan 0
        @($assessment.Components).Count | Should -BeGreaterThan 3
        $assessment.Formula | Should -Match ' = '
        $assessment.TechnicalRisk | Should -Match 'service identity'
        (@($assessment.AttackTechniques).Id -contains 'T1558') | Should -Be $true
    }

    It 'scores gMSA accounts as service accounts' {
        $group = [pscustomobject]@{ RiskWeight = 4; ExcludeExpectedMembers = $false; DifficultyDefault = 'Medium' }
        $enrichment = [pscustomobject]@{
            AccountType = 'ServiceAccount (gMSA)'
            IsDisabled = $false
            IsStale = $false
            IsExcluded = $false
            IsDomainController = $false
            UacRiskBonus = 0
        }

        Get-MembershipRiskScore -GroupCatalogEntry $group -Enrichment $enrichment | Should -Be 4.6
    }

    It 'uses configured stale and password-age thresholds in cleanup recommendations' {
        $enrichment = [pscustomobject]@{
            IsExcluded = $false
            IsApprovedException = $false
            IsDisabled = $false
            IsStale = $true
            StaleDaysThreshold = 180
            IsPasswordStale = $true
            PasswordAgeDaysThreshold = 730
            IsServiceAccount = $false
            IsComputer = $false
            IsDomainController = $false
            IsUser = $true
            UacPrivilegedConcernCount = 0
        }

        $actions = Get-CleanupRecommendation -Enrichment $enrichment -GroupName 'Domain Admins' -RiskScore 3

        ($actions -join '; ') | Should -Match '180\+ days'
        ($actions -join '; ') | Should -Match '730\+ days'
    }
}
