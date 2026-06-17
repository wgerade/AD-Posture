BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ADPostureIdentityRiskPosture.ps1')
    . (Join-Path $repoRoot 'src\Private\Resolve-ADPostureApprovedException.ps1')
    . (Join-Path $repoRoot 'src\Private\ConvertTo-ADObjectRiskModel.ps1')

}

Describe 'Identity risk posture' {
    It 'reports privileged SIDHistory as object-risk evidence' {
        $model = ConvertTo-ADPostureIdentityRiskModel -Domain 'contoso.local' `
            -PrivilegedPrincipals @([pscustomobject]@{
                SamAccountName = 'adm-migrated'
                DistinguishedName = 'CN=adm-migrated,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-1000'
                ObjectClass = 'user'
                AdminCount = 1
                SIDHistory = @('S-1-5-21-legacy-512')
            })

        $finding = $model.IdentityRiskFindings | Where-Object FindingType -eq 'PrivilegedSidHistoryPresent' | Select-Object -First 1
        $finding | Should -Not -BeNullOrEmpty
        $finding.IdentityRiskFindingId | Should -Match '^identity-'
        $finding.SourceDomain | Should -Be 'ObjectRisk'
        $finding.Tags -contains 'SIDHistory' | Should -Be $true
    }

    It 'reports adminCount protected objects without current protected membership as review evidence' {
        $model = ConvertTo-ADPostureIdentityRiskModel -Domain 'contoso.local' `
            -AdminCountPrincipals @([pscustomobject]@{
                SamAccountName = 'legacy-admin'
                DistinguishedName = 'CN=legacy-admin,OU=Users,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-2000'
                ObjectClass = 'user'
                AdminCount = 1
                MemberOf = @('CN=VPN Users,OU=Groups,DC=contoso,DC=local')
            })

        $finding = $model.IdentityRiskFindings | Where-Object FindingType -eq 'AdminCountOrphanedProtectedObject' | Select-Object -First 1
        $finding | Should -Not -BeNullOrEmpty
        $finding.SourceDomain | Should -Be 'ObjectRisk'
        $finding.Severity | Should -Be 'Medium'
        $finding.Tags -contains 'AdminSDHolder' | Should -Be $true
        $finding.Tags -contains 'SDProp' | Should -Be $true
        $finding.Reason | Should -Match 'AdminSDHolder'
    }

    It 'does not report adminCount objects that still reference protected groups' {
        $model = ConvertTo-ADPostureIdentityRiskModel -Domain 'contoso.local' `
            -AdminCountPrincipals @([pscustomobject]@{
                SamAccountName = 'adm-current'
                DistinguishedName = 'CN=adm-current,OU=Users,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-3000'
                ObjectClass = 'user'
                AdminCount = 1
                MemberOf = @('CN=Domain Admins,CN=Users,DC=contoso,DC=local')
            })

        @($model.IdentityRiskFindings | Where-Object FindingType -eq 'AdminCountOrphanedProtectedObject').Count | Should -Be 0
    }

    It 'matches approved exceptions scoped to migrated SIDHistory findings' {
        $catalog = [pscustomobject]@{
            Exceptions = @([pscustomobject]@{
                id = 'EXC-SIDHISTORY-001'
                enabled = $true
                findingDomain = 'IdentityRisk'
                findingType = 'PrivilegedSidHistoryPresent'
                setting = 'sIDHistory'
                reason = 'Temporary migration cleanup'
                expiresAt = '2026-12-31'
            })
        }
        $finding = [pscustomobject]@{
            IdentityRiskFindingId = 'identity-000001'
            FindingType = 'PrivilegedSidHistoryPresent'
            Setting = 'sIDHistory'
            Severity = 'High'
        }

        $result = Resolve-ADPostureApprovedFindingException -Finding $finding -Catalog $catalog -AsOf ([datetime]'2026-06-03')

        $result.Id | Should -Be 'EXC-SIDHISTORY-001'
    }

    It 'adds privileged SIDHistory to object risk as identity-risk evidence' {
        $finding = [pscustomobject]@{
            IdentityRiskFindingId = 'identity-000003'
            Domain = 'contoso.local'
            FindingType = 'PrivilegedSidHistoryPresent'
            SourceDomain = 'ObjectRisk'
            MitreId = 'T1134.005'
            RiskPattern = 'SIDHistory on privileged identity'
            Severity = 'High'
            RiskScore = 8
            Principal = 'adm-migrated'
            PrincipalSam = 'adm-migrated'
            PrincipalDn = 'CN=adm-migrated,DC=contoso,DC=local'
            PrincipalSid = 'S-1-5-21-1000'
            PrincipalClass = 'user'
            PrivilegeTier = 'Tier 0'
            Setting = 'sIDHistory'
            ObservedValue = 'S-1-5-21-legacy-512'
            Reason = 'Privileged identity has SIDHistory.'
            Remediation = 'Remove stale SIDHistory.'
            Tags = @('ObjectRisk', 'SIDHistory', 'IdentityRisk')
        }

        $objectModel = ConvertTo-ADObjectRiskModel -Findings @() -IdentityRiskFindings @($finding) -Domain 'contoso.local'

        @($objectModel.Objects).Count | Should -Be 1
        @($objectModel.ObjectEvidence | Where-Object SourceDomain -eq 'ObjectRisk').Count | Should -Be 1
        $objectModel.ObjectEvidence[0].IdentityRiskFindingId | Should -Be 'identity-000003'
    }
}
