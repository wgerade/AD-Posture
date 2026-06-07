$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\Protect-ADPostureFile.ps1')
. (Join-Path $repoRoot 'src\Private\Write-ADPostureDashboardData.ps1')
. (Join-Path $repoRoot 'src\Private\Get-ADPostureGovernanceMetadata.ps1')
. (Join-Path $repoRoot 'src\Private\New-ADPosturePostureSummary.ps1')
. (Join-Path $repoRoot 'src\Private\Update-ADPostureSnapshotV12.ps1')
. (Join-Path $repoRoot 'src\Private\Write-ADPostureDashboardDataPayloadV12.ps1')
. (Join-Path $repoRoot 'src\Public\Export-ADPostureReport.ps1')
. (Join-Path $repoRoot 'src\Public\New-ADPostureRemediationPlaybook.ps1')

function Get-ModuleConfig {
    [pscustomobject]@{
        ReportPath = Join-Path $TestDrive 'reports'
        DashboardPath = Join-Path $TestDrive 'dashboard'
        DataPath = Join-Path $TestDrive 'data'
    }
}

Describe 'Report export' {
    It 'exports complete ACL effective trustee detail outside the bounded dashboard payload' {
        $snapshot = [pscustomobject]@{
            Domain = 'contoso.local'
            Forest = 'contoso.local'
            Timestamp = '2026-05-22T13:00:00Z'
            OverallRiskScore = 12
            TargetScore = 0
            ActionableCount = 1
            ApprovedExceptionCount = 0
            ExpiredExceptionCount = 0
            ReadinessScorecard = [pscustomobject]@{ Score = 80; Level = 'Needs review'; Controls = @() }
            RemediationBreakdown = @{}
            TierBreakdown = @{}
            GroupSummaries = @()
            Findings = @()
            AclFindings = @([pscustomobject]@{
                AclFindingId = 'acl-000001'
                Domain = 'contoso.local'
                NormalizedRight = 'GenericAll'
                Severity = 'High'
                RiskScore = 12
                TrusteeName = 'Delegated ACL Group'
                TrusteeSid = 'S-1-5-21-1000-1000-1000-2201'
                TrusteeDistinguishedName = 'CN=Delegated ACL Group,DC=contoso,DC=local'
                TargetName = 'Tier0 Target'
                TargetDistinguishedName = 'CN=Tier0 Target,DC=contoso,DC=local'
                TargetObjectSid = 'S-1-5-21-1000-1000-1000-5000'
                TargetObjectClass = 'group'
                EffectiveTrustees = @(
                    [pscustomobject]@{ Name = 'user1'; Sid = 'S-1-5-21-1000-1000-1000-1001'; DistinguishedName = 'CN=user1,DC=contoso,DC=local'; ObjectClass = 'user'; NestingDepth = 1; Path = 'user1 -> Delegated ACL Group' },
                    [pscustomobject]@{ Name = 'user2'; Sid = 'S-1-5-21-1000-1000-1000-1002'; DistinguishedName = 'CN=user2,DC=contoso,DC=local'; ObjectClass = 'user'; NestingDepth = 1; Path = 'user2 -> Delegated ACL Group' }
                )
                Reason = 'Trustee can control target.'
                Remediation = 'Remove delegated control.'
            })
            GpoFindings = @()
            AdcsTemplates = @()
            AdcsCas = @()
            AdcsNtAuth = $null
            AdcsFindings = @()
            KerberosAuthPrincipals = @()
            KerberosAuthPolicy = $null
            KerberosAuthFindings = @()
            Trusts = @()
            TrustFindings = @()
            DnsZones = @()
            DnsRecords = @()
            DnsAdmins = @()
            DnsFindings = @()
            Objects = @()
            ObjectEvidence = @()
            ObjectRelationships = @()
        }

        $base = Join-Path $TestDrive 'audit-test'
        Export-ADPostureReport -Snapshot $snapshot -OutputBasePath $base

        $effectiveRows = Import-Csv -LiteralPath "$base-acl-effective-trustees.csv"
        @($effectiveRows).Count | Should Be 2
        $effectiveRows[0].AclFindingId | Should Be 'acl-000001'
        $effectiveRows[0].EffectiveTrusteeName | Should Be 'user1'
        $effectiveRows[1].EffectiveTrusteeName | Should Be 'user2'

        $dashboard = Get-Content -LiteralPath "$base-dashboard.json" -Raw | ConvertFrom-Json
        $dashboard.aclFindings[0].EffectiveTrusteeCount | Should Be 2
        @($dashboard.aclFindings[0].EffectiveTrusteesSample).Count | Should Be 2
        $dashboard.aclFindings[0].PSObject.Properties['EffectiveTrustees'] | Should BeNullOrEmpty
        $snapshot.SchemaVersion | Should Be '1.3'
        @($snapshot.PostureSummary).Count | Should Be 8
        $dashboard.meta.schemaVersion | Should Be '1.3'
        @($dashboard.postureSummary).Count | Should Be 8
    }
}
