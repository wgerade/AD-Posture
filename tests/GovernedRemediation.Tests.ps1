BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ADPostureGovernanceMetadata.ps1')
    . (Join-Path $repoRoot 'src\Private\New-ADPosturePostureSummary.ps1')
    . (Join-Path $repoRoot 'src\Private\Resolve-ADPostureApprovedException.ps1')
    . (Join-Path $repoRoot 'src\Private\Update-ADPostureSnapshotV12.ps1')
    . (Join-Path $repoRoot 'src\Public\New-ADPostureRemediationPlaybook.ps1')
    . (Join-Path $repoRoot 'src\Public\Invoke-ADPostureArtifactRetention.ps1')

    function Get-ModuleConfig {
        [pscustomobject]@{
            ModuleRoot = $repoRoot
            ConfigPath = Join-Path $repoRoot 'config'
            DataPath = Join-Path $TestDrive 'data'
            ReportPath = Join-Path $TestDrive 'reports'
            DashboardPath = Join-Path $TestDrive 'dashboard'
            ApprovedExceptionsPath = Join-Path $TestDrive 'ApprovedExceptions.json'
        }
    }

    function New-TestSnapshot {
        [pscustomobject]@{
            SchemaVersion = '1.1'
            AuditId = 'audit-governed'
            Timestamp = '2026-06-05T12:00:00Z'
            Domain = 'contoso.local'
            GroupSummaries = @(
                [pscustomobject]@{ SensitiveGroup = 'Domain Admins'; MemberCount = 0; PrivilegeTier = 'Tier 0'; GroupDistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=local' },
                [pscustomobject]@{ SensitiveGroup = 'Server Admins'; MemberCount = 3; PrivilegeTier = 'Tier 1' }
            )
            Findings = @([pscustomobject]@{
                FindingId = 'membership-1'; FindingType = 'SensitiveGroupMembership'; SensitiveGroup = 'Server Admins'
                MemberSam = 'svc.backup'; MemberDisplay = 'svc.backup'; MemberDn = 'CN=svc.backup,DC=contoso,DC=local'
                IsDirect = $true; TruncatedNesting = $false; RiskScore = 4.5; Severity = 'Medium'; RemediationDifficulty = 'Medium'
            })
            AclFindings = @([pscustomobject]@{ FindingId = 'acl-1'; FindingType = 'SensitiveAcl'; RiskScore = 8; Severity = 'High'; RemediationDifficulty = 'High' })
            GpoFindings = @([pscustomobject]@{ FindingId = 'gpo-1'; FindingType = 'GpoDelegation'; RiskScore = 5; Severity = 'High'; RemediationDifficulty = 'High' })
            AdcsFindings = @([pscustomobject]@{ FindingId = 'adcs-1'; FindingType = 'AdcsTemplateRisk'; RiskScore = 5; Severity = 'High'; RemediationDifficulty = 'High' })
            KerberosAuthFindings = @()
            TrustFindings = @()
            DnsFindings = @([pscustomobject]@{ FindingId = 'dns-1'; FindingType = 'DnsStaleRecord'; ZoneName = 'contoso.local'; RecordName = 'oldhost'; RecordType = 'A'; RiskScore = 2; Severity = 'Medium'; RemediationDifficulty = 'Low' })
            IdentityRiskFindings = @()
            Objects = @()
            ObjectEvidence = @()
            ObjectRelationships = @()
        }
    }

}

Describe 'Governed remediation contracts' {
    It 'adds orphaned sensitive groups, playbooks, and framework mappings to snapshot v1.3' {
        $updated = Update-ADPostureSnapshotV12 -Snapshot (New-TestSnapshot)

        $updated.SchemaVersion | Should -Be '1.3'
        @($updated.OrphanedSensitiveGroupFindings).Count | Should -Be 1
        $updated.Findings | Where-Object FindingType -eq 'OrphanedSensitiveGroup' | Should -Not -BeNullOrEmpty
        @($updated.RemediationPlaybooks).Count | Should -BeGreaterThan 5
        @($updated.FrameworkSummary).Count | Should -BeGreaterThan 0
        @($updated.ObjectEvidence | Where-Object EvidenceType -eq 'OrphanedSensitiveGroup').Count | Should -Be 1
    }

    It 'generates DNS WhatIf playbooks and blocks ambiguous domains' {
        $dns = [pscustomobject]@{ FindingId = 'dns-whatif'; FindingType = 'DnsStaleRecord'; ZoneName = 'contoso.local'; RecordName = 'oldhost'; RecordType = 'A' }
        $acl = [pscustomobject]@{ FindingId = 'acl-blocked'; FindingType = 'SensitiveAcl' }

        $dnsPlaybook = New-ADPostureRemediationPlaybook -Finding $dns
        $aclPlaybook = New-ADPostureRemediationPlaybook -Finding $acl

        $dnsPlaybook.CanGenerateScript | Should -Be $true
        $dnsPlaybook.WhatIfScript | Should -Match 'Remove-DnsServerResourceRecord'
        $dnsPlaybook.WhatIfScript | Should -Match '-WhatIf'
        $aclPlaybook.CanGenerateScript | Should -Be $false
        $aclPlaybook.BlockedReason | Should -Match 'ACL mutation is blocked'
    }

    It 'retains artifacts by dry-run default and removes only with explicit switch' {
        $data = Join-Path $TestDrive 'data'
        New-Item -ItemType Directory -Path $data -Force | Out-Null
        $old = Join-Path $data 'snapshot-old.json'
        '{}' | Set-Content -LiteralPath $old
        (Get-Item -LiteralPath $old).LastWriteTime = (Get-Date).AddDays(-200)

        $dryRun = Invoke-ADPostureArtifactRetention -RetentionDays 180
        Test-Path -LiteralPath $old | Should -Be $true
        $dryRun[0].Status | Should -Be 'DryRun'

        $removed = Invoke-ADPostureArtifactRetention -RetentionDays 180 -Remove -Confirm:$false
        Test-Path -LiteralPath $old | Should -Be $false
        $removed[0].Status | Should -Be 'Removed'
    }

    It 'keeps latest snapshot aliases out of destructive artifact retention' {
        $data = Join-Path $TestDrive 'data'
        New-Item -ItemType Directory -Path $data -Force | Out-Null
        $latest = Join-Path $data 'latest-snapshot.json'
        '{}' | Set-Content -LiteralPath $latest
        (Get-Item -LiteralPath $latest).LastWriteTime = (Get-Date).AddDays(-200)

        $dryRun = Invoke-ADPostureArtifactRetention -RetentionDays 180

        @($dryRun | Where-Object Path -eq $latest).Count | Should -Be 0
        Test-Path -LiteralPath $latest | Should -Be $true
    }
}
