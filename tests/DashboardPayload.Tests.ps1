$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\Protect-ADPostureFile.ps1')
. (Join-Path $repoRoot 'src\Private\Write-ADPostureDashboardData.ps1')
. (Join-Path $repoRoot 'src\Private\Write-ADPostureDashboardDataStatic.ps1')
. (Join-Path $repoRoot 'src\Private\Write-ADPostureDashboardDataPayloadV12.ps1')

function Get-ModuleConfig {
    [pscustomobject]@{
        ReportPath = Join-Path $TestDrive 'reports'
        DashboardPath = Join-Path $TestDrive 'dashboard'
    }
}

Describe 'Dashboard payload' {
    It 'filters excluded findings from dashboard rows' {
        $snapshot = [pscustomobject]@{
            SchemaVersion = '1.2'
            AuditId = 'audit-payload-1'
            Domain = 'contoso.local'
            Forest = 'contoso.local'
            Timestamp = '2026-05-22T13:00:00Z'
            OverallRiskScore = 2.5
            TargetScore = 0
            ActionableCount = 1
            ApprovedExceptionCount = 1
            ExpiredExceptionCount = 0
            ReadinessScorecard = [pscustomobject]@{ Score = 88; Level = 'Needs review'; Controls = @() }
            RemediationBreakdown = @{ Low = 0; Medium = 1; High = 0 }
            TierBreakdown = @{ 'Tier 0' = 1; 'Tier 1' = 0; 'Tier 2' = 0 }
            GroupSummaries = @([pscustomobject]@{ SensitiveGroup = 'Domain Admins'; MemberCount = 1 })
            AclFindings = @([pscustomobject]@{
                AclFindingId = 'acl-000001'
                NormalizedRight = 'GenericAll'
                TargetName = 'AXZ'
                TargetDistinguishedName = 'CN=AXZ,CN=Users,DC=contoso,DC=local'
                TrusteeName = 'Helpdesk'
                TrusteeSid = 'S-1-5-21-1000-1000-1000-4401'
                ObjectTypeName = 'msLAPS-Password'
                IsApprovedException = $true
                ApprovedExceptionStatus = 'Active'
                ApprovedExceptionId = 'EXC-ACL-1'
            })
            GpoFindings = @([pscustomobject]@{
                GpoFindingId = 'gpo-000001'
                FindingType = 'GpoDelegationControl'
                GpoName = 'Tier0 Lockdown'
                IsApprovedException = $true
                ApprovedExceptionStatus = 'Active'
                ApprovedExceptionId = 'EXC-GPO-1'
            })
            AdcsTemplates = @([pscustomobject]@{
                Name = 'UserAuth'
                DisplayName = 'User Authentication'
            })
            AdcsCas = @([pscustomobject]@{
                Name = 'CONTOSO-CA'
                DisplayName = 'CONTOSO-CA'
            })
            AdcsNtAuth = [pscustomobject]@{
                Name = 'NTAuthCertificates'
                CertificateCount = 1
            }
            AdcsFindings = @([pscustomobject]@{
                AdcsFindingId = 'adcs-000001'
                FindingType = 'AdcsEsc1LikeTemplate'
                TemplateName = 'User Authentication'
                IsApprovedException = $true
                ApprovedExceptionStatus = 'Active'
                ApprovedExceptionId = 'EXC-ADCS-1'
            })
            KerberosAuthPrincipals = @([pscustomobject]@{
                SamAccountName = 'svc-sql'
            })
            KerberosAuthPolicy = [pscustomobject]@{
                Source = 'Synthetic'
            }
            KerberosAuthFindings = @([pscustomobject]@{
                KerberosAuthFindingId = 'auth-000001'
                FindingType = 'KerberosRoastableServiceAccount'
                Principal = 'svc-sql'
                IsApprovedException = $true
                ApprovedExceptionStatus = 'Active'
                ApprovedExceptionId = 'EXC-AUTH-1'
            })
            Trusts = @([pscustomobject]@{
                TrustName = 'legacy.corp'
                TrustPartner = 'legacy.corp'
            })
            TrustFindings = @([pscustomobject]@{
                TrustFindingId = 'trust-000001'
                FindingType = 'TrustSidFilteringDisabled'
                TrustName = 'legacy.corp'
                TrustPartner = 'legacy.corp'
                IsApprovedException = $true
                ApprovedExceptionStatus = 'Active'
                ApprovedExceptionId = 'EXC-TRUST-1'
            })
            DnsZones = @([pscustomobject]@{ ZoneName = 'contoso.local' })
            DnsRecords = @([pscustomobject]@{ RecordName = '*'; ZoneName = 'contoso.local' })
            DnsAdmins = @([pscustomobject]@{ SamAccountName = 'dns-admin' })
            DnsFindings = @([pscustomobject]@{
                DnsFindingId = 'dns-000001'
                FindingType = 'DnsWildcardRecord'
                ZoneName = 'contoso.local'
                RecordName = '*'
                IsApprovedException = $true
                ApprovedExceptionStatus = 'Active'
                ApprovedExceptionId = 'EXC-DNS-1'
            })
            Objects = @([pscustomobject]@{ ObjectId = 'contoso.local:sid:S-1-5-21-1'; RiskScore = 2.5 })
            ObjectEvidence = @([pscustomobject]@{
                EvidenceId = 'ev-000001'
                ObjectId = 'contoso.local:sid:S-1-5-21-1'
                SourceDomain = 'ACL'
                AclFindingId = 'acl-000001'
                RelatedObjectName = 'Helpdesk'
                Path = 'Helpdesk -> GenericAll -> AXZ'
            })
            ObjectRelationships = @([pscustomobject]@{ FromObjectId = 'contoso.local:sid:S-1-5-21-1'; RelationshipType = 'SensitiveGroupMembership' })
            PostureSummary = @([pscustomobject]@{ PostureDomain = 'Sensitive Groups'; CollectionStatus = 'Collected'; ActiveFindingCount = 1 })
            Findings = @(
                [pscustomobject]@{ MemberSam = 'kept'; IsExcluded = $false },
                [pscustomobject]@{ MemberSam = 'hidden'; IsExcluded = $true },
                [pscustomobject]@{ MemberSam = 'approved'; IsExcluded = $true; IsApprovedException = $true; ApprovedExceptionStatus = 'Active' }
            )
        }

        $payload = Get-ADPostureDashboardPayload -Snapshot $snapshot

        $payload.meta.domain | Should Be 'contoso.local'
        $payload.meta.schemaVersion | Should Be '1.2'
        $payload.meta.auditId | Should Be 'audit-payload-1'
        @($payload.postureSummary).Count | Should Be 1
        $payload.postureSummary[0].PostureDomain | Should Be 'Sensitive Groups'
        $payload.meta.aclFieldClassification.TargetDistinguishedName | Should Be 'Sensitive'
        $payload.meta.aclFieldClassification.NormalizedRight | Should Be 'Operational'
        $payload.meta.redactedAclEvidence | Should Be $false
        $payload.meta.tierBreakdown['Tier 0'] | Should Be 1
        @($payload.findings).Count | Should Be 1
        $payload.findings[0].MemberSam | Should Be 'kept'
        @($payload.monitoring).Count | Should Be 1
        $payload.monitoring[0].MemberSam | Should Be 'hidden'
        foreach ($requiredProperty in @('MemberSam', 'IsExcluded')) {
            $payload.findings[0].PSObject.Properties.Name -contains $requiredProperty | Should Be $true
            $payload.monitoring[0].PSObject.Properties.Name -contains $requiredProperty | Should Be $true
        }
        $payload.meta.approvedExceptionCount | Should Be 1
        $payload.meta.readiness.Score | Should Be 88
        @($payload.exceptions).Count | Should Be 7
        $payload.exceptions[0].MemberSam | Should Be 'approved'
        @($payload.aclFindings).Count | Should Be 1
        $payload.aclFindings[0].NormalizedRight | Should Be 'GenericAll'
        @($payload.gpoFindings).Count | Should Be 1
        $payload.gpoFindings[0].FindingType | Should Be 'GpoDelegationControl'
        @($payload.adcsTemplates).Count | Should Be 1
        @($payload.adcsCas).Count | Should Be 1
        $payload.adcsNtAuth.Name | Should Be 'NTAuthCertificates'
        @($payload.adcsFindings).Count | Should Be 1
        $payload.adcsFindings[0].FindingType | Should Be 'AdcsEsc1LikeTemplate'
        @($payload.kerberosAuthFindings).Count | Should Be 1
        $payload.kerberosAuthFindings[0].FindingType | Should Be 'KerberosRoastableServiceAccount'
        @($payload.kerberosAuthPrincipals).Count | Should Be 1
        $payload.kerberosAuthPolicy.Source | Should Be 'Synthetic'
        @($payload.trusts).Count | Should Be 1
        @($payload.trustFindings).Count | Should Be 1
        $payload.trustFindings[0].FindingType | Should Be 'TrustSidFilteringDisabled'
        @($payload.dnsZones).Count | Should Be 1
        @($payload.dnsRecords).Count | Should Be 1
        @($payload.dnsAdmins).Count | Should Be 1
        @($payload.dnsFindings).Count | Should Be 1
        $payload.dnsFindings[0].FindingType | Should Be 'DnsWildcardRecord'
        @($payload.objects).Count | Should Be 1
        @($payload.objectEvidence).Count | Should Be 1
        @($payload.objectRelationships).Count | Should Be 1
    }

    It 'can redact sensitive ACL evidence fields for export' {
        $snapshot = [pscustomobject]@{
            Domain = 'contoso.local'
            Forest = 'contoso.local'
            Timestamp = '2026-05-22T13:00:00Z'
            OverallRiskScore = 2.5
            TargetScore = 0
            ActionableCount = 1
            ApprovedExceptionCount = 0
            ExpiredExceptionCount = 0
            ReadinessScorecard = [pscustomobject]@{ Score = 88; Level = 'Needs review'; Controls = @() }
            RemediationBreakdown = @{}
            TierBreakdown = @{}
            GroupSummaries = @()
            Findings = @()
            AclFindings = @([pscustomobject]@{
                AclFindingId = 'acl-000001'
                NormalizedRight = 'GenericAll'
                TargetName = 'AXZ'
                TargetDistinguishedName = 'CN=AXZ,CN=Users,DC=contoso,DC=local'
                TrusteeName = 'Helpdesk'
                TrusteeSid = 'S-1-5-21-1000-1000-1000-4401'
                RawSddl = 'O:SYG:SYD:(A;;GA;;;S-1-5-21-1000-1000-1000-4401)'
                RiskScore = 12
            })
            Objects = @()
            ObjectEvidence = @([pscustomobject]@{
                EvidenceId = 'ev-000001'
                SourceDomain = 'ACL'
                AclFindingId = 'acl-000001'
                RelatedObjectName = 'Helpdesk'
                Path = 'Helpdesk -> GenericAll -> AXZ'
                SecurityDescriptorSddl = 'O:SYG:SYD:(A;;GA;;;S-1-5-21-1000-1000-1000-4401)'
            })
            ObjectRelationships = @()
        }

        $payload = Get-ADPostureDashboardPayload -Snapshot $snapshot -RedactSensitiveAclEvidence

        $payload.meta.redactedAclEvidence | Should Be $true
        $payload.aclFindings[0].TargetName | Should Be '[REDACTED]'
        $payload.aclFindings[0].TargetDistinguishedName | Should Be '[REDACTED]'
        $payload.aclFindings[0].TrusteeName | Should Be '[REDACTED]'
        $payload.aclFindings[0].TrusteeSid | Should Be '[REDACTED]'
        $payload.aclFindings[0].RawSddl | Should Be '[REDACTED]'
        $payload.aclFindings[0].NormalizedRight | Should Be 'GenericAll'
        $payload.objectEvidence[0].RelatedObjectName | Should Be '[REDACTED]'
        $payload.objectEvidence[0].Path | Should Be '[REDACTED]'
        $payload.objectEvidence[0].SecurityDescriptorSddl | Should Be '[REDACTED]'
    }

    It 'keeps ACL effective trustees bounded in dashboard payload' {
        $effectiveTrustees = 1..25 | ForEach-Object {
            [pscustomobject]@{
                Name = "user$_"
                Sid = "S-1-5-21-1000-1000-1000-$($_)"
                DistinguishedName = "CN=user$_,DC=contoso,DC=local"
                ObjectClass = 'user'
                NestingDepth = 1
                Path = "user$_ -> Delegated ACL Group"
            }
        }
        $snapshot = [pscustomobject]@{
            Domain = 'contoso.local'
            Forest = 'contoso.local'
            Timestamp = '2026-05-22T13:00:00Z'
            OverallRiskScore = 2.5
            TargetScore = 0
            ActionableCount = 1
            ApprovedExceptionCount = 0
            ExpiredExceptionCount = 0
            ReadinessScorecard = [pscustomobject]@{ Score = 88; Level = 'Needs review'; Controls = @() }
            RemediationBreakdown = @{}
            TierBreakdown = @{}
            GroupSummaries = @()
            Findings = @()
            AclFindings = @([pscustomobject]@{
                AclFindingId = 'acl-000001'
                NormalizedRight = 'GenericAll'
                TargetName = 'AXZ'
                TrusteeName = 'Delegated ACL Group'
                RiskScore = 12
                EffectiveTrustees = @($effectiveTrustees)
            })
            Objects = @()
            ObjectEvidence = @()
            ObjectRelationships = @()
        }

        $payload = Get-ADPostureDashboardPayload -Snapshot $snapshot

        $payload.aclFindings[0].PSObject.Properties['EffectiveTrustees'] | Should BeNullOrEmpty
        $payload.aclFindings[0].EffectiveTrusteeCount | Should Be 25
        @($payload.aclFindings[0].EffectiveTrusteesSample).Count | Should Be 10
        $payload.aclFindings[0].EffectiveTrusteesTruncated | Should Be $true
    }

    It 'does not emit clear-text LAPS value fields in dashboard payload shape' {
        $snapshot = [pscustomobject]@{
            Domain = 'contoso.local'
            Forest = 'contoso.local'
            Timestamp = '2026-05-22T13:00:00Z'
            OverallRiskScore = 2.5
            TargetScore = 0
            ActionableCount = 1
            ApprovedExceptionCount = 0
            ExpiredExceptionCount = 0
            ReadinessScorecard = [pscustomobject]@{ Score = 88; Level = 'Needs review'; Controls = @() }
            RemediationBreakdown = @{}
            TierBreakdown = @{}
            GroupSummaries = @()
            Findings = @()
            AclFindings = @([pscustomobject]@{
                AclFindingId = 'acl-000001'
                NormalizedRight = 'WindowsLapsControl'
                ObjectTypeName = 'msLAPS-Password'
                Remediation = 'Restrict Windows LAPS attribute access.'
            })
            Objects = @()
            ObjectEvidence = @()
            ObjectRelationships = @()
        }

        $json = Get-ADPostureDashboardPayload -Snapshot $snapshot | ConvertTo-Json -Depth 12

        $json | Should Not Match '"ms-Mcs-AdmPwd"\s*:'
        $json | Should Not Match '"msLAPS-Password"\s*:'
        $json | Should Not Match '"msLAPS-EncryptedPassword"\s*:'
        $json | Should Not Match '"msLAPS-EncryptedDSRMPassword"\s*:'
    }

    It 'writes dashboard data atomically and protects generated files best-effort' {
        $payload = [pscustomobject]@{
            meta = [pscustomobject]@{ domain = 'contoso.local' }
            findings = @([pscustomobject]@{ MemberSam = 'adm.one' })
        }

        Write-ADPostureDashboardData -DashboardData $payload

        $cfg = Get-ModuleConfig
        $reportJson = Join-Path $cfg.ReportPath 'latest-dashboard.json'
        $dashboardJson = Join-Path $cfg.DashboardPath 'latest-dashboard.json'
        $dashboardJs = Join-Path $cfg.DashboardPath 'dashboard-data.js'

        Test-Path -LiteralPath $reportJson | Should Be $true
        Test-Path -LiteralPath $dashboardJson | Should Be $true
        Test-Path -LiteralPath $dashboardJs | Should Be $true
        (Get-Content -LiteralPath $reportJson -Raw -Encoding UTF8) | Should Match '"domain":"contoso.local"'
        (Get-Content -LiteralPath $dashboardJs -Raw -Encoding UTF8) | Should Match 'window.__AD_AUDIT_DATA__'
        Test-Path -LiteralPath (Join-Path $cfg.ReportPath 'dashboard-store') | Should Be $false
    }

    It 'loads the full embedded dashboard bundle for static pages' {
        $dashboardRoot = Join-Path $repoRoot 'dashboard'
        $pages = Get-ChildItem -LiteralPath $dashboardRoot -Filter '*.html' | Where-Object Name -ne 'timeline.html'

        foreach ($page in @($pages | Where-Object { $_.Name -ne 'trust.html' })) {
            $content = Get-Content -LiteralPath $page.FullName -Raw
            $content | Should Match '<script src="bootstrap\.js"'
        }

        $bootstrap = Get-Content -LiteralPath (Join-Path $dashboardRoot 'bootstrap.js') -Raw
        $bootstrap | Should Match 'dashboard-data\.js'
        $bootstrap | Should Not Match 'location\.protocol'
    }

    It 'keeps static dashboard shell, imports, and terminology consistent' {
        $dashboardRoot = Join-Path $repoRoot 'dashboard'
        $shared = Get-Content -LiteralPath (Join-Path $dashboardRoot 'shared.js') -Raw
        $shared | Should Match 'loadAuditData'
        $shared | Should Match 'setupJsonImport'
        $shared | Should Match 'updateSortHeaders'
        $shared | Should Match 'adaudit_banner_dismissed_\$\{currentFile\}'

        foreach ($pageName in @('auth.html', 'dns.html', 'trusts.html')) {
            $content = Get-Content -LiteralPath (Join-Path $dashboardRoot $pageName) -Raw
            $content | Should Match 'id="sb-lastrun"'
            $content | Should Match 'id="sb-target"'
            $content | Should Match 'sb-progress-fill'
            $content | Should Match 'type="file"'
            $content | Should Not Match 'v2\.0 - Blue Team'
            $content | Should Not Match 'id="sb-time"'
        }

        foreach ($page in @(Get-ChildItem -LiteralPath $dashboardRoot -Filter '*.html' | Where-Object { $_.Name -ne 'trust.html' })) {
            $content = Get-Content -LiteralPath $page.FullName -Raw
            $content | Should Match '<span class="sb-icon">ADO</span><span>AD Objects</span>'
            $content | Should Match '<span class="sb-icon">KRB</span><span>Kerberos</span>'
            $content | Should Not Match '<span class="sb-icon">HRD</span><span>Hardening</span>'
            $content | Should Match '<span class="sb-icon">FIX</span><span>Action Plan</span>'
            $content | Should Match '<span class="sb-icon">EXC</span><span>Exceptions</span>'
            $content | Should Match '<span class="sb-icon">TIM</span><span>Timeline</span>'
            $content | Should Match '<span class="sb-icon">RPT</span><span>Executive</span>'
        }

        (Get-Content -LiteralPath (Join-Path $dashboardRoot 'timeline.html') -Raw) | Should Not Match '<script src="bootstrap\.js"'
    }

    It 'writes and verifies SHA-256 sidecar files' {
        $path = Join-Path $TestDrive 'snapshot.json'
        Write-ADPostureAtomicTextFile -Path $path -Value '{"ok":true}'

        $hash = Write-ADPostureFileHashSidecar -Path $path
        $valid = Test-ADPostureFileHashSidecar -Path $path

        $hash | Should Match '^[A-F0-9]{64}$'
        $valid.Status | Should Be 'Valid'

        Write-ADPostureAtomicTextFile -Path $path -Value '{"ok":false}'
        $mismatch = Test-ADPostureFileHashSidecar -Path $path
        $mismatch.Status | Should Be 'Mismatch'
    }
}
