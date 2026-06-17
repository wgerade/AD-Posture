BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Protect-ADPostureFile.ps1')
    . (Join-Path $repoRoot 'src\Private\Resolve-ADPostureApprovedException.ps1')

}

Describe 'Approved baseline exceptions' {
    It 'matches active exceptions by group and member SamAccountName' {
        $catalog = [pscustomobject]@{
            Exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-001'
                    enabled = $true
                    sensitiveGroup = 'Domain Admins'
                    memberSam = 'adm-breakglass'
                    reason = 'Approved break-glass'
                    owner = 'Identity Ops'
                    approvedBy = 'CISO'
                    ticket = 'RISK-1'
                    expiresAt = '2026-12-31'
                }
            )
        }
        $enrichment = [pscustomobject]@{
            SamAccountName = 'adm-breakglass'
            ObjectSid = 'S-1-5-21-1'
            DistinguishedName = 'CN=adm-breakglass,DC=contoso,DC=com'
            AccountType = 'User'
        }

        $result = Resolve-ADPostureApprovedException -SensitiveGroup 'Domain Admins' -Enrichment $enrichment -Catalog $catalog -AsOf ([datetime]'2026-05-22')

        $result.Id | Should -Be 'EXC-001'
        $result.Status | Should -Be 'Active'
        $result.Owner | Should -Be 'Identity Ops'
    }

    It 'marks expired exceptions without treating them as active baseline' {
        $catalog = [pscustomobject]@{
            Exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-OLD'
                    enabled = $true
                    sensitiveGroup = '*'
                    memberSid = 'S-1-5-21-OLD'
                    reason = 'Expired approval'
                    expiresAt = '2026-01-01'
                }
            )
        }
        $enrichment = [pscustomobject]@{
            SamAccountName = 'old-admin'
            ObjectSid = 'S-1-5-21-OLD'
            DistinguishedName = 'CN=old-admin,DC=contoso,DC=com'
            AccountType = 'User'
        }

        $result = Resolve-ADPostureApprovedException -SensitiveGroup 'Schema Admins' -Enrichment $enrichment -Catalog $catalog -AsOf ([datetime]'2026-05-22')

        $result.Id | Should -Be 'EXC-OLD'
        $result.Status | Should -Be 'Expired'
    }

    It 'matches ACL findings with scoped exception fields' {
        $catalog = [pscustomobject]@{
            Exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-ACL-001'
                    enabled = $true
                    findingDomain = 'ACL'
                    findingType = 'SensitiveAcl'
                    aclRight = 'GenericAll'
                    trusteeName = 'CONTOSO\Helpdesk'
                    targetDn = 'OU=Servers,DC=contoso,DC=local'
                    reason = 'Accepted delegated server OU administration'
                    owner = 'Infrastructure'
                    approvedBy = 'Security'
                    ticket = 'RISK-ACL-1'
                    expiresAt = '2026-12-31'
                }
            )
        }
        $finding = [pscustomobject]@{
            AclFindingId = 'acl-000001'
            EvidenceType = 'SensitiveAcl'
            NormalizedRight = 'GenericAll'
            TrusteeName = 'CONTOSO\Helpdesk'
            TargetDistinguishedName = 'OU=Servers,DC=contoso,DC=local'
        }

        $result = Resolve-ADPostureApprovedFindingException -Finding $finding -Catalog $catalog -AsOf ([datetime]'2026-05-22')

        $result.Id | Should -Be 'EXC-ACL-001'
        $result.Status | Should -Be 'Active'
    }

    It 'matches GPO findings without allowing membership-only exceptions to match everything' {
        $catalog = [pscustomobject]@{
            Exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-MEMBER-ONLY'
                    enabled = $true
                    sensitiveGroup = '*'
                    memberSam = '*'
                    reason = 'Membership only'
                },
                [pscustomobject]@{
                    id = 'EXC-GPO-001'
                    enabled = $true
                    findingDomain = 'GPO'
                    findingType = 'GpoRiskyScriptContent'
                    gpoName = 'Workstation Startup'
                    delegatedRight = 'CredentialLiteral'
                    fileSystemPath = '*Startup*'
                    reason = 'Temporary lab script finding accepted'
                    owner = 'Endpoint'
                    approvedBy = 'Security'
                    ticket = 'RISK-GPO-1'
                    expiresAt = '2026-12-31'
                }
            )
        }
        $finding = [pscustomobject]@{
            GpoFindingId = 'gpo-000001'
            FindingType = 'GpoRiskyScriptContent'
            GpoName = 'Workstation Startup'
            DelegatedRight = 'CredentialLiteral'
            FileSystemPath = '\\contoso.local\SYSVOL\contoso.local\Policies\{GUID}\Machine\Scripts\Startup\Cred.ps1'
        }

        $result = Resolve-ADPostureApprovedFindingException -Finding $finding -Catalog $catalog -AsOf ([datetime]'2026-05-22')

        $result.Id | Should -Be 'EXC-GPO-001'
    }

    It 'matches ADCS findings with scoped template and principal fields' {
        $catalog = [pscustomobject]@{
            Exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-ADCS-001'
                    enabled = $true
                    findingDomain = 'ADCS'
                    findingType = 'AdcsEsc1LikeTemplate'
                    templateName = 'Legacy User Authentication'
                    principal = 'CONTOSO\Domain Users'
                    reason = 'Temporary ADCS migration exception'
                    owner = 'PKI Operations'
                    approvedBy = 'Security'
                    ticket = 'RISK-ADCS-1'
                    expiresAt = '2026-12-31'
                }
            )
        }
        $finding = [pscustomobject]@{
            AdcsFindingId = 'adcs-000001'
            FindingType = 'AdcsEsc1LikeTemplate'
            TemplateName = 'Legacy User Authentication'
            TemplateDistinguishedName = 'CN=Legacy User Authentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            Principal = 'CONTOSO\Domain Users'
        }

        $result = Resolve-ADPostureApprovedFindingException -Finding $finding -Catalog $catalog -AsOf ([datetime]'2026-05-22')

        $result.Id | Should -Be 'EXC-ADCS-001'
        $result.Status | Should -Be 'Active'
    }

    It 'matches Kerberos/Auth findings with scoped principal and delegation fields' {
        $catalog = [pscustomobject]@{
            Exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-AUTH-001'
                    enabled = $true
                    findingDomain = 'KerberosAuth'
                    findingType = 'KerberosConstrainedDelegation'
                    principalSam = 'svc-web'
                    delegationType = 'Constrained'
                    encryption = '*AES*'
                    reason = 'Approved app delegation pending redesign'
                    owner = 'Identity'
                    approvedBy = 'Security'
                    ticket = 'RISK-AUTH-1'
                    expiresAt = '2026-12-31'
                }
            )
        }
        $finding = [pscustomobject]@{
            KerberosAuthFindingId = 'auth-000001'
            FindingType = 'KerberosConstrainedDelegation'
            Principal = 'svc-web'
            PrincipalSam = 'svc-web'
            PrincipalDn = 'CN=svc-web,DC=contoso,DC=local'
            DelegationType = 'Constrained'
            EncryptionSummary = 'AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96'
        }

        $result = Resolve-ADPostureApprovedFindingException -Finding $finding -Catalog $catalog -AsOf ([datetime]'2026-05-22')

        $result.Id | Should -Be 'EXC-AUTH-001'
        $result.Status | Should -Be 'Active'
    }

    It 'matches Trust findings with scoped trust fields' {
        $catalog = [pscustomobject]@{
            Exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-TRUST-001'
                    enabled = $true
                    findingDomain = 'Trust'
                    findingType = 'TrustSidFilteringDisabled'
                    trustName = 'legacy.corp'
                    trustPartner = 'legacy.corp'
                    trustDirection = 'Inbound'
                    trustType = 'External'
                    reason = 'Temporary migration trust exception'
                    owner = 'Identity'
                    approvedBy = 'Security'
                    ticket = 'RISK-TRUST-1'
                    expiresAt = '2026-12-31'
                }
            )
        }
        $finding = [pscustomobject]@{
            TrustFindingId = 'trust-000001'
            FindingType = 'TrustSidFilteringDisabled'
            TrustName = 'legacy.corp'
            TrustPartner = 'legacy.corp'
            TrustDirection = 'Inbound'
            TrustType = 'External'
        }

        $result = Resolve-ADPostureApprovedFindingException -Finding $finding -Catalog $catalog -AsOf ([datetime]'2026-05-22')

        $result.Id | Should -Be 'EXC-TRUST-001'
        $result.Status | Should -Be 'Active'
    }

    It 'ignores membership exceptions without any membership scope field' {
        $catalog = [pscustomobject]@{
            Exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-UNSCOPED'
                    enabled = $true
                    reason = 'Misconfigured entry with metadata only'
                    owner = 'Identity Ops'
                    approvedBy = 'CISO'
                    ticket = 'RISK-9'
                },
                [pscustomobject]@{
                    id = 'EXC-DNS-SCOPED-ONLY'
                    enabled = $true
                    findingDomain = 'DNS'
                    zoneName = 'corp.example'
                    reason = 'DNS-only exception must not match membership rows'
                }
            )
        }
        $enrichment = [pscustomobject]@{
            SamAccountName = 'any.admin'
            ObjectSid = 'S-1-5-21-77'
            DistinguishedName = 'CN=any.admin,DC=contoso,DC=com'
            AccountType = 'User'
        }

        $result = Resolve-ADPostureApprovedException -SensitiveGroup 'Domain Admins' -Enrichment $enrichment -Catalog $catalog -AsOf ([datetime]'2026-05-22') -WarningAction SilentlyContinue

        $result | Should -BeNullOrEmpty
    }

    It 'matches DNS findings with scoped zone and record fields' {
        $catalog = [pscustomobject]@{
            Exceptions = @([pscustomobject]@{
                id = 'EXC-DNS-001'
                enabled = $true
                findingDomain = 'DNS'
                findingType = 'DnsWildcardRecord'
                zoneName = 'corp.example'
                recordName = '*'
                reason = 'Approved wildcard during migration'
                expiresAt = '2026-12-31'
            })
        }
        $finding = [pscustomobject]@{
            DnsFindingId = 'dns-000001'
            FindingType = 'DnsWildcardRecord'
            ZoneName = 'corp.example'
            RecordName = '*'
        }

        $result = Resolve-ADPostureApprovedFindingException -Finding $finding -Catalog $catalog -AsOf ([datetime]'2026-05-22')

        $result.Id | Should -Be 'EXC-DNS-001'
    }

}
