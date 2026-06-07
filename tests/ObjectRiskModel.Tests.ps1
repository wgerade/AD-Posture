$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\ConvertTo-ADObjectRiskModel.ps1')

Describe 'Object risk model' {
    It 'builds object summaries, evidence, and relationships from findings' {
        $findings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'
                SensitiveGroup = 'Domain Admins'
                PrivilegeTier = 'Tier 0'
                PrivilegeTierReason = 'Domain Admins'
                MemberSam = 'svc-backup'
                MemberDisplay = 'Backup Service'
                MemberDn = 'CN=svc-backup,OU=Service Accounts,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-1000-1000-1000-1101'
                AccountType = 'ServiceAccount'
                IsDirect = $false
                NestingDepth = 1
                MembershipChain = 'Domain Admins -> Backup Admins -> svc-backup'
                AccountStatus = 'Active'
                IsDisabled = $false
                IsStale = $true
                PasswordNeverExpires = $true
                UacActiveFlagNames = 'TRUSTED_FOR_DELEGATION'
                UserAccountControlSummary = 'Normal Account, Unconstrained Delegation'
                IsExcluded = $false
                IsApprovedException = $false
                RiskScore = 8.25
                ScoreFormula = '(5 * 1.15 * 1.12 * 1.08 * 1) + 1.25 = 8.25'
                ScoreComponents = @([pscustomobject]@{ Name = 'Sensitive group weight'; Value = 5 })
                TechnicalRisk = 'Privileged service identity can become a persistent control path'
                AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation' })
                RemediationDifficulty = 'High'
                CleanupActions = 'Remove standing service account privilege'
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings $findings -Domain 'contoso.local'

        @($model.Objects).Count | Should Be 1
        @($model.ObjectEvidence).Count | Should Be 1
        @($model.ObjectRelationships).Count | Should Be 1

        $member = $model.Objects | Where-Object ObjectSid -eq 'S-1-5-21-1000-1000-1000-1101'
        $member.RiskScore | Should Be 8.25
        $member.Severity | Should Be 'High'
        $member.Tags -contains 'Tier0Exposure' | Should Be $true
        $member.Tags -contains 'PrivilegedMembership' | Should Be $true
        $member.Tags -contains 'IndirectPrivilege' | Should Be $true
        $member.Tags -contains 'StaleIdentity' | Should Be $true
        $member.Tags -contains 'PasswordNeverExpires' | Should Be $true
        $member.Tags -contains 'DelegationRisk' | Should Be $true
        $member.Tags -contains 'ServiceAccount' | Should Be $true
        @($member.EvidenceIds).Count | Should Be 1

        $model.ObjectEvidence[0].EvidenceType | Should Be 'SensitiveGroupMembership'
        $model.ObjectEvidence[0].RelatedObjectName | Should Be 'Domain Admins'
        $model.ObjectRelationships[0].RelationshipType | Should Be 'SensitiveGroupMembership'
    }

    It 'aggregates multiple findings for the same object' {
        $findings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'; SensitiveGroup = 'Domain Admins'; PrivilegeTier = 'Tier 0'
                MemberSam = 'adm-user'; MemberDisplay = 'Admin User'; MemberDn = 'CN=adm-user,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-1000-1000-1000-1102'; AccountType = 'User'; IsDirect = $true; NestingDepth = 0
                MembershipChain = 'Domain Admins -> adm-user'; IsExcluded = $false; IsApprovedException = $false
                RiskScore = 5.0; TechnicalRisk = 'Membership grants broad administrative control'
            },
            [pscustomobject]@{
                Domain = 'contoso.local'; SensitiveGroup = 'Backup Operators'; PrivilegeTier = 'Tier 1'
                MemberSam = 'adm-user'; MemberDisplay = 'Admin User'; MemberDn = 'CN=adm-user,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-1000-1000-1000-1102'; AccountType = 'User'; IsDirect = $true; NestingDepth = 0
                MembershipChain = 'Backup Operators -> adm-user'; IsExcluded = $false; IsApprovedException = $false
                RiskScore = 2.5; TechnicalRisk = 'Sensitive group membership requires validation'
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings $findings -Domain 'contoso.local'
        $member = $model.Objects | Where-Object ObjectSid -eq 'S-1-5-21-1000-1000-1000-1102'

        $member.RiskScore | Should Be 7.5
        @($member.EvidenceIds).Count | Should Be 2
        @($model.ObjectEvidence).Count | Should Be 2
        @($model.ObjectRelationships).Count | Should Be 2
    }

    It 'adds Kerberos/Auth findings to object risk summaries' {
        $authFindings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'
                KerberosAuthFindingId = 'auth-000001'
                FindingType = 'KerberosRoastableServiceAccount'
                RiskPattern = 'Kerberoast'
                Severity = 'High'
                RiskScore = 7.0
                Principal = 'svc-sql'
                PrincipalSam = 'svc-sql'
                PrincipalDn = 'CN=svc-sql,DC=contoso,DC=local'
                PrincipalSid = 'S-1-5-21-1000-1000-1000-5001'
                PrincipalClass = 'user'
                AccountType = 'ServiceAccount'
                PrivilegeTier = 'Tier 1'
                ServicePrincipalNames = @('MSSQLSvc/sql01.contoso.local:1433')
                DelegationTargets = @()
                EncryptionSummary = 'RC4-HMAC'
                EncryptionTypes = @('RC4-HMAC')
                Reason = 'Service principal can receive Kerberos service tickets.'
                Remediation = 'Rotate and reduce service account privilege.'
                ScoreFormula = 'Kerberoast score'
                ScoreComponents = @([pscustomobject]@{ Name = 'SPN count'; Value = 1 })
                Tags = @('KerberosAuth', 'Kerberoast', 'ServicePrincipal')
            }
        )

        $model = ConvertTo-ADObjectRiskModel -KerberosAuthFindings $authFindings -Domain 'contoso.local'

        @($model.Objects).Count | Should Be 1
        @($model.ObjectEvidence).Count | Should Be 1
        $model.Objects[0].SamAccountName | Should Be 'svc-sql'
        $model.Objects[0].Tags -contains 'Kerberoast' | Should Be $true
        $model.ObjectEvidence[0].SourceDomain | Should Be 'KerberosAuth'
        $model.ObjectEvidence[0].KerberosAuthFindingId | Should Be 'auth-000001'
    }

    It 'adds Trust findings to object risk summaries' {
        $trustFindings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'
                TrustFindingId = 'trust-000001'
                FindingType = 'TrustSidFilteringDisabled'
                RiskPattern = 'SID filtering gap'
                Severity = 'Critical'
                RiskScore = 12.0
                TrustName = 'legacy.corp'
                TrustPartner = 'legacy.corp'
                TrustDirection = 'Inbound'
                TrustType = 'External'
                DistinguishedName = 'CN=legacy.corp,CN=System,DC=contoso,DC=local'
                IsTransitive = $false
                SelectiveAuthentication = $false
                SIDFilteringEnabled = $false
                Reason = 'Inbound external trust lacks SID filtering.'
                Remediation = 'Enable SID filtering.'
                ScoreFormula = 'Trust score'
                ScoreComponents = @([pscustomobject]@{ Name = 'SID filtering'; Value = $false })
                Tags = @('TrustPosture', 'TrustBoundary', 'Tier0Exposure')
            }
        )

        $model = ConvertTo-ADObjectRiskModel -TrustFindings $trustFindings -Domain 'contoso.local'

        @($model.Objects).Count | Should Be 1
        @($model.ObjectEvidence).Count | Should Be 1
        @($model.ObjectRelationships).Count | Should Be 1
        $model.Objects[0].ObjectClass | Should Be 'trustedDomain'
        $model.Objects[0].Tags -contains 'TrustBoundary' | Should Be $true
        $model.Objects[0].PrivilegeTier | Should Be 'Tier 0'
        $model.ObjectEvidence[0].SourceDomain | Should Be 'Trust'
        $model.ObjectEvidence[0].TrustFindingId | Should Be 'trust-000001'
        $model.ObjectRelationships[0].RelationshipType | Should Be 'TrustSidFilteringDisabled'
    }

    It 'adds DNS findings to object risk summaries' {
        $dnsFindings = @([pscustomobject]@{
            Domain = 'contoso.local'
            DnsFindingId = 'dns-000001'
            FindingType = 'DnsWildcardRecord'
            RiskPattern = 'Wildcard DNS record'
            Severity = 'Medium'
            RiskScore = 6.0
            ZoneName = 'contoso.local'
            RecordName = '*'
            RecordType = 'A'
            RecordData = '10.0.0.1'
            Reason = 'Wildcard record exists.'
            Remediation = 'Remove wildcard record.'
            Tags = @('DnsPosture', 'Wildcard')
        })
        $model = ConvertTo-ADObjectRiskModel -DnsFindings $dnsFindings -Domain 'contoso.local'

        @($model.Objects).Count | Should Be 1
        @($model.ObjectEvidence).Count | Should Be 1
        @($model.ObjectEvidence | Where-Object SourceDomain -eq 'DNS').Count | Should Be 1
        ($model.Objects | Where-Object DisplayName -eq '*.contoso.local').Tags -contains 'DnsPosture' | Should Be $true
    }

    It 'keeps native and excluded architecture objects out of the actionable object queue' {
        $findings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'; SensitiveGroup = 'Domain Admins'; PrivilegeTier = 'Tier 0'
                MemberSam = 'Administrator'; MemberDisplay = 'Administrator'; MemberDn = 'CN=Administrator,CN=Users,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-1000-1000-1000-500'; AccountType = 'User'; IsDirect = $false; NestingDepth = 1
                MembershipChain = 'Domain Admins -> Administrator'; IsExcluded = $false
                RiskScore = 40.62; TechnicalRisk = 'Built-in Administrator account'
            },
            [pscustomobject]@{
                Domain = 'contoso.local'; SensitiveGroup = 'Domain Admins'; PrivilegeTier = 'Tier 0'
                MemberSam = 'Domain Admins'; MemberDisplay = 'Domain Admins'; MemberDn = 'CN=Domain Admins,CN=Users,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-1000-1000-1000-512'; AccountType = 'Group'; IsDirect = $false; NestingDepth = 1
                MembershipChain = 'Domain Admins -> Domain Admins'; IsExcluded = $false
                RiskScore = 4.86; TechnicalRisk = 'Built-in domain principal'
            },
            [pscustomobject]@{
                Domain = 'contoso.local'; SensitiveGroup = 'Enterprise Admins'; PrivilegeTier = 'Tier 0'
                MemberSam = 'Enterprise Admins'; MemberDisplay = 'Enterprise Admins'; MemberDn = 'CN=Enterprise Admins,CN=Users,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-1000-1000-1000-519'; AccountType = 'Group'; IsDirect = $false; NestingDepth = 1
                MembershipChain = 'Enterprise Admins -> Enterprise Admins'; IsExcluded = $false; IsNativeIdentity = $true; IsRemediableIdentity = $false
                RiskScore = 5.9; TechnicalRisk = 'Built-in domain principal'
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings $findings -Domain 'contoso.local'

        @($model.Objects).Count | Should Be 0
        @($model.ObjectEvidence).Count | Should Be 0
        @($model.ObjectRelationships).Count | Should Be 0
    }

    It 'keeps built-in ACL targets out of the object queue while preserving custom trustees' {
        $aclFindings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'
                AclFindingId = 'acl-000001'
                TargetName = 'Domain Admins'
                TargetObjectClass = 'group'
                TargetObjectSid = 'S-1-5-21-1000-1000-1000-512'
                TrusteeName = 'Group Operators'
                TrusteeObjectClass = 'group'
                NormalizedRight = 'WriteMembership'
                RiskScore = 9.5
                Severity = 'High'
                Reason = 'Trustee can modify privileged group membership'
                Tags = @('MembershipControl', 'SensitiveAclTarget', 'SensitiveAclTrustee')
                ActiveDirectoryRights = @('WriteProperty')
                ObjectType = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
                IsInherited = $false
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings @() -AclFindings $aclFindings -Domain 'contoso.local'

        @($model.Objects | Where-Object DisplayName -eq 'Domain Admins').Count | Should Be 0
        @($model.Objects | Where-Object DisplayName -eq 'Group Operators').Count | Should Be 1
        @($model.ObjectEvidence).Count | Should Be 1
        @($model.ObjectRelationships).Count | Should Be 1
    }

    It 'keeps broad ACL trustees out of the object queue and labels GPO targets clearly' {
        $aclFindings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'
                AclFindingId = 'acl-000040'
                TargetName = 'Everyone'
                TargetObjectClass = 'groupPolicyContainer'
                TargetDistinguishedName = 'CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System,DC=contoso,DC=local'
                TrusteeName = 'Everyone'
                TrusteeSid = 'S-1-1-0'
                TrusteeObjectClass = 'unknown'
                NormalizedRight = 'GenericAll'
                RiskScore = 10.2
                Severity = 'High'
                Reason = 'Trustee can fully control the GPO container'
                Tags = @('GpoAclTarget', 'SensitiveAclTarget', 'SensitiveAclTrustee')
                ActiveDirectoryRights = @('GenericAll')
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings @() -AclFindings $aclFindings -Domain 'contoso.local'

        @($model.Objects).Count | Should Be 1
        $model.Objects[0].DisplayName | Should Be 'GPO: Everyone'
        $model.Objects[0].ObjectClass | Should Be 'groupPolicyContainer'
        $model.Objects[0].ObjectRoles -contains 'AclTarget' | Should Be $true
        @($model.Objects | Where-Object { $_.DisplayName -eq 'Everyone' -and $_.ObjectClass -eq 'wellKnownPrincipal' }).Count | Should Be 0
        @($model.ObjectEvidence).Count | Should Be 1
        @($model.ObjectRelationships).Count | Should Be 1
    }

    It 'preserves ACL inheritance and object-type details in object evidence' {
        $aclFindings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'
                AclFindingId = 'acl-000050'
                TargetName = 'Privileged Workstation'
                TargetObjectClass = 'computer'
                TargetDistinguishedName = 'CN=Privileged Workstation,OU=Workstations,DC=contoso,DC=local'
                TrusteeName = 'Helpdesk Delegates'
                TrusteeObjectClass = 'group'
                NormalizedRight = 'WindowsLapsControl'
                RiskScore = 5.2
                Severity = 'High'
                Reason = 'Trustee has access to Windows LAPS attributes'
                Tags = @('WindowsLAPS', 'CredentialExposure', 'SensitiveAclTarget', 'SensitiveAclTrustee')
                ActiveDirectoryRights = @('ReadProperty')
                ObjectType = 'f3531ec6-6330-4f8e-8d39-7a671fbac605'
                ObjectTypeName = 'ms-LAPS-Encrypted-Password-Attributes'
                InheritedObjectType = 'bf967a86-0de6-11d0-a285-00aa003049e2'
                InheritedObjectTypeName = 'Computer'
                InheritanceType = 'All'
                ObjectFlags = 'ObjectAceTypePresent, InheritedObjectAceTypePresent'
                InheritanceFlags = 'ContainerInherit'
                PropagationFlags = 'None'
                AccessControlType = 'Allow'
                IsInherited = $true
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings @() -AclFindings $aclFindings -Domain 'contoso.local'
        $evidence = $model.ObjectEvidence[0]

        $evidence.ObjectType | Should Be 'f3531ec6-6330-4f8e-8d39-7a671fbac605'
        $evidence.ObjectTypeName | Should Be 'ms-LAPS-Encrypted-Password-Attributes'
        $evidence.InheritedObjectType | Should Be 'bf967a86-0de6-11d0-a285-00aa003049e2'
        $evidence.InheritedObjectTypeName | Should Be 'Computer'
        $evidence.InheritanceType | Should Be 'All'
        $evidence.ObjectFlags | Should Be 'ObjectAceTypePresent, InheritedObjectAceTypePresent'
        $evidence.InheritanceFlags | Should Be 'ContainerInherit'
        $evidence.PropagationFlags | Should Be 'None'
        $evidence.AccessControlType | Should Be 'Allow'
        $evidence.IsInherited | Should Be $true
    }

    It 'preserves owner and source descriptor details in object evidence' {
        $aclFindings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'
                AclFindingId = 'acl-000060'
                TargetName = 'AXZ'
                TargetObjectClass = 'user'
                TargetDistinguishedName = 'CN=AXZ,CN=Users,DC=contoso,DC=local'
                OwnerName = 'CONTOSO\HelpdeskUser'
                OwnerSid = 'S-1-5-21-1000-1000-1000-4401'
                OwnerDistinguishedName = 'CN=HelpdeskUser,OU=Helpdesk,DC=contoso,DC=local'
                OwnerObjectClass = 'user'
                TrusteeName = 'CONTOSO\HelpdeskUser'
                TrusteeSid = 'S-1-5-21-1000-1000-1000-4401'
                TrusteeObjectClass = 'user'
                NormalizedRight = 'ObjectOwner'
                EvidenceType = 'SensitiveAclOwner'
                RiskScore = 6.6
                Severity = 'High'
                Reason = 'Unexpected owner can modify the DACL on the sensitive AD object'
                Tags = @('UnexpectedOwner', 'OwnerControl', 'SensitiveAclTarget', 'SensitiveAclTrustee')
                ActiveDirectoryRights = @('Owner')
                ObjectType = 'Owner'
                ObjectTypeName = 'Owner'
                AccessControlType = 'Owner'
                SourceDescriptorId = 'CN=AXZ,CN=Users,DC=contoso,DC=local'
                IsInherited = $false
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings @() -AclFindings $aclFindings -Domain 'contoso.local'
        $evidence = $model.ObjectEvidence[0]

        $evidence.EvidenceType | Should Be 'SensitiveAclOwner'
        $evidence.OwnerName | Should Be 'CONTOSO\HelpdeskUser'
        $evidence.OwnerSid | Should Be 'S-1-5-21-1000-1000-1000-4401'
        $evidence.OwnerDistinguishedName | Should Be 'CN=HelpdeskUser,OU=Helpdesk,DC=contoso,DC=local'
        $evidence.OwnerObjectClass | Should Be 'user'
        $evidence.SourceDescriptorId | Should Be 'CN=AXZ,CN=Users,DC=contoso,DC=local'
    }

    It 'aggregates Windows LAPS attribute ACLs in the object risk model' {
        $aclFindings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'; AclFindingId = 'acl-000101'; TargetName = 'LapsNovo'
                TargetObjectClass = 'organizationalUnit'; TargetDistinguishedName = 'OU=LapsNovo,DC=contoso,DC=local'
                TrusteeName = 'BUILTIN\Guests'; TrusteeSid = 'S-1-5-32-546'; TrusteeObjectClass = 'group'
                NormalizedRight = 'WindowsLapsControl'; RiskScore = 6; Severity = 'High'
                Reason = 'Trustee has access to Windows LAPS attributes'; Tags = @('WindowsLAPS', 'CredentialExposure')
                ActiveDirectoryRights = @('ReadProperty', 'ExtendedRight'); ObjectType = 'guid-password'
                ObjectTypeName = 'msLAPS-Password'; AccessControlType = 'Allow'; InheritanceType = 'Descendents'
                IsInherited = $false
                EffectiveTrustees = @([pscustomobject]@{ Name = 'Guest'; Sid = 'S-1-5-21-1000-1000-1000-501'; ObjectClass = 'user'; NestingDepth = 1; Path = 'Guest -> BUILTIN\Guests' })
            },
            [pscustomobject]@{
                Domain = 'contoso.local'; AclFindingId = 'acl-000102'; TargetName = 'LapsNovo'
                TargetObjectClass = 'organizationalUnit'; TargetDistinguishedName = 'OU=LapsNovo,DC=contoso,DC=local'
                TrusteeName = 'BUILTIN\Guests'; TrusteeSid = 'S-1-5-32-546'; TrusteeObjectClass = 'group'
                NormalizedRight = 'WindowsLapsControl'; RiskScore = 6; Severity = 'High'
                Reason = 'Trustee has access to Windows LAPS attributes'; Tags = @('WindowsLAPS', 'CredentialExposure')
                ActiveDirectoryRights = @('ReadProperty', 'ExtendedRight'); ObjectType = 'guid-encrypted'
                ObjectTypeName = 'msLAPS-EncryptedPassword'; AccessControlType = 'Allow'; InheritanceType = 'Descendents'
                IsInherited = $false
                EffectiveTrustees = @([pscustomobject]@{ Name = 'Guest'; Sid = 'S-1-5-21-1000-1000-1000-501'; ObjectClass = 'user'; NestingDepth = 1; Path = 'Guest -> BUILTIN\Guests' })
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings @() -AclFindings $aclFindings -Domain 'contoso.local'
        $target = $model.Objects | Where-Object DisplayName -eq 'LapsNovo'
        $directEvidence = $model.ObjectEvidence | Where-Object EvidenceType -eq 'SensitiveAcl'
        $effectiveEvidence = $model.ObjectEvidence | Where-Object EvidenceType -eq 'SensitiveAclEffectiveTrustee'

        $target.RiskScore | Should Be 6
        $target.RelationshipCount | Should Be 2
        @($directEvidence).Count | Should Be 1
        @($effectiveEvidence).Count | Should Be 1
        $directEvidence.AggregatedFindingCount | Should Be 2
        $directEvidence.IsAggregatedAclEvidence | Should Be $true
        $directEvidence.ObjectTypeName | Should Be 'msLAPS-EncryptedPassword, msLAPS-Password'
        $directEvidence.AclFindingIds -contains 'acl-000101' | Should Be $true
        $directEvidence.AclFindingIds -contains 'acl-000102' | Should Be $true
        @($model.ObjectRelationships | Where-Object RelationshipType -eq 'WindowsLapsControl').Count | Should Be 1
        @($model.ObjectRelationships | Where-Object RelationshipType -eq 'EffectiveWindowsLapsControl').Count | Should Be 1
    }

    It 'models effective ACL exposure separately from the direct ACE trustee' {
        $aclFindings = @(
            [pscustomobject]@{
                Domain = 'contoso.local'
                AclFindingId = 'acl-000070'
                TargetName = 'AdminSDHolder'
                TargetObjectClass = 'container'
                TargetDistinguishedName = 'CN=AdminSDHolder,CN=System,DC=contoso,DC=local'
                TrusteeName = 'ACL Delegated Admins'
                TrusteeSid = 'S-1-5-21-1000-1000-1000-2500'
                TrusteeDistinguishedName = 'CN=ACL Delegated Admins,OU=Groups,DC=contoso,DC=local'
                TrusteeObjectClass = 'group'
                NormalizedRight = 'WriteDacl'
                RiskScore = 10
                Severity = 'High'
                Reason = 'Trustee can change the DACL on a sensitive AD object'
                Tags = @('SensitiveAclTarget', 'SensitiveAclTrustee')
                ActiveDirectoryRights = @('WriteDacl')
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
                EffectiveTrustees = @(
                    [pscustomobject]@{
                        Name = 'svc-deploy'
                        Sid = 'S-1-5-21-1000-1000-1000-3301'
                        DistinguishedName = 'CN=svc-deploy,OU=Service Accounts,DC=contoso,DC=local'
                        ObjectClass = 'serviceAccount'
                        NestingDepth = 1
                        Path = 'svc-deploy -> ACL Delegated Admins'
                    }
                )
            }
        )

        $model = ConvertTo-ADObjectRiskModel -Findings @() -AclFindings $aclFindings -Domain 'contoso.local'

        @($model.ObjectEvidence | Where-Object EvidenceType -eq 'SensitiveAcl').Count | Should Be 1
        @($model.ObjectEvidence | Where-Object EvidenceType -eq 'SensitiveAclEffectiveTrustee').Count | Should Be 1

        $directEvidence = $model.ObjectEvidence | Where-Object EvidenceType -eq 'SensitiveAcl'
        $effectiveEvidence = $model.ObjectEvidence | Where-Object EvidenceType -eq 'SensitiveAclEffectiveTrustee'
        $effectiveObject = $model.Objects | Where-Object DisplayName -eq 'svc-deploy'

        $directEvidence.RelatedObjectName | Should Be 'ACL Delegated Admins'
        $effectiveEvidence.DirectAclEvidenceId | Should Be $directEvidence.EvidenceId
        $effectiveEvidence.DirectTrusteeName | Should Be 'ACL Delegated Admins'
        $effectiveEvidence.EffectiveTrusteeName | Should Be 'svc-deploy'
        $effectiveEvidence.Path | Should Be 'svc-deploy -> ACL Delegated Admins -> WriteDacl -> AdminSDHolder'
        $effectiveObject.Tags -contains 'EffectiveAclExposure' | Should Be $true
        $effectiveObject.Tags -contains 'EffectiveTrustee' | Should Be $true

        @($model.ObjectRelationships | Where-Object RelationshipType -eq 'WriteDacl').Count | Should Be 1
        @($model.ObjectRelationships | Where-Object RelationshipType -eq 'EffectiveAclTrusteeMembership').Count | Should Be 1
        @($model.ObjectRelationships | Where-Object RelationshipType -eq 'EffectiveWriteDacl').Count | Should Be 1
    }
}
