BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\ConvertTo-ADAclRiskModel.ps1')
    . (Join-Path $repoRoot 'src\Private\ConvertTo-ADObjectRiskModel.ps1')
    . (Join-Path $repoRoot 'src\Private\Get-ADPostureAclTargets.ps1')
    . (Join-Path $repoRoot 'src\Private\Get-ADPostureAclPosture.ps1')

}

Describe 'ACL posture risk model' {
    It 'normalizes dangerous GenericAll ACEs' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Domain Admins'
                TargetDistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=local'
                TargetCanonicalName = 'contoso.local/Users/Domain Admins'
                TargetObjectSid = 'S-1-5-21-1000-1000-1000-512'
                TargetObjectClass = 'group'
                TrusteeName = 'Helpdesk Delegates'
                TrusteeSid = 'S-1-5-21-1000-1000-1000-2201'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].NormalizedRight | Should -Be 'GenericAll'
        $model.AclFindings[0].RiskScore | Should -Be 12.0
        $model.AclFindings[0].TargetCanonicalName | Should -Be 'contoso.local/Users/Domain Admins'
        $model.AclFindings[0].TargetPrivilegeTier | Should -Be 'Tier 0'
        $model.AclFindings[0].TargetRiskContext | Should -Be 'Tier 0 privileged target'
        $model.AclFindings[0].Tags -contains 'SensitiveAclTrustee' | Should -Be $true
        $model.AclFindings[0].Tags -contains 'SensitiveAclTarget' | Should -Be $true
        $model.AclFindings[0].Tags -contains 'Tier0Exposure' | Should -Be $true
    }

    It 'scores broad ACL findings lower on common objects than Tier 0 targets' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Target_User_01'
                TargetDistinguishedName = 'CN=Target_User_01,OU=Lab,DC=contoso,DC=local'
                TargetObjectClass = 'user'
                TrusteeName = 'CONTOSO\User_Invasor'
                TrusteeObjectClass = 'user'
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].RiskScore | Should -Be 7.2
        $model.AclFindings[0].Severity | Should -Be 'High'
        $model.AclFindings[0].TargetPrivilegeTier | Should -Be 'Tier 2'
        $model.AclFindings[0].TargetRiskContext | Should -Be 'User object'
        $model.AclFindings[0].Tags -contains 'UserAclTarget' | Should -Be $true
    }

    It 'detects DCSync replication extended rights' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'contoso.local'
                TargetDistinguishedName = 'DC=contoso,DC=local'
                TargetObjectClass = 'domainDNS'
                TrusteeName = 'Sync Operators'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].NormalizedRight | Should -Be 'DCSync'
        $model.AclFindings[0].Severity | Should -Be 'Critical'
        $model.AclFindings[0].Tags -contains 'DCSyncCapable' | Should -Be $true
        $model.AclFindings[0].Tags -contains 'Tier0Exposure' | Should -Be $true
    }

    It 'detects all extended rights represented by zero object type' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Target_User_08'
                TargetObjectClass = 'user'
                TrusteeName = 'CONTOSO\User_Invasor'
                TrusteeObjectClass = 'user'
                ActiveDirectoryRights = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].NormalizedRight | Should -Be 'AllExtendedRights'
    }

    It 'detects Windows LAPS extended rights' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Workstation-01'
                TargetDistinguishedName = 'CN=Workstation-01,OU=Workstations,DC=contoso,DC=local'
                TargetObjectClass = 'computer'
                TrusteeName = 'Helpdesk LAPS Readers'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'ReadProperty'
                AccessControlType = 'Allow'
                ObjectType = 'f3531ec6-6330-4f8e-8d39-7a671fbac605'
                ObjectTypeName = 'ms-LAPS-Encrypted-Password-Attributes'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].NormalizedRight | Should -Be 'WindowsLapsControl'
        $model.AclFindings[0].Tags -contains 'WindowsLAPS' | Should -Be $true
        $model.AclFindings[0].Tags -contains 'CredentialExposure' | Should -Be $true
        $model.AclFindings[0].ObjectTypeName | Should -Be 'ms-LAPS-Encrypted-Password-Attributes'
        $model.AclFindings[0].Reason | Should -Match 'encrypted password attribute control set'
    }

    It 'detects LAPS attribute access resolved from schema names' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'LegacyWorkstation'
                TargetObjectClass = 'computer'
                TrusteeName = 'Legacy LAPS Readers'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'ReadProperty'
                AccessControlType = 'Allow'
                ObjectType = '11111111-1111-1111-1111-111111111111'
                ObjectTypeName = 'ms-Mcs-AdmPwd'
                IsInherited = $false
            },
            [pscustomobject]@{
                TargetName = 'ModernWorkstation'
                TargetObjectClass = 'computer'
                TrusteeName = 'Windows LAPS Readers'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'ReadProperty'
                AccessControlType = 'Allow'
                ObjectType = '22222222-2222-2222-2222-222222222222'
                ObjectTypeName = 'msLAPS-Password'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 2
        @($model.AclFindings | Where-Object NormalizedRight -eq 'LegacyLapsControl').Count | Should -Be 1
        @($model.AclFindings | Where-Object NormalizedRight -eq 'WindowsLapsControl').Count | Should -Be 1
        ($model.AclFindings | Where-Object NormalizedRight -eq 'LegacyLapsControl').Reason | Should -Match 'clear-text local administrator password'
        ($model.AclFindings | Where-Object NormalizedRight -eq 'WindowsLapsControl').Reason | Should -Match 'Windows LAPS password attribute'
    }

    It 'uses distinct Windows LAPS reasons for different attributes' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'LapsNovo'
                TargetObjectClass = 'organizationalUnit'
                TrusteeName = 'LAPS Readers'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'ReadProperty'
                AccessControlType = 'Allow'
                ObjectType = '11111111-1111-1111-1111-111111111111'
                ObjectTypeName = 'msLAPS-EncryptedPassword'
                IsInherited = $false
            },
            [pscustomobject]@{
                TargetName = 'LapsNovo'
                TargetObjectClass = 'organizationalUnit'
                TrusteeName = 'LAPS Readers'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'ReadProperty'
                AccessControlType = 'Allow'
                ObjectType = '22222222-2222-2222-2222-222222222222'
                ObjectTypeName = 'msLAPS-PasswordExpirationTime'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 2
        ($model.AclFindings | Where-Object ObjectTypeName -eq 'msLAPS-EncryptedPassword').Reason | Should -Match 'encrypted password blob'
        ($model.AclFindings | Where-Object ObjectTypeName -eq 'msLAPS-PasswordExpirationTime').Reason | Should -Match 'password expiration attribute'
    }

    It 'detects sensitive membership and SPN write properties' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Domain Admins'
                TargetObjectClass = 'group'
                TrusteeName = 'Group Operators'
                ActiveDirectoryRights = 'WriteProperty'
                AccessControlType = 'Allow'
                ObjectType = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
                IsInherited = $false
            },
            [pscustomobject]@{
                TargetName = 'Privileged Service'
                TargetObjectClass = 'user'
                TrusteeName = 'SPN Operators'
                ActiveDirectoryRights = 'WriteProperty'
                AccessControlType = 'Allow'
                ObjectType = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 2
        @($model.AclFindings | Where-Object NormalizedRight -eq 'WriteMembership').Count | Should -Be 1
        @($model.AclFindings | Where-Object NormalizedRight -eq 'WriteSPN').Count | Should -Be 1
    }

    It 'detects unexpected owners on privileged objects' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'AXZ'
                TargetDistinguishedName = 'CN=AXZ,CN=Users,DC=contoso,DC=local'
                TargetObjectClass = 'user'
                OwnerName = 'CONTOSO\HelpdeskUser'
                OwnerSid = 'S-1-5-21-1000-1000-1000-4401'
                OwnerDistinguishedName = 'CN=HelpdeskUser,OU=Helpdesk,DC=contoso,DC=local'
                OwnerObjectClass = 'user'
                ActiveDirectoryRights = 'Owner'
                AccessControlType = 'Owner'
                SourceDescriptorId = 'CN=AXZ,CN=Users,DC=contoso,DC=local'
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].NormalizedRight | Should -Be 'ObjectOwner'
        $model.AclFindings[0].EvidenceType | Should -Be 'SensitiveAclOwner'
        $model.AclFindings[0].OwnerName | Should -Be 'CONTOSO\HelpdeskUser'
        $model.AclFindings[0].OwnerSid | Should -Be 'S-1-5-21-1000-1000-1000-4401'
        $model.AclFindings[0].OwnerDistinguishedName | Should -Be 'CN=HelpdeskUser,OU=Helpdesk,DC=contoso,DC=local'
        $model.AclFindings[0].TrusteeDistinguishedName | Should -Be 'CN=HelpdeskUser,OU=Helpdesk,DC=contoso,DC=local'
        $model.AclFindings[0].SourceDescriptorId | Should -Be 'CN=AXZ,CN=Users,DC=contoso,DC=local'
        $model.AclFindings[0].Tags -contains 'UnexpectedOwner' | Should -Be $true
    }

    It 'falls back to target DN as source descriptor for owner findings' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'AXZ'
                TargetDistinguishedName = 'CN=AXZ,CN=Users,DC=contoso,DC=local'
                TargetObjectClass = 'user'
                OwnerName = 'CONTOSO\HelpdeskUser'
                ActiveDirectoryRights = 'Owner'
                AccessControlType = 'Owner'
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].SourceDescriptorId | Should -Be 'CN=AXZ,CN=Users,DC=contoso,DC=local'
    }

    It 'does not flag expected built-in owners' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Domain Admins'
                TargetObjectClass = 'group'
                OwnerName = 'CONTOSO\Domain Admins'
                ActiveDirectoryRights = 'Owner'
                AccessControlType = 'Owner'
            }
        )

        @($model.AclFindings).Count | Should -Be 0
    }

    It 'does not flag expected built-in ACL trustees' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Domain Admins'
                TargetObjectClass = 'group'
                TrusteeName = 'NT AUTHORITY\SYSTEM'
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            },
            [pscustomobject]@{
                TargetName = 'Domain Admins'
                TargetObjectClass = 'group'
                TrusteeName = 'BUILTIN\Administrators'
                ActiveDirectoryRights = 'WriteDacl'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            },
            [pscustomobject]@{
                TargetName = 'contoso.local'
                TargetObjectClass = 'domainDNS'
                TrusteeName = 'CONTOSO\Domain Controllers'
                ActiveDirectoryRights = 'ExtendedRight'
                AccessControlType = 'Allow'
                ObjectType = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                IsInherited = $false
            },
            [pscustomobject]@{
                TargetName = 'Group Policy Creator Owners'
                TargetObjectClass = 'group'
                TrusteeName = 'BUILTIN\Account Operators'
                ActiveDirectoryRights = 'WriteDacl'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            },
            [pscustomobject]@{
                TargetName = 'OU=Tier0'
                TargetObjectClass = 'organizationalUnit'
                TrusteeName = 'CREATOR OWNER'
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $true
            }
        )

        @($model.AclFindings).Count | Should -Be 0
    }

    It 'still flags custom ACL trustees on built-in targets' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Domain Admins'
                TargetObjectClass = 'group'
                TrusteeName = 'CONTOSO\Helpdesk Delegates'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'WriteDacl'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].TrusteeName | Should -Be 'CONTOSO\Helpdesk Delegates'
        $model.AclFindings[0].NormalizedRight | Should -Be 'WriteDacl'
    }

    It 'preserves raw trustee strings and marks SID-only trustees as unresolved' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Domain Admins'
                TargetObjectClass = 'group'
                IdentityReference = 'S-1-5-21-1000-1000-1000-8899'
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].TrusteeSid | Should -Be 'S-1-5-21-1000-1000-1000-8899'
        $model.AclFindings[0].RawTrustee | Should -Be 'S-1-5-21-1000-1000-1000-8899'
        $model.AclFindings[0].UnresolvedTrustee | Should -Be $true
        $model.AclFindings[0].Tags -contains 'UnresolvedTrustee' | Should -Be $true
    }

    It 'keeps resolved trustee metadata when supplied by the collector' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'Target_User_02'
                TargetObjectClass = 'user'
                TrusteeName = 'CONTOSO\Helpdesk Delegates'
                TrusteeSid = 'S-1-5-21-1000-1000-1000-2201'
                TrusteeDistinguishedName = 'CN=Helpdesk Delegates,OU=Groups,DC=contoso,DC=local'
                TrusteeObjectClass = 'group'
                RawTrustee = 'CONTOSO\Helpdesk Delegates'
                ActiveDirectoryRights = 'GenericWrite'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        $model.AclFindings[0].TrusteeSid | Should -Be 'S-1-5-21-1000-1000-1000-2201'
        $model.AclFindings[0].TrusteeDistinguishedName | Should -Be 'CN=Helpdesk Delegates,OU=Groups,DC=contoso,DC=local'
        $model.AclFindings[0].TrusteeObjectClass | Should -Be 'group'
        $model.AclFindings[0].UnresolvedTrustee | Should -Be $false
    }

    It 'preserves collector-supplied effective trustees on ACL findings' {
        $model = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'AdminSDHolder'
                TargetObjectClass = 'container'
                TrusteeName = 'ACL Delegated Admins'
                TrusteeObjectClass = 'group'
                EffectiveTrustees = @(
                    [pscustomobject]@{
                        Name = 'svc-deploy'
                        Sid = 'S-1-5-21-1000-1000-1000-3301'
                        DistinguishedName = 'CN=svc-deploy,OU=Service Accounts,DC=contoso,DC=local'
                        ObjectClass = 'serviceAccount'
                    }
                )
                ActiveDirectoryRights = 'WriteDacl'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        @($model.AclFindings).Count | Should -Be 1
        @($model.AclFindings[0].EffectiveTrustees).Count | Should -Be 1
        $model.AclFindings[0].EffectiveTrustees[0].Name | Should -Be 'svc-deploy'
        $model.AclFindings[0].FindingType | Should -Be 'AdminSDHolderDelegationControl'
        $model.AclFindings[0].NormalizedRight | Should -Be 'WriteDacl'
        $model.AclFindings[0].TargetRiskContext | Should -Be 'AdminSDHolder protected-object ACL template'
        $model.AclFindings[0].PropagationMechanism | Should -Be 'SDProp'
        $model.AclFindings[0].Tags -contains 'AdminSDHolder' | Should -Be $true
        $model.AclFindings[0].Tags -contains 'SDProp' | Should -Be $true
        $model.AclFindings[0].Reason | Should -Match 'adminCount=1'
    }

    It 'adds ACL evidence and relationships to object risk summaries' {
        $acl = ConvertTo-ADAclRiskModel -Domain 'contoso.local' -AccessRules @(
            [pscustomobject]@{
                TargetName = 'AdminSDHolder'
                TargetDistinguishedName = 'CN=AdminSDHolder,CN=System,DC=contoso,DC=local'
                TargetObjectClass = 'container'
                TrusteeName = 'Legacy Admins'
                TrusteeObjectClass = 'group'
                ActiveDirectoryRights = 'WriteDacl'
                AccessControlType = 'Allow'
                ObjectType = '00000000-0000-0000-0000-000000000000'
                IsInherited = $false
            }
        )

        $objectModel = ConvertTo-ADObjectRiskModel -Findings @() -AclFindings @($acl.AclFindings) -Domain 'contoso.local'

        @($objectModel.Objects).Count | Should -Be 2
        @($objectModel.ObjectEvidence).Count | Should -Be 1
        @($objectModel.ObjectRelationships).Count | Should -Be 1
        $objectModel.ObjectEvidence[0].EvidenceType | Should -Be 'SensitiveAcl'
        $objectModel.ObjectRelationships[0].RelationshipType | Should -Be 'WriteDacl'

        $target = $objectModel.Objects | Where-Object DisplayName -eq 'AdminSDHolder'
        $target.Tags -contains 'SensitiveAclTarget' | Should -Be $true
        $target.Tags -contains 'SDProp' | Should -Be $true
        $target.RiskScore | Should -Be 10.0
    }
}

Describe 'ACL posture target discovery' {
    It 'deduplicates base ACL targets by distinguished name' {
        $domain = [pscustomobject]@{
            DNSRoot = 'contoso.local'
            DistinguishedName = 'DC=contoso,DC=local'
        }
        $baseTargets = @(
            [pscustomobject]@{
                Name = 'Domain Admins'
                DistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=local'
                ObjectSid = 'S-1-5-21-1000-1000-1000-512'
                ObjectGuid = $null
                ObjectClass = 'group'
            },
            [pscustomobject]@{
                Name = 'Domain Admins duplicate'
                DistinguishedName = 'cn=domain admins,cn=users,dc=contoso,dc=local'
                ObjectSid = 'S-1-5-21-1000-1000-1000-512'
                ObjectGuid = $null
                ObjectClass = 'group'
            }
        )

        $targets = Get-ADPostureAclTargets -BaseTargets $baseTargets -Domain $domain -DomainParams @{}

        @($targets).Count | Should -Be 1
        $targets[0].Name | Should -Be 'Domain Admins'
    }

    It 'normalizes synthetic AD objects into ACL targets without requiring live AD' {
        $object = [pscustomobject]@{
            Name = 'AXZ'
            DistinguishedName = 'CN=AXZ,CN=Users,DC=contoso,DC=local'
            SID = [pscustomobject]@{ Value = 'S-1-5-21-1000-1000-1000-5001' }
            ObjectGUID = [guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            ObjectClass = @('top', 'person', 'organizationalPerson', 'user')
            CanonicalName = 'contoso.local/Users/AXZ'
        }

        $target = ConvertTo-ADPostureAclTarget -InputObject $object -TargetType 'user'

        $target.Name | Should -Be 'AXZ'
        $target.DistinguishedName | Should -Be 'CN=AXZ,CN=Users,DC=contoso,DC=local'
        $target.CanonicalName | Should -Be 'contoso.local/Users/AXZ'
        $target.ObjectSid | Should -Be 'S-1-5-21-1000-1000-1000-5001'
        $target.ObjectClass | Should -Be 'user'
        $target.AclTargetType | Should -Be 'user'
    }

    It 'exposes broad ACL target discovery switches' {
        $command = Get-Command Get-ADPostureAclTargets

        $command.Parameters.ContainsKey('IncludeAllObjects') | Should -Be $true
        $command.Parameters.ContainsKey('SearchBase') | Should -Be $true
    }

    It 'keeps ACL collection pacing and effective expansion tunable' {
        $command = Get-Command Get-ADPostureAclPosture

        $command.Parameters.ContainsKey('ReadDelayMilliseconds') | Should -Be $true
        $command.Parameters.ContainsKey('EffectiveTrusteeLimit') | Should -Be $true
    }

    It 'disables effective trustee expansion when the limit is zero' {
        $trustee = [pscustomobject]@{
            Name = 'Domain Admins'
            DistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=local'
            ObjectClass = 'group'
        }

        $effective = Resolve-ADPostureAclEffectiveTrustees -Trustee $trustee -Limit 0

        @($effective).Count | Should -Be 0
    }

    It 'uses a bounded paged LDAP query for recursive effective trustees' {
        $source = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'src\Private\Get-ADPostureAclPosture.ps1')

        $source | Should -Match '1\.2\.840\.113556\.1\.4\.1941'
        $source | Should -Match '-ResultSetSize \$Limit'
        $source | Should -Not -Match 'Get-ADGroupMember\s+-Identity\s+\$Trustee\.DistinguishedName\s+-Recursive'
    }

    It 'uses ObjectSid for generic AD object target discovery' {
        $source = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'src\Private\Get-ADPostureAclTargets.ps1')

        $source | Should -Match 'DisplayName,ObjectSid,ObjectGUID,ObjectClass,CanonicalName'
        $source | Should -Not -Match 'DisplayName,SID,ObjectGUID,ObjectClass'
    }

    It 'normalizes synthetic effective trustees without requiring live AD' {
        $member = [pscustomobject]@{
            SamAccountName = 'svc-deploy'
            DistinguishedName = 'CN=svc-deploy,OU=Service Accounts,DC=contoso,DC=local'
            SID = [pscustomobject]@{ Value = 'S-1-5-21-1000-1000-1000-3301' }
            ObjectClass = @('top', 'person', 'organizationalPerson', 'user')
        }

        $effective = ConvertTo-ADPostureAclEffectiveTrustee -InputObject $member -DirectTrusteeName 'ACL Delegated Admins'

        $effective.Name | Should -Be 'svc-deploy'
        $effective.Sid | Should -Be 'S-1-5-21-1000-1000-1000-3301'
        $effective.DistinguishedName | Should -Be 'CN=svc-deploy,OU=Service Accounts,DC=contoso,DC=local'
        $effective.ObjectClass | Should -Be 'user'
        $effective.Path | Should -Be 'svc-deploy -> ACL Delegated Admins'
    }
}

Describe 'ACL trustee resolution' {
    It 'keeps name-only trustees as named rather than unresolved' {
        $trustee = Resolve-ADPostureAclTrustee -IdentityReference 'CONTOSO\Helpdesk Delegates' -DomainParams @{} -Cache @{}

        $trustee.Name | Should -Be 'CONTOSO\Helpdesk Delegates'
        $trustee.Raw | Should -Be 'CONTOSO\Helpdesk Delegates'
        $trustee.Sid | Should -Be $null
        $trustee.IsUnresolved | Should -Be $false
    }

    It 'marks deleted account trustees with embedded SIDs as unresolved' {
        $trustee = Resolve-ADPostureAclTrustee -IdentityReference 'Account Unknown(S-1-5-21-1000-1000-1000-8899)' -DomainParams @{} -Cache @{}

        $trustee.Raw | Should -Be 'Account Unknown(S-1-5-21-1000-1000-1000-8899)'
        $trustee.Sid | Should -Be 'S-1-5-21-1000-1000-1000-8899'
        $trustee.IsUnresolved | Should -Be $true
    }
}
