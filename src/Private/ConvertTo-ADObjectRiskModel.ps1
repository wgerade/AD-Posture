function New-ADObjectRiskObjectId {
    param(
        [string]$Domain,
        [string]$ObjectSid,
        [string]$DistinguishedName,
        [string]$Name,
        [string]$Prefix = 'object'
    )

    $domainPart = if ($Domain) { $Domain.ToLowerInvariant() } else { 'unknown-domain' }
    if ($ObjectSid) { return "${domainPart}:sid:$ObjectSid" }
    if ($DistinguishedName) { return "${domainPart}:dn:$($DistinguishedName.ToLowerInvariant())" }
    if ($Name) { return "${domainPart}:${Prefix}:$($Name.ToLowerInvariant())" }
    "${domainPart}:${Prefix}:unknown"
}

function Add-ADObjectRiskTag {
    param(
        [Parameter(Mandatory)]
        [hashtable]$TagSet,
        [string]$Tag
    )

    if ($Tag) { $TagSet[$Tag] = $true }
}

function Get-ADObjectRiskSeverity {
    param([double]$Score)

    if ($Score -ge 15) { return 'Critical' }
    if ($Score -ge 5) { return 'High' }
    if ($Score -gt 0.5) { return 'Medium' }
    if ($Score -gt 0) { return 'Low' }
    'Informational'
}

function Get-ADObjectRiskAclEffectiveTrustees {
    param($AclFinding)

    $values = @()
    foreach ($propertyName in @('EffectiveTrustees', 'EffectiveMembers')) {
        if ($AclFinding.PSObject.Properties[$propertyName] -and $AclFinding.$propertyName) {
            $values += @($AclFinding.$propertyName)
        }
    }

    @($values | Where-Object { $_ })
}

function Get-ADObjectRiskAclEffectiveTrusteeClass {
    param($Trustee)

    $class = if ($Trustee.ObjectClass) { [string]$Trustee.ObjectClass } elseif ($Trustee.AccountType) { [string]$Trustee.AccountType } else { 'unknown' }
    $sid = if ($Trustee.ObjectSid) { [string]$Trustee.ObjectSid } elseif ($Trustee.Sid) { [string]$Trustee.Sid } else { $null }
    $name = (([string]$Trustee.Name), ([string]$Trustee.SamAccountName), ([string]$Trustee.DisplayName) | Where-Object { $_ }) -join ' '
    if (Test-ADObjectRiskBroadAclTrustee -Name $name -Sid $sid) { return 'wellKnownPrincipal' }
    if ($class -match '^ServiceAccount') { return 'serviceAccount' }
    if ($class -match '^Computer') { return 'computer' }
    if ($class -match '^Group') { return 'group' }
    if ($class -match '^User') { return 'user' }
    $class
}

function Test-ADObjectRiskBroadAclTrustee {
    param(
        [string]$Name,
        [string]$Sid
    )

    if ($Sid -in @('S-1-1-0', 'S-1-5-7', 'S-1-5-11')) { return $true }
    if ($Name -match '^(?i:(NT AUTHORITY\\)?Authenticated Users|Everyone|NT AUTHORITY\\Anonymous Logon|Anonymous Logon)$') { return $true }
    $false
}

function Get-ADObjectRiskAclTrusteeClass {
    param($AclFinding)

    if (Test-ADObjectRiskBroadAclTrustee -Name ([string]$AclFinding.TrusteeName) -Sid ([string]$AclFinding.TrusteeSid)) {
        return 'wellKnownPrincipal'
    }
    if ($AclFinding.TrusteeObjectClass) { return [string]$AclFinding.TrusteeObjectClass }
    'unknown'
}

function Get-ADObjectRiskAclTargetDisplayName {
    param($AclFinding)

    $name = if ($AclFinding.TargetName) { [string]$AclFinding.TargetName } else { 'Unknown target' }
    if ([string]$AclFinding.TargetObjectClass -eq 'groupPolicyContainer' -and $name -notmatch '^(?i:GPO:)') {
        return "GPO: $name"
    }
    $name
}

function Test-ADObjectRiskAclShouldAggregate {
    param($AclFinding)

    [string]$AclFinding.NormalizedRight -in @(
        'LegacyLapsControl',
        'WindowsLapsControl',
        'SecretAttributeAccess'
    )
}

function Get-ADObjectRiskAclAggregationKey {
    param($AclFinding)

    @(
        $AclFinding.Domain
        $AclFinding.TargetObjectSid
        $AclFinding.TargetDistinguishedName
        $AclFinding.TargetName
        $AclFinding.TrusteeSid
        $AclFinding.TrusteeDistinguishedName
        $AclFinding.TrusteeName
        $AclFinding.NormalizedRight
        $AclFinding.AccessControlType
        $AclFinding.InheritanceType
        $AclFinding.InheritedObjectType
        [bool]$AclFinding.IsInherited
    ) -join '|'
}

function Merge-ADObjectRiskAclFindingsForObjectModel {
    [CmdletBinding()]
    param([object[]]$AclFindings = @())

    $merged = [ordered]@{}
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($aclFinding in @($AclFindings)) {
        if (-not (Test-ADObjectRiskAclShouldAggregate -AclFinding $aclFinding)) {
            $results.Add($aclFinding)
            continue
        }

        $key = Get-ADObjectRiskAclAggregationKey -AclFinding $aclFinding
        if (-not $merged.Contains($key)) {
            $copy = [ordered]@{}
            foreach ($property in $aclFinding.PSObject.Properties) {
                $copy[$property.Name] = $property.Value
            }
            $copy['AclFindingIds'] = @($aclFinding.AclFindingId)
            $copy['ObjectTypes'] = @($aclFinding.ObjectType | Where-Object { $_ })
            $copy['ObjectTypeNames'] = @($aclFinding.ObjectTypeName | Where-Object { $_ })
            $copy['ActiveDirectoryRights'] = @($aclFinding.ActiveDirectoryRights)
            $copy['AggregatedFindingCount'] = 1
            $copy['IsAggregatedAclEvidence'] = $true
            $merged[$key] = [pscustomobject]$copy
            continue
        }

        $existing = $merged[$key]
        $existing.AclFindingIds = @($existing.AclFindingIds + $aclFinding.AclFindingId | Where-Object { $_ } | Sort-Object -Unique)
        $existing.ObjectTypes = @($existing.ObjectTypes + $aclFinding.ObjectType | Where-Object { $_ } | Sort-Object -Unique)
        $existing.ObjectTypeNames = @($existing.ObjectTypeNames + $aclFinding.ObjectTypeName | Where-Object { $_ } | Sort-Object -Unique)
        $existing.ActiveDirectoryRights = @($existing.ActiveDirectoryRights + @($aclFinding.ActiveDirectoryRights) | Where-Object { $_ } | Sort-Object -Unique)
        $existing.AggregatedFindingCount = [int]$existing.AggregatedFindingCount + 1
        $existing.RiskScore = [Math]::Max([double]$existing.RiskScore, [double]$aclFinding.RiskScore)
        if ($existing.ObjectTypeNames.Count -gt 1) {
            $existing.ObjectTypeName = ($existing.ObjectTypeNames -join ', ')
        }
        if ($existing.ObjectTypes.Count -gt 1) {
            $existing.ObjectType = ($existing.ObjectTypes -join ', ')
        }
    }

    foreach ($entry in $merged.GetEnumerator()) {
        $finding = $entry.Value
        if ($finding.ObjectTypeNames.Count -gt 1) {
            $finding.Reason = "$($finding.Reason) Aggregated attributes: $($finding.ObjectTypeNames -join ', ')."
        }
        $results.Add($finding)
    }

    @($results)
}

function Get-ADObjectRiskTagsFromFinding {
    param($Finding)

    $tags = @{}
    if ($Finding.PrivilegeTier -eq 'Tier 0') { Add-ADObjectRiskTag -TagSet $tags -Tag 'Tier0Exposure' }
    if ($Finding.SensitiveGroup) { Add-ADObjectRiskTag -TagSet $tags -Tag 'PrivilegedMembership' }
    if ($Finding.NestingDepth -gt 0 -or $Finding.IsDirect -eq $false) { Add-ADObjectRiskTag -TagSet $tags -Tag 'IndirectPrivilege' }
    if ($Finding.IsStale) { Add-ADObjectRiskTag -TagSet $tags -Tag 'StaleIdentity' }
    if ($Finding.PasswordNeverExpires) { Add-ADObjectRiskTag -TagSet $tags -Tag 'PasswordNeverExpires' }
    if ($Finding.IsPasswordStale) { Add-ADObjectRiskTag -TagSet $tags -Tag 'PasswordAge' }
    if ($Finding.AccountType -match '^ServiceAccount') { Add-ADObjectRiskTag -TagSet $tags -Tag 'ServiceAccount' }
    if ($Finding.AccountType -match '^Group') { Add-ADObjectRiskTag -TagSet $tags -Tag 'NestedGroup' }
    if ($Finding.AccountType -match '^Computer') { Add-ADObjectRiskTag -TagSet $tags -Tag 'ComputerIdentity' }
    if ($Finding.IsDisabled) { Add-ADObjectRiskTag -TagSet $tags -Tag 'DisabledIdentity' }
    if ($Finding.UacActiveFlagNames -match 'DONT_REQ_PREAUTH') { Add-ADObjectRiskTag -TagSet $tags -Tag 'NoPreAuth' }
    if ($Finding.UacActiveFlagNames -match 'TRUSTED_FOR_DELEGATION|TRUSTED_TO_AUTH_FOR_DELEGATION') { Add-ADObjectRiskTag -TagSet $tags -Tag 'DelegationRisk' }
    if ($Finding.UacActiveFlagNames -match 'USE_DES_KEY_ONLY') { Add-ADObjectRiskTag -TagSet $tags -Tag 'WeakKerberos' }
    if ($Finding.UserAccountControlSummary -match 'Pre-Auth') { Add-ADObjectRiskTag -TagSet $tags -Tag 'NoPreAuth' }
    if ($Finding.UserAccountControlSummary -match 'Delegation') { Add-ADObjectRiskTag -TagSet $tags -Tag 'DelegationRisk' }
    if ($Finding.UserAccountControlSummary -match 'DES') { Add-ADObjectRiskTag -TagSet $tags -Tag 'WeakKerberos' }

    @($tags.Keys | Sort-Object)
}

function Test-ADObjectRiskNativeArchitectureObject {
    param(
        $Object,
        [string]$NameProperty = 'MemberSam',
        [string]$DisplayProperty = 'MemberDisplay',
        [string]$SidProperty = 'ObjectSid'
    )

    if (-not $Object) { return $false }
    if ($Object.IsExcluded -or $Object.IsNativeIdentity -or $Object.IsRemediableIdentity -eq $false) { return $true }

    $sid = [string]$Object.$SidProperty
    if ($sid -match '^S-1-5-32-' -or $sid -match '^S-1-5-21-.+-(500|501|502|512|513|514|515|516|517|518|519|520|521|522|525|526|527|548|549|550|551|553|571|572)$') {
        return $true
    }

    $name = (([string]$Object.$NameProperty), ([string]$Object.$DisplayProperty), ([string]$Object.SamAccountName), ([string]$Object.DisplayName) | Where-Object { $_ }) -join ' '
    if ($name -match '^(?i:administrator|guest|krbtgt)$') { return $true }
    if ($name -match '(?i)\b(domain admins|enterprise admins|schema admins|domain users|domain guests|domain computers|domain controllers|read-only domain controllers|cloneable domain controllers|group policy creator owners|cert publishers|key admins|enterprise key admins|protected users|account operators|server operators|print operators|backup operators)\b') {
        return $true
    }

    $false
}

function ConvertTo-ADObjectRiskModel {
    [CmdletBinding()]
    param(
        [object[]]$Findings = @(),
        [object[]]$AclFindings = @(),
        [object[]]$KerberosAuthFindings = @(),
        [object[]]$TrustFindings = @(),
        [object[]]$DnsFindings = @(),
        [object[]]$IdentityRiskFindings = @(),
        [string]$Domain
    )

    $objectMap = @{}
    $evidence = [System.Collections.Generic.List[object]]::new()
    $relationships = [System.Collections.Generic.List[object]]::new()
    $relationshipKeys = @{}
    $evidenceIndex = 0

    function Ensure-ObjectSummary {
        param(
            [string]$ObjectId,
            [string]$ObjectClass,
            [string]$SamAccountName,
            [string]$DisplayName,
            [string]$DistinguishedName,
            [string]$ObjectSid,
            [string]$SourceDomain,
            [string]$AccountType,
            [string]$PrivilegeTier,
            [string]$PrivilegeTierReason,
            [string]$Role
        )

        if (-not $objectMap.ContainsKey($ObjectId)) {
            $objectMap[$ObjectId] = [ordered]@{
                ObjectId              = $ObjectId
                Domain                = $SourceDomain
                ObjectClass           = $ObjectClass
                SamAccountName        = $SamAccountName
                DisplayName           = $DisplayName
                DistinguishedName     = $DistinguishedName
                ObjectSid             = $ObjectSid
                AccountType           = $AccountType
                PrivilegeTier         = $PrivilegeTier
                PrivilegeTierReason   = $PrivilegeTierReason
                RiskScore             = 0.0
                Severity              = 'Informational'
                Tags                  = @()
                EvidenceIds           = [System.Collections.Generic.List[string]]::new()
                RelationshipCount     = 0
                HighestEvidenceScore  = 0.0
                TopReason             = $null
                IsExcluded            = $false
                IsApprovedException   = $false
                RemediationDifficulty = $null
                CleanupActions        = $null
                _TagSet               = @{}
                ObjectRoles           = @()
                _RoleSet              = @{}
            }
        }

        if ($Role) {
            $objectMap[$ObjectId]._RoleSet[$Role] = $true
        }

        $objectMap[$ObjectId]
    }

    foreach ($finding in @($Findings)) {
        if ((Test-ADObjectRiskNativeArchitectureObject -Object $finding) -or [double]($finding.RiskScore) -le 0) {
            continue
        }

        $sourceDomain = if ($finding.Domain) { $finding.Domain } elseif ($Domain) { $Domain } else { 'unknown-domain' }
        $memberObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -ObjectSid $finding.ObjectSid -DistinguishedName $finding.MemberDn -Name $finding.MemberSam
        $groupObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -Name $finding.SensitiveGroup -Prefix 'sensitive-group'
        $memberClass = if ($finding.AccountType -match '^Group') { 'group' } elseif ($finding.AccountType -match '^Computer') { 'computer' } elseif ($finding.AccountType -match '^ServiceAccount') { 'serviceAccount' } elseif ($finding.AccountType) { 'user' } else { 'unknown' }

        $member = Ensure-ObjectSummary -ObjectId $memberObjectId `
            -ObjectClass $memberClass `
            -SamAccountName $finding.MemberSam `
            -DisplayName $finding.MemberDisplay `
            -DistinguishedName $finding.MemberDn `
            -ObjectSid $finding.ObjectSid `
            -SourceDomain $sourceDomain `
            -AccountType $finding.AccountType `
            -PrivilegeTier $finding.PrivilegeTier `
            -PrivilegeTierReason $finding.PrivilegeTierReason `
            -Role 'SensitiveGroupMember'

        $riskScore = [double]($finding.RiskScore)
        $tags = Get-ADObjectRiskTagsFromFinding -Finding $finding
        foreach ($tag in $tags) {
            Add-ADObjectRiskTag -TagSet $member._TagSet -Tag $tag
        }

        $evidenceIndex++
        $evidenceId = 'ev-{0:000000}' -f $evidenceIndex
        $reason = if ($finding.TechnicalRisk) {
            $finding.TechnicalRisk
        }
        elseif ($finding.MembershipChain) {
            "Membership path to $($finding.SensitiveGroup): $($finding.MembershipChain)"
        }
        else {
            "Sensitive group membership: $($finding.SensitiveGroup)"
        }

        $evidence.Add([PSCustomObject]@{
            EvidenceId            = $evidenceId
            ObjectId              = $memberObjectId
            EvidenceType          = 'SensitiveGroupMembership'
            SourceDomain          = 'SensitiveGroups'
            Score                 = [Math]::Round($riskScore, 2)
            Severity              = Get-ADObjectRiskSeverity -Score $riskScore
            Reason                = $reason
            Remediation           = $finding.CleanupActions
            RelatedObjectId       = $groupObjectId
            RelatedObjectName     = $finding.SensitiveGroup
            PrivilegeTier         = $finding.PrivilegeTier
            IsDirect              = $finding.IsDirect
            NestingDepth          = $finding.NestingDepth
            Path                  = $finding.MembershipChain
            ScoreFormula          = $finding.ScoreFormula
            ScoreComponents       = @($finding.ScoreComponents)
            AttackTechniques      = @($finding.AttackTechniques)
            IsExcluded            = [bool]$finding.IsExcluded
            IsApprovedException   = [bool]$finding.IsApprovedException
        })

        $member.EvidenceIds.Add($evidenceId)
        $member.RiskScore = [Math]::Round(([double]$member.RiskScore + $riskScore), 2)
        if ($riskScore -gt [double]$member.HighestEvidenceScore) {
            $member.HighestEvidenceScore = [Math]::Round($riskScore, 2)
            $member.TopReason = $reason
        }
        if ($finding.IsExcluded) { $member.IsExcluded = $true }
        if ($finding.IsApprovedException) { $member.IsApprovedException = $true }
        if ($finding.RemediationDifficulty) { $member.RemediationDifficulty = $finding.RemediationDifficulty }
        if ($finding.CleanupActions) { $member.CleanupActions = $finding.CleanupActions }

        $relationshipKey = "$memberObjectId|$groupObjectId|SensitiveGroupMembership|$($finding.MembershipChain)"
        if (-not $relationshipKeys.ContainsKey($relationshipKey)) {
            $relationshipKeys[$relationshipKey] = $true
            $relationships.Add([PSCustomObject]@{
                FromObjectId      = $memberObjectId
                ToObjectId        = $groupObjectId
                RelationshipType  = 'SensitiveGroupMembership'
                SourceDomain      = 'SensitiveGroups'
                RelationshipName  = $finding.SensitiveGroup
                IsDirect          = $finding.IsDirect
                NestingDepth      = $finding.NestingDepth
                Path              = $finding.MembershipChain
                EvidenceId        = $evidenceId
                IsInherited       = $false
            })
            $member.RelationshipCount++
        }
    }

    foreach ($aclFinding in @(Merge-ADObjectRiskAclFindingsForObjectModel -AclFindings $AclFindings)) {
        $sourceDomain = if ($aclFinding.Domain) { $aclFinding.Domain } elseif ($Domain) { $Domain } else { 'unknown-domain' }
        $trusteeObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -ObjectSid $aclFinding.TrusteeSid -DistinguishedName $aclFinding.TrusteeDistinguishedName -Name $aclFinding.TrusteeName -Prefix 'acl-trustee'
        $targetObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -ObjectSid $aclFinding.TargetObjectSid -DistinguishedName $aclFinding.TargetDistinguishedName -Name $aclFinding.TargetName -Prefix 'acl-target'
        $trusteeObjectClass = Get-ADObjectRiskAclTrusteeClass -AclFinding $aclFinding
        $targetDisplayName = Get-ADObjectRiskAclTargetDisplayName -AclFinding $aclFinding

        $trustee = Ensure-ObjectSummary -ObjectId $trusteeObjectId `
            -ObjectClass $trusteeObjectClass `
            -SamAccountName $aclFinding.TrusteeName `
            -DisplayName $aclFinding.TrusteeName `
            -DistinguishedName $aclFinding.TrusteeDistinguishedName `
            -ObjectSid $aclFinding.TrusteeSid `
            -SourceDomain $sourceDomain `
            -AccountType $trusteeObjectClass `
            -PrivilegeTier $(if ($aclFinding.TargetPrivilegeTier) { $aclFinding.TargetPrivilegeTier } elseif (@($aclFinding.Tags) -contains 'Tier0Exposure') { 'Tier 0' } else { 'Unknown' }) `
            -PrivilegeTierReason $aclFinding.NormalizedRight `
            -Role 'AclTrustee'

        $target = Ensure-ObjectSummary -ObjectId $targetObjectId `
            -ObjectClass $aclFinding.TargetObjectClass `
            -SamAccountName $aclFinding.TargetName `
            -DisplayName $targetDisplayName `
            -DistinguishedName $aclFinding.TargetDistinguishedName `
            -ObjectSid $aclFinding.TargetObjectSid `
            -SourceDomain $sourceDomain `
            -AccountType $aclFinding.TargetObjectClass `
            -PrivilegeTier $(if ($aclFinding.TargetPrivilegeTier) { $aclFinding.TargetPrivilegeTier } elseif (@($aclFinding.Tags) -contains 'Tier0Exposure') { 'Tier 0' } else { 'Unknown' }) `
            -PrivilegeTierReason $(if ($aclFinding.TargetRiskContext) { $aclFinding.TargetRiskContext } else { $aclFinding.NormalizedRight }) `
            -Role 'AclTarget'

        foreach ($tag in @($aclFinding.Tags)) {
            Add-ADObjectRiskTag -TagSet $trustee._TagSet -Tag $tag
            Add-ADObjectRiskTag -TagSet $target._TagSet -Tag $tag
        }
        if ($trusteeObjectClass -eq 'wellKnownPrincipal') {
            Add-ADObjectRiskTag -TagSet $trustee._TagSet -Tag 'BroadTrustee'
        }

        $riskScore = if ($aclFinding.IsApprovedException -and $aclFinding.ApprovedExceptionStatus -eq 'Active') {
            0.0
        }
        else {
            [double]$aclFinding.RiskScore
        }
        $evidenceIndex++
        $evidenceId = 'ev-{0:000000}' -f $evidenceIndex
        $path = "$($aclFinding.TrusteeName) -> $($aclFinding.NormalizedRight) -> $targetDisplayName"

        $evidence.Add([PSCustomObject]@{
            EvidenceId            = $evidenceId
            ObjectId              = $targetObjectId
            EvidenceType          = if ($aclFinding.EvidenceType) { $aclFinding.EvidenceType } else { 'SensitiveAcl' }
            SourceDomain          = 'ACL'
            Score                 = [Math]::Round($riskScore, 2)
            Severity              = if ($aclFinding.Severity) { $aclFinding.Severity } else { Get-ADObjectRiskSeverity -Score $riskScore }
            Reason                = $aclFinding.Reason
            Remediation           = $aclFinding.Remediation
            RelatedObjectId       = $trusteeObjectId
            RelatedObjectName     = $aclFinding.TrusteeName
            PrivilegeTier         = $target.PrivilegeTier
            IsDirect              = -not [bool]$aclFinding.IsInherited
            NestingDepth          = 0
            Path                  = $path
            ScoreFormula          = "$($aclFinding.NormalizedRight) ACL exposure = $riskScore"
            ScoreComponents       = @([pscustomobject]@{ Name = 'ACL right'; Value = $aclFinding.NormalizedRight; Reason = $aclFinding.Reason })
            AttackTechniques      = @($aclFinding.AttackTechniques)
            IsExcluded            = [bool]$aclFinding.IsExcluded
            IsApprovedException   = [bool]$aclFinding.IsApprovedException
            AclFindingId          = $aclFinding.AclFindingId
            AclFindingIds         = @($aclFinding.AclFindingIds)
            AggregatedFindingCount = if ($aclFinding.AggregatedFindingCount) { [int]$aclFinding.AggregatedFindingCount } else { 1 }
            IsAggregatedAclEvidence = [bool]$aclFinding.IsAggregatedAclEvidence
            ActiveDirectoryRights = @($aclFinding.ActiveDirectoryRights)
            ObjectType            = $aclFinding.ObjectType
            ObjectTypeName        = $aclFinding.ObjectTypeName
            ObjectTypes           = @($aclFinding.ObjectTypes)
            ObjectTypeNames       = @($aclFinding.ObjectTypeNames)
            InheritedObjectType   = $aclFinding.InheritedObjectType
            InheritedObjectTypeName = $aclFinding.InheritedObjectTypeName
            InheritanceType       = $aclFinding.InheritanceType
            ObjectFlags           = $aclFinding.ObjectFlags
            InheritanceFlags      = $aclFinding.InheritanceFlags
            PropagationFlags      = $aclFinding.PropagationFlags
            AccessControlType     = $aclFinding.AccessControlType
            OwnerName             = $aclFinding.OwnerName
            OwnerSid              = $aclFinding.OwnerSid
            OwnerDistinguishedName = $aclFinding.OwnerDistinguishedName
            OwnerObjectClass      = $aclFinding.OwnerObjectClass
            IsInherited           = [bool]$aclFinding.IsInherited
            TargetRiskContext     = $aclFinding.TargetRiskContext
            RawTrustee            = $aclFinding.RawTrustee
            UnresolvedTrustee     = [bool]$aclFinding.UnresolvedTrustee
            TargetCanonicalName   = $aclFinding.TargetCanonicalName
            SourceDescriptorId    = $aclFinding.SourceDescriptorId
            ApprovedExceptionStatus = $aclFinding.ApprovedExceptionStatus
            ApprovedExceptionId   = $aclFinding.ApprovedExceptionId
            ApprovedExceptionReason = $aclFinding.ApprovedExceptionReason
        })

        foreach ($item in @($trustee, $target)) {
            $item.EvidenceIds.Add($evidenceId)
            $item.RiskScore = [Math]::Round(([double]$item.RiskScore + $riskScore), 2)
            if ($riskScore -gt [double]$item.HighestEvidenceScore) {
                $item.HighestEvidenceScore = [Math]::Round($riskScore, 2)
                $item.TopReason = $aclFinding.Reason
            }
            if ($aclFinding.Remediation) { $item.CleanupActions = $aclFinding.Remediation }
            if (-not $item.RemediationDifficulty) { $item.RemediationDifficulty = 'Medium' }
            if ($aclFinding.IsApprovedException) { $item.IsApprovedException = $true }
            if ($aclFinding.IsExcluded) { $item.IsExcluded = $true }
        }

        $relationshipKey = "$trusteeObjectId|$targetObjectId|$($aclFinding.NormalizedRight)|$($aclFinding.ObjectType)"
        if (-not $relationshipKeys.ContainsKey($relationshipKey)) {
            $relationshipKeys[$relationshipKey] = $true
            $relationships.Add([PSCustomObject]@{
                FromObjectId      = $trusteeObjectId
                ToObjectId        = $targetObjectId
                RelationshipType  = $aclFinding.NormalizedRight
                SourceDomain      = 'ACL'
                RelationshipName  = $aclFinding.NormalizedRight
                IsDirect          = -not [bool]$aclFinding.IsInherited
                NestingDepth      = 0
                Path              = $path
                EvidenceId        = $evidenceId
                IsInherited       = [bool]$aclFinding.IsInherited
                ObjectType        = $aclFinding.ObjectType
            })
            $trustee.RelationshipCount++
            $target.RelationshipCount++
        }

        foreach ($effectiveTrusteeInfo in Get-ADObjectRiskAclEffectiveTrustees -AclFinding $aclFinding) {
            $effectiveName = if ($effectiveTrusteeInfo.Name) { [string]$effectiveTrusteeInfo.Name } elseif ($effectiveTrusteeInfo.SamAccountName) { [string]$effectiveTrusteeInfo.SamAccountName } elseif ($effectiveTrusteeInfo.DisplayName) { [string]$effectiveTrusteeInfo.DisplayName } else { 'Unknown effective trustee' }
            $effectiveSid = if ($effectiveTrusteeInfo.ObjectSid) { [string]$effectiveTrusteeInfo.ObjectSid } elseif ($effectiveTrusteeInfo.Sid) { [string]$effectiveTrusteeInfo.Sid } else { $null }
            $effectiveDn = if ($effectiveTrusteeInfo.DistinguishedName) { [string]$effectiveTrusteeInfo.DistinguishedName } else { $null }
            $effectiveClass = Get-ADObjectRiskAclEffectiveTrusteeClass -Trustee $effectiveTrusteeInfo
            $effectiveObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -ObjectSid $effectiveSid -DistinguishedName $effectiveDn -Name $effectiveName -Prefix 'acl-effective-trustee'
            $effectivePath = if ($effectiveTrusteeInfo.Path) {
                "$($effectiveTrusteeInfo.Path) -> $($aclFinding.NormalizedRight) -> $($aclFinding.TargetName)"
            }
            else {
                "$effectiveName -> $($aclFinding.TrusteeName) -> $($aclFinding.NormalizedRight) -> $targetDisplayName"
            }

            $effective = Ensure-ObjectSummary -ObjectId $effectiveObjectId `
                -ObjectClass $effectiveClass `
                -SamAccountName $effectiveName `
                -DisplayName $effectiveName `
                -DistinguishedName $effectiveDn `
                -ObjectSid $effectiveSid `
                -SourceDomain $sourceDomain `
                -AccountType $effectiveClass `
                -PrivilegeTier $target.PrivilegeTier `
                -PrivilegeTierReason "Effective $($aclFinding.NormalizedRight) via $($aclFinding.TrusteeName)" `
                -Role 'EffectiveAclTrustee'

            foreach ($tag in @($aclFinding.Tags + 'EffectiveAclExposure' + 'EffectiveTrustee')) {
                Add-ADObjectRiskTag -TagSet $effective._TagSet -Tag $tag
            }

            $evidenceIndex++
            $effectiveEvidenceId = 'ev-{0:000000}' -f $evidenceIndex
            $evidence.Add([PSCustomObject]@{
                EvidenceId              = $effectiveEvidenceId
                ObjectId                = $effectiveObjectId
                EvidenceType            = 'SensitiveAclEffectiveTrustee'
                SourceDomain            = 'ACL'
                Score                   = [Math]::Round($riskScore, 2)
                Severity                = if ($aclFinding.Severity) { $aclFinding.Severity } else { Get-ADObjectRiskSeverity -Score $riskScore }
                Reason                  = "Effective trustee inherits $($aclFinding.NormalizedRight) through direct ACL trustee $($aclFinding.TrusteeName)."
                Remediation             = $aclFinding.Remediation
                RelatedObjectId         = $targetObjectId
                RelatedObjectName       = $aclFinding.TargetName
                DirectTrusteeObjectId   = $trusteeObjectId
                DirectTrusteeName       = $aclFinding.TrusteeName
                EffectiveTrusteeName    = $effectiveName
                EffectiveTrusteeSid     = $effectiveSid
                EffectiveTrusteeDn      = $effectiveDn
                PrivilegeTier           = $target.PrivilegeTier
                IsDirect                = $false
                NestingDepth            = if ($null -ne $effectiveTrusteeInfo.NestingDepth) { $effectiveTrusteeInfo.NestingDepth } else { 1 }
                Path                    = $effectivePath
                ScoreFormula            = "Effective $($aclFinding.NormalizedRight) ACL exposure = $riskScore"
                ScoreComponents         = @([pscustomobject]@{ Name = 'Effective ACL right'; Value = $aclFinding.NormalizedRight; Reason = "Expanded from direct trustee $($aclFinding.TrusteeName)" })
                AttackTechniques        = @($aclFinding.AttackTechniques)
                IsExcluded              = $false
                IsApprovedException     = $false
                AclFindingId            = $aclFinding.AclFindingId
                AclFindingIds           = @($aclFinding.AclFindingIds)
                DirectAclEvidenceId     = $evidenceId
                AggregatedFindingCount  = if ($aclFinding.AggregatedFindingCount) { [int]$aclFinding.AggregatedFindingCount } else { 1 }
                IsAggregatedAclEvidence = [bool]$aclFinding.IsAggregatedAclEvidence
                NormalizedRight         = $aclFinding.NormalizedRight
                ObjectTypes             = @($aclFinding.ObjectTypes)
                ObjectTypeNames         = @($aclFinding.ObjectTypeNames)
                TargetRiskContext       = $aclFinding.TargetRiskContext
                TargetCanonicalName     = $aclFinding.TargetCanonicalName
                SourceDescriptorId      = $aclFinding.SourceDescriptorId
            })

            $effective.EvidenceIds.Add($effectiveEvidenceId)
            $effective.RiskScore = [Math]::Round(([double]$effective.RiskScore + $riskScore), 2)
            if ($riskScore -gt [double]$effective.HighestEvidenceScore) {
                $effective.HighestEvidenceScore = [Math]::Round($riskScore, 2)
                $effective.TopReason = "Effective $($aclFinding.NormalizedRight) through $($aclFinding.TrusteeName)"
            }
            if ($aclFinding.Remediation) { $effective.CleanupActions = $aclFinding.Remediation }
            if (-not $effective.RemediationDifficulty) { $effective.RemediationDifficulty = 'Medium' }

            $membershipRelationshipKey = "$effectiveObjectId|$trusteeObjectId|EffectiveAclTrusteeMembership|$($aclFinding.AclFindingId)"
            if (-not $relationshipKeys.ContainsKey($membershipRelationshipKey)) {
                $relationshipKeys[$membershipRelationshipKey] = $true
                $relationships.Add([PSCustomObject]@{
                    FromObjectId      = $effectiveObjectId
                    ToObjectId        = $trusteeObjectId
                    RelationshipType  = 'EffectiveAclTrusteeMembership'
                    SourceDomain      = 'ACL'
                    RelationshipName  = $aclFinding.TrusteeName
                    IsDirect          = $false
                    NestingDepth      = if ($null -ne $effectiveTrusteeInfo.NestingDepth) { $effectiveTrusteeInfo.NestingDepth } else { 1 }
                    Path              = if ($effectiveTrusteeInfo.Path) { [string]$effectiveTrusteeInfo.Path } else { "$effectiveName -> $($aclFinding.TrusteeName)" }
                    EvidenceId        = $effectiveEvidenceId
                    IsInherited       = $false
                })
                $effective.RelationshipCount++
                $trustee.RelationshipCount++
            }

            $effectiveAclRelationshipKey = "$effectiveObjectId|$targetObjectId|Effective$($aclFinding.NormalizedRight)|$($aclFinding.AclFindingId)"
            if (-not $relationshipKeys.ContainsKey($effectiveAclRelationshipKey)) {
                $relationshipKeys[$effectiveAclRelationshipKey] = $true
                $relationships.Add([PSCustomObject]@{
                    FromObjectId      = $effectiveObjectId
                    ToObjectId        = $targetObjectId
                    RelationshipType  = "Effective$($aclFinding.NormalizedRight)"
                    SourceDomain      = 'ACL'
                    RelationshipName  = $aclFinding.NormalizedRight
                    IsDirect          = $false
                    NestingDepth      = if ($null -ne $effectiveTrusteeInfo.NestingDepth) { $effectiveTrusteeInfo.NestingDepth } else { 1 }
                    Path              = $effectivePath
                    EvidenceId        = $effectiveEvidenceId
                    DirectAclEvidenceId = $evidenceId
                    DirectTrusteeObjectId = $trusteeObjectId
                    IsInherited       = [bool]$aclFinding.IsInherited
                    ObjectType        = $aclFinding.ObjectType
                })
                $effective.RelationshipCount++
                $target.RelationshipCount++
            }
        }
    }

    foreach ($authFinding in @($KerberosAuthFindings)) {
        if ([double]($authFinding.RiskScore) -le 0) { continue }

        $sourceDomain = if ($authFinding.Domain) { $authFinding.Domain } elseif ($Domain) { $Domain } else { 'unknown-domain' }
        $principalObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -ObjectSid $authFinding.PrincipalSid -DistinguishedName $authFinding.PrincipalDn -Name $authFinding.PrincipalSam -Prefix 'auth-principal'
        $principal = Ensure-ObjectSummary -ObjectId $principalObjectId `
            -ObjectClass $authFinding.PrincipalClass `
            -SamAccountName $authFinding.PrincipalSam `
            -DisplayName $authFinding.Principal `
            -DistinguishedName $authFinding.PrincipalDn `
            -ObjectSid $authFinding.PrincipalSid `
            -SourceDomain $sourceDomain `
            -AccountType $authFinding.AccountType `
            -PrivilegeTier $authFinding.PrivilegeTier `
            -PrivilegeTierReason $authFinding.RiskPattern `
            -Role 'KerberosAuthPrincipal'

        foreach ($tag in @($authFinding.Tags)) {
            Add-ADObjectRiskTag -TagSet $principal._TagSet -Tag $tag
        }

        $riskScore = if ($authFinding.IsApprovedException -and $authFinding.ApprovedExceptionStatus -eq 'Active') {
            0.0
        }
        else {
            [double]$authFinding.RiskScore
        }

        $evidenceIndex++
        $evidenceId = 'ev-{0:000000}' -f $evidenceIndex
        $pathParts = @($authFinding.Principal, $authFinding.RiskPattern)
        if (@($authFinding.DelegationTargets).Count) {
            $pathParts += (@($authFinding.DelegationTargets) -join ', ')
        }
        elseif (@($authFinding.ServicePrincipalNames).Count) {
            $pathParts += (@($authFinding.ServicePrincipalNames | Select-Object -First 3) -join ', ')
        }
        $path = ($pathParts | Where-Object { $_ }) -join ' -> '

        $evidence.Add([PSCustomObject]@{
            EvidenceId              = $evidenceId
            ObjectId                = $principalObjectId
            EvidenceType            = $authFinding.FindingType
            SourceDomain            = 'KerberosAuth'
            Score                   = [Math]::Round($riskScore, 2)
            Severity                = $authFinding.Severity
            Reason                  = $authFinding.Reason
            Remediation             = $authFinding.Remediation
            RelatedObjectId         = $null
            RelatedObjectName       = $authFinding.RiskPattern
            PrivilegeTier           = $authFinding.PrivilegeTier
            IsDirect                = $true
            NestingDepth            = 0
            Path                    = $path
            ScoreFormula            = $authFinding.ScoreFormula
            ScoreComponents         = @($authFinding.ScoreComponents)
            AttackTechniques        = @($authFinding.AttackTechniques)
            IsExcluded              = [bool]$authFinding.IsExcluded
            IsApprovedException     = [bool]$authFinding.IsApprovedException
            KerberosAuthFindingId   = $authFinding.KerberosAuthFindingId
            FindingType             = $authFinding.FindingType
            RiskPattern             = $authFinding.RiskPattern
            DelegationType          = $authFinding.DelegationType
            DelegationTargets       = @($authFinding.DelegationTargets)
            ServicePrincipalNames   = @($authFinding.ServicePrincipalNames)
            EncryptionSummary       = $authFinding.EncryptionSummary
            EncryptionTypes         = @($authFinding.EncryptionTypes)
            ApprovedExceptionStatus = $authFinding.ApprovedExceptionStatus
            ApprovedExceptionId     = $authFinding.ApprovedExceptionId
            ApprovedExceptionReason = $authFinding.ApprovedExceptionReason
        })

        $principal.EvidenceIds.Add($evidenceId)
        $principal.RiskScore = [Math]::Round(([double]$principal.RiskScore + $riskScore), 2)
        if ($riskScore -gt [double]$principal.HighestEvidenceScore) {
            $principal.HighestEvidenceScore = [Math]::Round($riskScore, 2)
            $principal.TopReason = $authFinding.Reason
        }
        if ($authFinding.Remediation) { $principal.CleanupActions = $authFinding.Remediation }
        if (-not $principal.RemediationDifficulty) { $principal.RemediationDifficulty = if ($authFinding.Severity -in @('Critical', 'High')) { 'High' } else { 'Medium' } }
        if ($authFinding.IsApprovedException) { $principal.IsApprovedException = $true }
        if ($authFinding.IsExcluded) { $principal.IsExcluded = $true }

        foreach ($target in @($authFinding.DelegationTargets)) {
            if (-not $target) { continue }
            $targetObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -Name ([string]$target) -Prefix 'auth-target'
            $relationshipKey = "$principalObjectId|$targetObjectId|$($authFinding.FindingType)|$target"
            if (-not $relationshipKeys.ContainsKey($relationshipKey)) {
                $relationshipKeys[$relationshipKey] = $true
                $relationships.Add([PSCustomObject]@{
                    FromObjectId      = $principalObjectId
                    ToObjectId        = $targetObjectId
                    RelationshipType  = $authFinding.FindingType
                    SourceDomain      = 'KerberosAuth'
                    RelationshipName  = $target
                    IsDirect          = $true
                    NestingDepth      = 0
                    Path              = $path
                    EvidenceId        = $evidenceId
                    IsInherited       = $false
                })
                $principal.RelationshipCount++
            }
        }
    }

    foreach ($trustFinding in @($TrustFindings)) {
        if ([double]($trustFinding.RiskScore) -le 0) { continue }

        $sourceDomain = if ($trustFinding.Domain) { $trustFinding.Domain } elseif ($Domain) { $Domain } else { 'unknown-domain' }
        $trustObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -DistinguishedName $trustFinding.DistinguishedName -Name $trustFinding.TrustName -Prefix 'trust'
        $partnerObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -Name $trustFinding.TrustPartner -Prefix 'trusted-domain'
        $trustObject = Ensure-ObjectSummary -ObjectId $trustObjectId `
            -ObjectClass 'trustedDomain' `
            -SamAccountName $trustFinding.TrustName `
            -DisplayName $trustFinding.TrustName `
            -DistinguishedName $trustFinding.DistinguishedName `
            -ObjectSid $null `
            -SourceDomain $sourceDomain `
            -AccountType 'Trust' `
            -PrivilegeTier 'Tier 0' `
            -PrivilegeTierReason $trustFinding.RiskPattern `
            -Role 'TrustBoundary'

        foreach ($tag in @($trustFinding.Tags + 'TrustBoundary' + 'Tier0Exposure')) {
            Add-ADObjectRiskTag -TagSet $trustObject._TagSet -Tag $tag
        }

        $riskScore = if ($trustFinding.IsApprovedException -and $trustFinding.ApprovedExceptionStatus -eq 'Active') {
            0.0
        }
        else {
            [double]$trustFinding.RiskScore
        }

        $evidenceIndex++
        $evidenceId = 'ev-{0:000000}' -f $evidenceIndex
        $path = (@($sourceDomain, $trustFinding.TrustDirection, $trustFinding.TrustPartner, $trustFinding.RiskPattern) | Where-Object { $_ }) -join ' -> '
        $evidence.Add([PSCustomObject]@{
            EvidenceId              = $evidenceId
            ObjectId                = $trustObjectId
            EvidenceType            = $trustFinding.FindingType
            SourceDomain            = 'Trust'
            Score                   = [Math]::Round($riskScore, 2)
            Severity                = $trustFinding.Severity
            Reason                  = $trustFinding.Reason
            Remediation             = $trustFinding.Remediation
            RelatedObjectId         = $partnerObjectId
            RelatedObjectName       = $trustFinding.TrustPartner
            PrivilegeTier           = 'Tier 0'
            IsDirect                = $true
            NestingDepth            = 0
            Path                    = $path
            ScoreFormula            = $trustFinding.ScoreFormula
            ScoreComponents         = @($trustFinding.ScoreComponents)
            AttackTechniques        = @($trustFinding.AttackTechniques)
            IsExcluded              = [bool]$trustFinding.IsExcluded
            IsApprovedException     = [bool]$trustFinding.IsApprovedException
            TrustFindingId          = $trustFinding.TrustFindingId
            FindingType             = $trustFinding.FindingType
            RiskPattern             = $trustFinding.RiskPattern
            TrustName               = $trustFinding.TrustName
            TrustPartner            = $trustFinding.TrustPartner
            TrustDirection          = $trustFinding.TrustDirection
            TrustType               = $trustFinding.TrustType
            IsTransitive            = [bool]$trustFinding.IsTransitive
            SelectiveAuthentication = [bool]$trustFinding.SelectiveAuthentication
            SIDFilteringEnabled     = [bool]$trustFinding.SIDFilteringEnabled
            ApprovedExceptionStatus = $trustFinding.ApprovedExceptionStatus
            ApprovedExceptionId     = $trustFinding.ApprovedExceptionId
            ApprovedExceptionReason = $trustFinding.ApprovedExceptionReason
        })

        $trustObject.EvidenceIds.Add($evidenceId)
        $trustObject.RiskScore = [Math]::Round(([double]$trustObject.RiskScore + $riskScore), 2)
        if ($riskScore -gt [double]$trustObject.HighestEvidenceScore) {
            $trustObject.HighestEvidenceScore = [Math]::Round($riskScore, 2)
            $trustObject.TopReason = $trustFinding.Reason
        }
        if ($trustFinding.Remediation) { $trustObject.CleanupActions = $trustFinding.Remediation }
        if (-not $trustObject.RemediationDifficulty) { $trustObject.RemediationDifficulty = if ($trustFinding.Severity -in @('Critical', 'High')) { 'High' } else { 'Medium' } }
        if ($trustFinding.IsApprovedException) { $trustObject.IsApprovedException = $true }
        if ($trustFinding.IsExcluded) { $trustObject.IsExcluded = $true }

        $relationshipKey = "$trustObjectId|$partnerObjectId|$($trustFinding.FindingType)|$($trustFinding.TrustPartner)"
        if (-not $relationshipKeys.ContainsKey($relationshipKey)) {
            $relationshipKeys[$relationshipKey] = $true
            $relationships.Add([PSCustomObject]@{
                FromObjectId      = $trustObjectId
                ToObjectId        = $partnerObjectId
                RelationshipType  = $trustFinding.FindingType
                SourceDomain      = 'Trust'
                RelationshipName  = $trustFinding.TrustPartner
                IsDirect          = $true
                NestingDepth      = 0
                Path              = $path
                EvidenceId        = $evidenceId
                IsInherited       = $false
            })
            $trustObject.RelationshipCount++
        }
    }

    foreach ($dnsFinding in @($DnsFindings)) {
        if ([double]($dnsFinding.RiskScore) -le 0) { continue }

        $sourceDomain = if ($dnsFinding.Domain) { $dnsFinding.Domain } elseif ($Domain) { $Domain } else { 'unknown-domain' }
        $name = if ($dnsFinding.RecordName) { "$($dnsFinding.RecordName).$($dnsFinding.ZoneName)" } elseif ($dnsFinding.ZoneName) { $dnsFinding.ZoneName } elseif ($dnsFinding.Principal) { $dnsFinding.Principal } else { $dnsFinding.FindingType }
        $dnsObjectId = New-ADObjectRiskObjectId -Domain $sourceDomain -DistinguishedName $dnsFinding.DistinguishedName -Name $name -Prefix 'dns'
        $dnsObject = Ensure-ObjectSummary -ObjectId $dnsObjectId `
            -ObjectClass $(if ($dnsFinding.RecordName) { 'dnsNode' } elseif ($dnsFinding.ZoneName) { 'dnsZone' } else { 'dnsPrincipal' }) `
            -SamAccountName $name `
            -DisplayName $name `
            -DistinguishedName $dnsFinding.DistinguishedName `
            -ObjectSid $null `
            -SourceDomain $sourceDomain `
            -AccountType 'DNS' `
            -PrivilegeTier $(if (@($dnsFinding.Tags) -contains 'Tier0Exposure') { 'Tier 0' } else { 'Tier 1' }) `
            -PrivilegeTierReason $dnsFinding.RiskPattern `
            -Role 'DnsPostureObject'

        foreach ($tag in @($dnsFinding.Tags + 'DnsPosture')) {
            Add-ADObjectRiskTag -TagSet $dnsObject._TagSet -Tag $tag
        }

        $riskScore = if ($dnsFinding.IsApprovedException -and $dnsFinding.ApprovedExceptionStatus -eq 'Active') { 0.0 } else { [double]$dnsFinding.RiskScore }
        $evidenceIndex++
        $evidenceId = 'ev-{0:000000}' -f $evidenceIndex
        $path = (@($dnsFinding.Principal, $dnsFinding.RecordName, $dnsFinding.ZoneName, $dnsFinding.RiskPattern) | Where-Object { $_ }) -join ' -> '
        $evidence.Add([PSCustomObject]@{
            EvidenceId              = $evidenceId
            ObjectId                = $dnsObjectId
            EvidenceType            = $dnsFinding.FindingType
            SourceDomain            = 'DNS'
            Score                   = [Math]::Round($riskScore, 2)
            Severity                = $dnsFinding.Severity
            Reason                  = $dnsFinding.Reason
            Remediation             = $dnsFinding.Remediation
            RelatedObjectId         = $null
            RelatedObjectName       = $dnsFinding.ZoneName
            PrivilegeTier           = $dnsObject.PrivilegeTier
            IsDirect                = $true
            NestingDepth            = 0
            Path                    = $path
            ScoreFormula            = $dnsFinding.ScoreFormula
            ScoreComponents         = @($dnsFinding.ScoreComponents)
            AttackTechniques        = @($dnsFinding.AttackTechniques)
            IsExcluded              = [bool]$dnsFinding.IsExcluded
            IsApprovedException     = [bool]$dnsFinding.IsApprovedException
            DnsFindingId            = $dnsFinding.DnsFindingId
            FindingType             = $dnsFinding.FindingType
            RiskPattern             = $dnsFinding.RiskPattern
            ZoneName                = $dnsFinding.ZoneName
            RecordName              = $dnsFinding.RecordName
            RecordType              = $dnsFinding.RecordType
            Principal               = $dnsFinding.Principal
            ApprovedExceptionStatus = $dnsFinding.ApprovedExceptionStatus
            ApprovedExceptionId     = $dnsFinding.ApprovedExceptionId
            ApprovedExceptionReason = $dnsFinding.ApprovedExceptionReason
        })

        $dnsObject.EvidenceIds.Add($evidenceId)
        $dnsObject.RiskScore = [Math]::Round(([double]$dnsObject.RiskScore + $riskScore), 2)
        if ($riskScore -gt [double]$dnsObject.HighestEvidenceScore) {
            $dnsObject.HighestEvidenceScore = [Math]::Round($riskScore, 2)
            $dnsObject.TopReason = $dnsFinding.Reason
        }
        if ($dnsFinding.Remediation) { $dnsObject.CleanupActions = $dnsFinding.Remediation }
        if (-not $dnsObject.RemediationDifficulty) { $dnsObject.RemediationDifficulty = if ($dnsFinding.Severity -in @('Critical', 'High')) { 'High' } else { 'Medium' } }
        if ($dnsFinding.IsApprovedException) { $dnsObject.IsApprovedException = $true }
        if ($dnsFinding.IsExcluded) { $dnsObject.IsExcluded = $true }
    }

    foreach ($identityFinding in @($IdentityRiskFindings)) {
        if ([double]($identityFinding.RiskScore) -le 0) { continue }

        $sourceDomain = if ($identityFinding.Domain) { $identityFinding.Domain } elseif ($Domain) { $Domain } else { 'unknown-domain' }
        $objectName = if ($identityFinding.PrincipalSam) { $identityFinding.PrincipalSam } elseif ($identityFinding.Principal) { $identityFinding.Principal } elseif ($identityFinding.Setting) { $identityFinding.Setting } else { $identityFinding.FindingType }
        $objectClass = if ($identityFinding.PrincipalClass) { [string]$identityFinding.PrincipalClass } elseif ($identityFinding.Principal -or $identityFinding.PrincipalSam) { 'user' } else { 'identity' }
        $evidenceSource = if ($identityFinding.SourceDomain) { [string]$identityFinding.SourceDomain } else { 'ObjectRisk' }
        $role = 'IdentityRisk'
        $objectId = New-ADObjectRiskObjectId -Domain $sourceDomain -ObjectSid $identityFinding.PrincipalSid -DistinguishedName $identityFinding.PrincipalDn -Name $objectName -Prefix 'identity-risk'

        $identityObject = Ensure-ObjectSummary -ObjectId $objectId `
            -ObjectClass $objectClass `
            -SamAccountName $objectName `
            -DisplayName $objectName `
            -DistinguishedName $identityFinding.PrincipalDn `
            -ObjectSid $identityFinding.PrincipalSid `
            -SourceDomain $sourceDomain `
            -AccountType $objectClass `
            -PrivilegeTier $(if ($identityFinding.PrivilegeTier) { $identityFinding.PrivilegeTier } else { 'Tier 0' }) `
            -PrivilegeTierReason $identityFinding.RiskPattern `
            -Role $role

        foreach ($tag in @($identityFinding.Tags + $role)) {
            Add-ADObjectRiskTag -TagSet $identityObject._TagSet -Tag $tag
        }

        $riskScore = if ($identityFinding.IsApprovedException -and $identityFinding.ApprovedExceptionStatus -eq 'Active') { 0.0 } else { [double]$identityFinding.RiskScore }
        $evidenceIndex++
        $evidenceId = 'ev-{0:000000}' -f $evidenceIndex
        $evidence.Add([PSCustomObject]@{
            EvidenceId                  = $evidenceId
            ObjectId                    = $objectId
            EvidenceType                = $identityFinding.FindingType
            SourceDomain                = $evidenceSource
            Score                       = [Math]::Round($riskScore, 2)
            Severity                    = $identityFinding.Severity
            Reason                      = $identityFinding.Reason
            Remediation                 = $identityFinding.Remediation
            RelatedObjectId             = $null
            RelatedObjectName           = $identityFinding.Setting
            PrivilegeTier               = $identityObject.PrivilegeTier
            IsDirect                    = $true
            NestingDepth                = 0
            Path                        = (@($objectName, $identityFinding.Setting, $identityFinding.FindingType) | Where-Object { $_ }) -join ' -> '
            ScoreFormula                = $null
            ScoreComponents             = @()
            AttackTechniques            = @()
            IsExcluded                  = [bool]$identityFinding.IsExcluded
            IsApprovedException         = [bool]$identityFinding.IsApprovedException
            IdentityRiskFindingId       = $identityFinding.IdentityRiskFindingId
            FindingType                 = $identityFinding.FindingType
            RiskPattern                 = $identityFinding.RiskPattern
            SourceDomainDetail          = $identityFinding.SourceDomain
            MitreId                     = $identityFinding.MitreId
            Principal                   = $identityFinding.Principal
            Setting                     = $identityFinding.Setting
            ObservedValue               = $identityFinding.ObservedValue
            ApprovedExceptionStatus     = $identityFinding.ApprovedExceptionStatus
            ApprovedExceptionId         = $identityFinding.ApprovedExceptionId
            ApprovedExceptionReason     = $identityFinding.ApprovedExceptionReason
        })

        $identityObject.EvidenceIds.Add($evidenceId)
        $identityObject.RiskScore = [Math]::Round(([double]$identityObject.RiskScore + $riskScore), 2)
        if ($riskScore -gt [double]$identityObject.HighestEvidenceScore) {
            $identityObject.HighestEvidenceScore = [Math]::Round($riskScore, 2)
            $identityObject.TopReason = $identityFinding.Reason
        }
        if ($identityFinding.Remediation) { $identityObject.CleanupActions = $identityFinding.Remediation }
        if (-not $identityObject.RemediationDifficulty) { $identityObject.RemediationDifficulty = if ($identityFinding.Severity -in @('Critical', 'High')) { 'High' } else { 'Medium' } }
        if ($identityFinding.IsApprovedException) { $identityObject.IsApprovedException = $true }
        if ($identityFinding.IsExcluded) { $identityObject.IsExcluded = $true }
    }

    $objects = foreach ($entry in $objectMap.GetEnumerator()) {
        $item = $entry.Value
        $item.ObjectRoles = @($item._RoleSet.Keys | Sort-Object)
        $isOnlyAclTrustee = @($item.ObjectRoles | Where-Object { $_ -notin @('AclTrustee', 'EffectiveAclTrustee') }).Count -eq 0
        if ($isOnlyAclTrustee -and $item.ObjectClass -eq 'wellKnownPrincipal') {
            continue
        }

        if (Test-ADObjectRiskNativeArchitectureObject -Object ([pscustomobject]$item) -NameProperty 'SamAccountName' -DisplayProperty 'DisplayName' -SidProperty 'ObjectSid') {
            continue
        }

        $item.Tags = @($item._TagSet.Keys | Sort-Object)
        $item.Severity = Get-ADObjectRiskSeverity -Score ([double]$item.RiskScore)
        $item.EvidenceIds = @($item.EvidenceIds)
        $item.Remove('_TagSet')
        $item.Remove('_RoleSet')
        [PSCustomObject]$item
    }

    [PSCustomObject]@{
        Objects             = @($objects | Sort-Object @{ Expression = 'RiskScore'; Descending = $true }, DisplayName)
        ObjectEvidence      = @($evidence)
        ObjectRelationships = @($relationships)
    }
}
