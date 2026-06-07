function ConvertTo-ADPostureAclRightsList {
    param([object]$Rights)

    if ($null -eq $Rights) { return @() }
    if ($Rights -is [array]) { return @($Rights | ForEach-Object { [string]$_ }) }
    @(([string]$Rights) -split ',\s*' | Where-Object { $_ })
}

function Test-ADPostureAclBuiltinPrincipal {
    param([string]$Name)

    if (-not $Name) { return $false }
    $normalized = $Name.Trim()
    @(
        'CREATOR OWNER',
        'OWNER RIGHTS',
        'BUILTIN\Account Operators',
        'BUILTIN\Administrators',
        'BUILTIN\Backup Operators',
        'BUILTIN\Print Operators',
        'BUILTIN\Replicator',
        'BUILTIN\Server Operators',
        'NT AUTHORITY\SELF',
        'NT AUTHORITY\SYSTEM',
        'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
    ) -contains $normalized -or
        $normalized -like '*\Account Operators' -or
        $normalized -like '*\Backup Operators' -or
        $normalized -like '*\Cert Publishers' -or
        $normalized -like '*\Domain Admins' -or
        $normalized -like '*\Domain Controllers' -or
        $normalized -like '*\DnsAdmins' -or
        $normalized -like '*\Enterprise Admins' -or
        $normalized -like '*\Enterprise Domain Controllers' -or
        $normalized -like '*\Enterprise Key Admins' -or
        $normalized -like '*\Enterprise Read-only Domain Controllers' -or
        $normalized -like '*\Group Policy Creator Owners' -or
        $normalized -like '*\Key Admins' -or
        $normalized -like '*\Print Operators' -or
        $normalized -like '*\Protected Users' -or
        $normalized -like '*\Read-only Domain Controllers' -or
        $normalized -like '*\Schema Admins' -or
        $normalized -like '*\Server Operators'
}

function Get-ADPostureAclObjectTypeName {
    param([string]$ObjectType)

    $map = @{
        '00000000-0000-0000-0000-000000000000' = 'All properties'
        '00299570-246d-11d0-a768-00aa006e0529' = 'Reset Password'
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating Directory Changes'
        '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'Replication Synchronization'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating Directory Changes All'
        '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' = 'Read Only Replication Secret Synchronization'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'Replicating Directory Changes In Filtered Set'
        'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' = 'Membership'
        'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'member'
        'bf967991-0de6-11d0-a285-00aa003049e2' = 'memberOf'
        'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'servicePrincipalName'
        'bf967a68-0de6-11d0-a285-00aa003049e2' = 'userAccountControl'
        'c7407360-20bf-11d0-a768-00aa006e0529' = 'Domain Password and Lockout Policies'
        '4c164200-20c0-11d0-a768-00aa006e0529' = 'Account Restrictions'
        'f3531ec6-6330-4f8e-8d39-7a671fbac605' = 'ms-LAPS-Encrypted-Password-Attributes'
        '084c93a2-620d-4879-a836-f0ae47de0e89' = 'Read secret attributes'
        '94825a8d-b171-4116-8146-1e34d8f54401' = 'Write secret attributes'
    }

    $key = ([string]$ObjectType).ToLowerInvariant()
    if ($map.ContainsKey($key)) { return $map[$key] }
    if ($ObjectType) { return $ObjectType }
    $null
}

function Get-ADPostureAclFindingTemplate {
    param(
        [string[]]$Rights,
        [string]$ObjectType,
        [string]$ObjectTypeName
    )

    $rightSet = @{}
    foreach ($right in @($Rights)) {
        $rightSet[$right.Trim().ToLowerInvariant()] = $true
    }

    $replicationGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2',
        '89e95b76-444d-4c62-991a-0facbeda640c'
    )

    $membershipGuids = @(
        'bc0ac240-79a9-11d0-9020-00c04fc2d4cf',
        'bf9679c0-0de6-11d0-a285-00aa003049e2',
        'bf967991-0de6-11d0-a285-00aa003049e2'
    )

    $spnGuids = @('f3a64788-5306-11d1-a9c5-0000f80367c1')
    $accountControlGuids = @(
        'bf967a68-0de6-11d0-a285-00aa003049e2',
        'c7407360-20bf-11d0-a768-00aa006e0529',
        '4c164200-20c0-11d0-a768-00aa003049e2'
    )
    $legacyLapsNames = @('ms-mcs-admpwd', 'ms-mcs-admpwdexpirationtime')
    $windowsLapsNames = @(
        'mslaps-password',
        'mslaps-passwordexpirationtime',
        'mslaps-encryptedpassword',
        'mslaps-encryptedpasswordhistory',
        'mslaps-encrypteddsrmpassword',
        'mslaps-encrypteddsrmpasswordhistory',
        'mslaps-currentpasswordversion',
        'ms-laps-encrypted-password-attributes'
    )
    $windowsLapsGuids = @('f3531ec6-6330-4f8e-8d39-7a671fbac605')
    $secretAttributeGuids = @(
        '084c93a2-620d-4879-a836-f0ae47de0e89',
        '94825a8d-b171-4116-8146-1e34d8f54401'
    )

    $objectTypeText = ([string]$ObjectType).ToLowerInvariant()
    $objectTypeNameText = ([string]$ObjectTypeName).ToLowerInvariant()
    $hasReplicationRight = $false
    foreach ($guid in $replicationGuids) {
        if ($objectTypeText -eq $guid) {
            $hasReplicationRight = $true
            break
        }
    }
    $isAllProperties = (-not $objectTypeText) -or $objectTypeText -eq '00000000-0000-0000-0000-000000000000'

    if ($rightSet.ContainsKey('genericall')) {
        return @{
            NormalizedRight = 'GenericAll'
            Score = 12.0
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget')
            Reason = 'Trustee has GenericAll over a sensitive AD object.'
            Remediation = 'Remove GenericAll delegation or scope it to a least-privilege administrative group.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' })
        }
    }

    if ($rightSet.ContainsKey('writedacl')) {
        return @{
            NormalizedRight = 'WriteDacl'
            Score = 10.0
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget')
            Reason = 'Trustee can change the DACL on a sensitive AD object.'
            Remediation = 'Remove WriteDacl rights and review whether the trustee can grant itself higher privilege.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1222'; Name = 'File and Directory Permissions Modification'; Tactic = 'Defense Evasion, Privilege Escalation' })
        }
    }

    if ($rightSet.ContainsKey('writeowner')) {
        return @{
            NormalizedRight = 'WriteOwner'
            Score = 9.0
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget')
            Reason = 'Trustee can take ownership of a sensitive AD object.'
            Remediation = 'Remove WriteOwner rights and validate ownership delegation.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' })
        }
    }

    if ($rightSet.ContainsKey('genericwrite')) {
        return @{
            NormalizedRight = 'GenericWrite'
            Score = 8.0
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget')
            Reason = 'Trustee can write sensitive attributes on an AD object.'
            Remediation = 'Replace GenericWrite with specific delegated rights that are required.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' })
        }
    }

    if ($rightSet.ContainsKey('delete') -or $rightSet.ContainsKey('deletetree') -or $rightSet.ContainsKey('deletechild')) {
        return @{
            NormalizedRight = 'Delete'
            Score = 7.5
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'DestructiveAcl')
            Reason = 'Trustee can delete or remove child objects from a sensitive AD object.'
            Remediation = 'Remove delete delegation from sensitive targets unless it is explicitly approved and monitored.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1485'; Name = 'Data Destruction'; Tactic = 'Impact' })
        }
    }

    if ($rightSet.ContainsKey('writeproperty') -and ($isAllProperties -or $membershipGuids -contains $objectTypeText)) {
        return @{
            NormalizedRight = 'WriteMembership'
            Score = 9.5
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'MembershipControl')
            Reason = 'Trustee can modify group membership or membership-related attributes on a sensitive AD object.'
            Remediation = 'Remove membership write delegation from privileged groups and review approved group management paths.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' })
        }
    }

    if ($rightSet.ContainsKey('writeproperty') -and $spnGuids -contains $objectTypeText) {
        return @{
            NormalizedRight = 'WriteSPN'
            Score = 8.5
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'KerberoastExposure')
            Reason = 'Trustee can modify service principal names on a sensitive identity.'
            Remediation = 'Remove SPN write delegation from privileged identities and validate Kerberos delegation paths.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1558.003'; Name = 'Kerberoasting'; Tactic = 'Credential Access' })
        }
    }

    if ($rightSet.ContainsKey('writeproperty') -and $accountControlGuids -contains $objectTypeText) {
        return @{
            NormalizedRight = 'WriteAccountControl'
            Score = 8.0
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'AccountControl')
            Reason = 'Trustee can modify account control or password policy attributes on a sensitive AD object.'
            Remediation = 'Remove account-control write delegation from privileged identities and policy containers.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' })
        }
    }

    if (($rightSet.ContainsKey('writeproperty') -or $rightSet.ContainsKey('readproperty') -or $rightSet.ContainsKey('extendedright')) -and
        (($legacyLapsNames -contains $objectTypeNameText) -or $objectTypeNameText -like '*ms-mcs-admpwd*')) {
        return @{
            NormalizedRight = 'LegacyLapsControl'
            Score = 7.5
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'LegacyLAPS', 'LegacyLapsExposure', 'CredentialExposure')
            Reason = 'Trustee has access to legacy Microsoft LAPS password or expiration attributes.'
            Remediation = 'Restrict legacy LAPS attribute access to approved workstation administration roles.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1552.006'; Name = 'Group Policy Preferences'; Tactic = 'Credential Access' })
        }
    }

    if (($rightSet.ContainsKey('writeproperty') -or $rightSet.ContainsKey('readproperty') -or $rightSet.ContainsKey('extendedright')) -and
        (($windowsLapsGuids -contains $objectTypeText) -or ($windowsLapsNames -contains $objectTypeNameText) -or $objectTypeNameText -like '*mslaps-*')) {
        return @{
            NormalizedRight = 'WindowsLapsControl'
            Score = 8.0
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'WindowsLAPS', 'WindowsLapsExposure', 'CredentialExposure')
            Reason = 'Trustee has access to Windows LAPS password, encrypted password, DSRM password, or password version attributes.'
            Remediation = 'Restrict Windows LAPS attribute and extended-right access to approved LAPS readers and recovery operators.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1552'; Name = 'Unsecured Credentials'; Tactic = 'Credential Access' })
        }
    }

    if (($rightSet.ContainsKey('writeproperty') -or $rightSet.ContainsKey('readproperty') -or $rightSet.ContainsKey('extendedright')) -and
        ($secretAttributeGuids -contains $objectTypeText)) {
        return @{
            NormalizedRight = 'SecretAttributeAccess'
            Score = 9.0
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'CredentialExposure')
            Reason = 'Trustee can read or write secret attributes on an AD partition.'
            Remediation = 'Remove secret attribute delegation unless it is tied to an approved Tier 0 service identity.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1552'; Name = 'Unsecured Credentials'; Tactic = 'Credential Access' })
        }
    }

    if ($rightSet.ContainsKey('extendedright') -and $hasReplicationRight) {
        return @{
            NormalizedRight = 'DCSync'
            Score = 15.0
            Severity = 'Critical'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'DCSyncCapable', 'Tier0Exposure')
            Reason = 'Trustee has directory replication extended rights that can enable DCSync.'
            Remediation = 'Remove replication extended rights unless the trustee is an approved directory replication identity.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1003.006'; Name = 'DCSync'; Tactic = 'Credential Access' })
        }
    }

    if ($rightSet.ContainsKey('allextendedrights') -or ($rightSet.ContainsKey('extendedright') -and $isAllProperties)) {
        return @{
            NormalizedRight = 'AllExtendedRights'
            Score = 7.0
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget')
            Reason = 'Trustee has all extended rights over a sensitive AD object.'
            Remediation = 'Replace AllExtendedRights with explicitly required delegated extended rights.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' })
        }
    }

    if ($rightSet.ContainsKey('extendedright') -and $objectTypeText -eq '00299570-246d-11d0-a768-00aa006e0529') {
        return @{
            NormalizedRight = 'ResetPassword'
            Score = 6.5
            Severity = 'High'
            Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget')
            Reason = 'Trustee can reset passwords on a sensitive AD object.'
            Remediation = 'Remove password reset delegation from privileged targets or scope it to approved helpdesk tiers.'
            AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' })
        }
    }

    $null
}

function Get-ADPostureAclAttributeReason {
    param(
        [string]$NormalizedRight,
        [string]$ObjectTypeName,
        [string[]]$Rights
    )

    $name = ([string]$ObjectTypeName).ToLowerInvariant()
    $rightsText = ((@($Rights) | ForEach-Object { [string]$_ }) -join ', ')

    if ($NormalizedRight -eq 'LegacyLapsControl') {
        if ($name -eq 'ms-mcs-admpwd') {
            return "Trustee can read the legacy Microsoft LAPS clear-text local administrator password attribute ($ObjectTypeName). Rights: $rightsText."
        }
        if ($name -eq 'ms-mcs-admpwdexpirationtime') {
            return "Trustee can read or change the legacy Microsoft LAPS password expiration attribute ($ObjectTypeName), which can influence password rotation timing. Rights: $rightsText."
        }
    }

    if ($NormalizedRight -eq 'WindowsLapsControl') {
        switch ($name) {
            'mslaps-password' {
                return "Trustee can read the Windows LAPS password attribute ($ObjectTypeName). Rights: $rightsText."
            }
            'mslaps-encryptedpassword' {
                return "Trustee can read the Windows LAPS encrypted password blob ($ObjectTypeName). Recovery depends on authorized decryptors, but this is still credential-recovery material. Rights: $rightsText."
            }
            'mslaps-encryptedpasswordhistory' {
                return "Trustee can read Windows LAPS encrypted password history ($ObjectTypeName), exposing previous local administrator password material where decryptable. Rights: $rightsText."
            }
            'mslaps-encrypteddsrmpassword' {
                return "Trustee can read the Windows LAPS encrypted DSRM password blob ($ObjectTypeName), which is sensitive for domain controller recovery paths. Rights: $rightsText."
            }
            'mslaps-encrypteddsrmpasswordhistory' {
                return "Trustee can read Windows LAPS encrypted DSRM password history ($ObjectTypeName), exposing previous recovery password material where decryptable. Rights: $rightsText."
            }
            'mslaps-passwordexpirationtime' {
                return "Trustee can read or change the Windows LAPS password expiration attribute ($ObjectTypeName), which can influence local administrator password rotation timing. Rights: $rightsText."
            }
            'mslaps-currentpasswordversion' {
                return "Trustee can read Windows LAPS password version metadata ($ObjectTypeName), which can aid credential recovery workflow mapping. Rights: $rightsText."
            }
            'ms-laps-encrypted-password-attributes' {
                return "Trustee has the Windows LAPS encrypted password attribute control set ($ObjectTypeName), covering encrypted password recovery attributes. Rights: $rightsText."
            }
        }

        return "Trustee has Windows LAPS attribute access on $ObjectTypeName. Rights: $rightsText."
    }

    if ($NormalizedRight -eq 'SecretAttributeAccess') {
        return "Trustee can access protected secret attribute control set $ObjectTypeName. Rights: $rightsText."
    }

    $null
}

function Get-ADPostureAclSeverity {
    param([double]$Score)

    if ($Score -ge 14) { return 'Critical' }
    if ($Score -ge 5) { return 'High' }
    if ($Score -ge 2) { return 'Medium' }
    if ($Score -gt 0) { return 'Low' }
    'Informational'
}

function Test-ADPostureAclAdminSdHolderTarget {
    param(
        [string]$TargetName,
        [string]$TargetDistinguishedName
    )

    $name = ([string]$TargetName).Trim()
    $dn = ([string]$TargetDistinguishedName).Trim()

    if ($name -match '^(?i:AdminSDHolder)$') { return $true }
    if ($dn -match '^(?i:CN=AdminSDHolder,CN=System,)') { return $true }

    $false
}

function Resolve-ADPostureAclTargetContext {
    param(
        [string]$TargetName,
        [string]$TargetDistinguishedName,
        [string]$TargetObjectClass,
        [string]$NormalizedRight
    )

    $name = ([string]$TargetName).Trim()
    $dn = ([string]$TargetDistinguishedName).Trim()
    $class = ([string]$TargetObjectClass).Trim()
    $text = "$name $dn"
    $tags = [System.Collections.Generic.List[string]]::new()
    $tier = 'Tier 2'
    $context = 'Common directory object'
    $multiplier = 0.55

    $isAdminSdHolder = Test-ADPostureAclAdminSdHolderTarget -TargetName $TargetName -TargetDistinguishedName $TargetDistinguishedName

    switch -Regex ($class) {
        '^(?i:domainDNS)$' {
            $tier = 'Tier 0'
            $context = 'Domain naming context'
            $multiplier = 1.0
            $tags.Add('Tier0Exposure')
            $tags.Add('DomainRootAcl')
            break
        }
        '^(?i:groupPolicyContainer)$' {
            $tier = 'Tier 1'
            $context = 'Group Policy container'
            $multiplier = 0.85
            $tags.Add('Tier1Exposure')
            $tags.Add('GpoAclTarget')
            break
        }
        '^(?i:organizationalUnit)$' {
            $tier = 'Tier 1'
            $context = 'Organizational Unit delegation'
            $multiplier = 0.75
            $tags.Add('Tier1Exposure')
            $tags.Add('OrganizationalUnitAclTarget')
            break
        }
        '^(?i:computer)$' {
            $tier = 'Tier 2'
            $context = 'Computer object'
            $multiplier = 0.65
            $tags.Add('ComputerAclTarget')
            break
        }
        '^(?i:user)$' {
            $tier = 'Tier 2'
            $context = 'User object'
            $multiplier = 0.60
            $tags.Add('UserAclTarget')
            break
        }
        '^(?i:group)$' {
            $tier = 'Tier 2'
            $context = 'Group object'
            $multiplier = 0.70
            $tags.Add('GroupAclTarget')
            break
        }
    }

    if ($isAdminSdHolder) {
        $tier = 'Tier 0'
        $context = 'AdminSDHolder protected-object ACL template'
        $multiplier = 1.0
        $tags.Add('Tier0Exposure')
        $tags.Add('PrivilegedAclTarget')
        $tags.Add('AdminSDHolder')
        $tags.Add('SDProp')
        $tags.Add('ProtectedObjectTemplate')
    }
    elseif ($text -match '(?i)\b(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Key Admins|Enterprise Key Admins|Domain Controllers|Read-only Domain Controllers|Protected Users|Group Policy Creator Owners|DnsAdmins)\b') {
        $tier = 'Tier 0'
        $context = 'Tier 0 privileged target'
        $multiplier = 1.0
        $tags.Add('Tier0Exposure')
        $tags.Add('PrivilegedAclTarget')
    }
    elseif ($dn -match '(?i),CN=Policies,CN=System,' -or $name -match '(?i)\bGPO\b') {
        $tier = 'Tier 1'
        $context = 'Group Policy container'
        $multiplier = [Math]::Max($multiplier, 0.85)
        $tags.Add('Tier1Exposure')
        $tags.Add('GpoAclTarget')
    }

    if ($NormalizedRight -eq 'DCSync') {
        $tier = 'Tier 0'
        $context = 'Directory replication control'
        $multiplier = 1.0
        $tags.Add('Tier0Exposure')
        $tags.Add('DCSyncCapable')
    }

    [pscustomobject]@{
        PrivilegeTier = $tier
        Context = $context
        Multiplier = $multiplier
        Tags = @($tags | Sort-Object -Unique)
        IsAdminSdHolder = $isAdminSdHolder
    }
}

function Get-ADPostureAclOwnerFindingTemplate {
    param(
        [string]$OwnerName,
        [string]$TargetObjectClass
    )

    if (-not $OwnerName -or (Test-ADPostureAclBuiltinPrincipal -Name $OwnerName)) { return $null }

    $isPrivilegedClass = @('domainDNS', 'group', 'user', 'computer', 'container', 'organizationalUnit') -contains $TargetObjectClass
    @{
        NormalizedRight = 'ObjectOwner'
        Score = if ($isPrivilegedClass) { 11.0 } else { 8.0 }
        Severity = if ($isPrivilegedClass) { 'High' } else { 'Medium' }
        Tags = @('SensitiveAclTrustee', 'SensitiveAclTarget', 'UnexpectedOwner', 'OwnerControl')
        Reason = 'Unexpected owner can modify the DACL on the sensitive AD object and may grant itself control.'
        Remediation = 'Reset ownership to an approved administrative owner and review why the owner changed.'
        AttackTechniques = @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' })
    }
}

function ConvertTo-ADAclRiskModel {
    [CmdletBinding()]
    param(
        [object[]]$AccessRules = @(),
        [string]$Domain,
        [string]$LogPath,
        [int]$ProgressInterval = 1000,
        [switch]$ShowProgress
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = 0
    $accessRuleList = @($AccessRules)
    $totalRules = $accessRuleList.Count
    $processedRules = 0
    $activity = 'Classifying AD ACL risk'
    if ($ShowProgress) {
        $startMessage = "ACL risk classification started: $totalRules raw ACL entries to evaluate."
        Write-Host $startMessage
        if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
            Write-ADPostureLog -Message $startMessage -Path $LogPath
        }
    }

    foreach ($rule in $accessRuleList) {
        $processedRules++
        if ($ShowProgress -and ($processedRules -eq 1 -or $processedRules -eq $totalRules -or ($ProgressInterval -gt 0 -and ($processedRules % $ProgressInterval) -eq 0))) {
            $percentComplete = if ($totalRules -gt 0) { [Math]::Min(100, [Math]::Round(($processedRules / $totalRules) * 100, 0)) } else { 0 }
            $message = "ACL risk classification progress: $processedRules/$totalRules raw ACL entries evaluated; $($findings.Count) findings so far."
            Write-Progress -Activity $activity -Status $message -PercentComplete $percentComplete
            Write-Host $message
            if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
                Write-ADPostureLog -Message $message -Path $LogPath
            }
        }

        $accessType = [string]$rule.AccessControlType
        if ($accessType -and $accessType -ne 'Allow') { continue }

        $rights = ConvertTo-ADPostureAclRightsList -Rights $rule.ActiveDirectoryRights
        $objectTypeName = if ($rule.ObjectTypeName) { [string]$rule.ObjectTypeName } else { Get-ADPostureAclObjectTypeName -ObjectType $rule.ObjectType }
        $trusteeName = if ($rule.TrusteeName) { $rule.TrusteeName } elseif ($rule.IdentityReference) { [string]$rule.IdentityReference } else { 'Unknown trustee' }
        $rawTrustee = if ($rule.RawTrustee) { [string]$rule.RawTrustee } elseif ($rule.IdentityReference) { [string]$rule.IdentityReference } else { $trusteeName }
        $trusteeSid = if ($rule.TrusteeSid) { [string]$rule.TrusteeSid } elseif ($rawTrustee -match '^S-\d-\d+-.+') { $rawTrustee } else { $null }
        $unresolvedTrustee = [bool]$rule.UnresolvedTrustee
        if (-not $unresolvedTrustee -and $trusteeSid -and -not $rule.TrusteeDistinguishedName -and (($rawTrustee -eq $trusteeSid) -or ($rawTrustee -match '^(?i:Account Unknown)'))) {
            $unresolvedTrustee = $true
        }
        if (Test-ADPostureAclBuiltinPrincipal -Name $trusteeName) { continue }

        $template = Get-ADPostureAclFindingTemplate -Rights $rights -ObjectType $rule.ObjectType -ObjectTypeName $objectTypeName
        if (-not $template) { continue }

        $index++
        $targetName = if ($rule.TargetName) { $rule.TargetName } elseif ($rule.TargetDistinguishedName) { $rule.TargetDistinguishedName } else { 'Unknown target' }
        $targetClass = if ($rule.TargetObjectClass) { $rule.TargetObjectClass } else { 'unknown' }
        $targetContext = Resolve-ADPostureAclTargetContext -TargetName $targetName -TargetDistinguishedName $rule.TargetDistinguishedName -TargetObjectClass $targetClass -NormalizedRight $template.NormalizedRight
        $riskScore = [Math]::Round(([double]$template.Score * [double]$targetContext.Multiplier), 2)
        $tags = @($template.Tags + $targetContext.Tags | Sort-Object -Unique)
        if ($unresolvedTrustee) { $tags = @($tags + 'UnresolvedTrustee' | Sort-Object -Unique) }
        $sourceDomain = if ($rule.Domain) { $rule.Domain } elseif ($Domain) { $Domain } else { 'unknown-domain' }
        $inheritanceNote = if ($rule.IsInherited) { 'Inherited ACE' } else { 'Direct ACE' }

        $attributeReason = Get-ADPostureAclAttributeReason -NormalizedRight $template.NormalizedRight -ObjectTypeName $objectTypeName -Rights $rights
        $baseReason = if ($attributeReason) { $attributeReason } else { $template.Reason }
        $findingType = $null
        $adminSdHolderImpact = $null
        $reason = "$baseReason Target context: $($targetContext.Context). $inheritanceNote."
        $remediation = $template.Remediation
        if ($targetContext.IsAdminSdHolder) {
            $findingType = 'AdminSDHolderDelegationControl'
            $adminSdHolderImpact = 'AdminSDHolder ACL changes can be propagated by SDProp to adminCount=1 protected users, groups, and computers.'
            $reason = "$baseReason Target context: $($targetContext.Context). $inheritanceNote. AdminSDHolder is the protected-object ACL template; this delegation can be propagated by SDProp to adminCount=1 protected users, groups, and computers."
            $remediation = "$($template.Remediation) Restore the AdminSDHolder ACL to an approved Tier 0 baseline, then review adminCount=1 protected objects for inherited protected-state drift."
        }

        $findings.Add([pscustomobject]@{
            AclFindingId                = 'acl-{0:000000}' -f $index
            Domain                      = $sourceDomain
            SourceDomain                = 'ACL'
            FindingType                 = $findingType
            TargetName                  = $targetName
            TargetDistinguishedName     = $rule.TargetDistinguishedName
            TargetCanonicalName         = $rule.TargetCanonicalName
            TargetObjectSid             = $rule.TargetObjectSid
            TargetObjectGuid            = $rule.TargetObjectGuid
            TargetObjectClass           = $targetClass
            TargetPrivilegeTier         = $targetContext.PrivilegeTier
            TargetRiskContext           = $targetContext.Context
            TrusteeName                 = $trusteeName
            TrusteeSid                  = $trusteeSid
            TrusteeDistinguishedName    = $rule.TrusteeDistinguishedName
            TrusteeObjectClass          = if ($rule.TrusteeObjectClass) { $rule.TrusteeObjectClass } else { 'unknown' }
            RawTrustee                  = $rawTrustee
            UnresolvedTrustee           = $unresolvedTrustee
            EffectiveTrustees           = @($rule.EffectiveTrustees)
            ActiveDirectoryRights       = @($rights)
            NormalizedRight             = $template.NormalizedRight
            ObjectType                  = $rule.ObjectType
            ObjectTypeName              = $objectTypeName
            InheritedObjectType         = $rule.InheritedObjectType
            InheritedObjectTypeName     = if ($rule.InheritedObjectTypeName) { $rule.InheritedObjectTypeName } else { Get-ADPostureAclObjectTypeName -ObjectType $rule.InheritedObjectType }
            InheritanceType             = $rule.InheritanceType
            ObjectFlags                 = $rule.ObjectFlags
            InheritanceFlags            = $rule.InheritanceFlags
            PropagationFlags            = $rule.PropagationFlags
            IsInherited                 = [bool]$rule.IsInherited
            AccessControlType           = if ($accessType) { $accessType } else { 'Allow' }
            RiskScore                   = $riskScore
            Severity                    = Get-ADPostureAclSeverity -Score $riskScore
            Tags                        = $tags
            Reason                      = $reason
            Remediation                 = $remediation
            AdminSdHolderImpact         = $adminSdHolderImpact
            PropagationMechanism        = if ($targetContext.IsAdminSdHolder) { 'SDProp' } else { $null }
            AttackTechniques            = @($template.AttackTechniques)
            EvidenceType                = 'SensitiveAcl'
            SourceDescriptorId          = $rule.SourceDescriptorId
        })
    }

    foreach ($owner in @($AccessRules | Where-Object { [string]$_.AccessControlType -eq 'Owner' })) {
        $targetName = if ($owner.TargetName) { $owner.TargetName } elseif ($owner.TargetDistinguishedName) { $owner.TargetDistinguishedName } else { 'Unknown target' }
        $trusteeName = if ($owner.OwnerName) { [string]$owner.OwnerName } elseif ($owner.TrusteeName) { [string]$owner.TrusteeName } elseif ($owner.IdentityReference) { [string]$owner.IdentityReference } else { 'Unknown owner' }
        $rawTrustee = if ($owner.RawTrustee) { [string]$owner.RawTrustee } elseif ($owner.IdentityReference) { [string]$owner.IdentityReference } else { $trusteeName }
        $trusteeSid = if ($owner.OwnerSid) { [string]$owner.OwnerSid } elseif ($owner.TrusteeSid) { [string]$owner.TrusteeSid } elseif ($rawTrustee -match '(S-\d-\d+(?:-\d+)+)') { $Matches[1] } else { $null }
        $ownerDistinguishedName = if ($owner.OwnerDistinguishedName) { [string]$owner.OwnerDistinguishedName } elseif ($owner.TrusteeDistinguishedName) { [string]$owner.TrusteeDistinguishedName } else { $null }
        $ownerObjectClass = if ($owner.OwnerObjectClass) { [string]$owner.OwnerObjectClass } elseif ($owner.TrusteeObjectClass) { [string]$owner.TrusteeObjectClass } else { 'unknown' }
        $unresolvedTrustee = [bool]$owner.UnresolvedTrustee
        if (-not $unresolvedTrustee -and $trusteeSid -and -not $ownerDistinguishedName -and (($rawTrustee -eq $trusteeSid) -or ($rawTrustee -match '^(?i:Account Unknown)'))) {
            $unresolvedTrustee = $true
        }
        $template = Get-ADPostureAclOwnerFindingTemplate -OwnerName $trusteeName -TargetObjectClass $owner.TargetObjectClass
        if (-not $template) { continue }
        $targetClass = if ($owner.TargetObjectClass) { $owner.TargetObjectClass } else { 'unknown' }
        $targetContext = Resolve-ADPostureAclTargetContext -TargetName $targetName -TargetDistinguishedName $owner.TargetDistinguishedName -TargetObjectClass $targetClass -NormalizedRight $template.NormalizedRight
        $riskScore = [Math]::Round(([double]$template.Score * [double]$targetContext.Multiplier), 2)
        $tags = @($template.Tags + $targetContext.Tags | Sort-Object -Unique)
        if ($unresolvedTrustee) { $tags = @($tags + 'UnresolvedTrustee' | Sort-Object -Unique) }
        $sourceDomain = if ($owner.Domain) { $owner.Domain } elseif ($Domain) { $Domain } else { 'unknown-domain' }
        $index++
        $findingType = $null
        $adminSdHolderImpact = $null
        $reason = "$($template.Reason) Target context: $($targetContext.Context)."
        $remediation = $template.Remediation
        if ($targetContext.IsAdminSdHolder) {
            $findingType = 'AdminSDHolderUnexpectedOwner'
            $adminSdHolderImpact = 'AdminSDHolder ownership can influence the ACL template that SDProp applies to adminCount=1 protected users, groups, and computers.'
            $reason = "$($template.Reason) Target context: $($targetContext.Context). AdminSDHolder is the protected-object ACL template; unexpected ownership can alter the permissions SDProp applies to adminCount=1 protected objects."
            $remediation = "$($template.Remediation) Restore AdminSDHolder ownership to the approved Tier 0 owner and validate the protected-object ACL baseline."
        }

        $findings.Add([pscustomobject]@{
            AclFindingId                = 'acl-{0:000000}' -f $index
            Domain                      = $sourceDomain
            SourceDomain                = 'ACL'
            FindingType                 = $findingType
            TargetName                  = $targetName
            TargetDistinguishedName     = $owner.TargetDistinguishedName
            TargetCanonicalName         = $owner.TargetCanonicalName
            TargetObjectSid             = $owner.TargetObjectSid
            TargetObjectGuid            = $owner.TargetObjectGuid
            TargetObjectClass           = $targetClass
            TargetPrivilegeTier         = $targetContext.PrivilegeTier
            TargetRiskContext           = $targetContext.Context
            OwnerName                   = $trusteeName
            OwnerSid                    = $trusteeSid
            OwnerDistinguishedName      = $ownerDistinguishedName
            OwnerObjectClass            = $ownerObjectClass
            TrusteeName                 = $trusteeName
            TrusteeSid                  = $trusteeSid
            TrusteeDistinguishedName    = $ownerDistinguishedName
            TrusteeObjectClass          = $ownerObjectClass
            RawTrustee                  = $rawTrustee
            UnresolvedTrustee           = $unresolvedTrustee
            ActiveDirectoryRights       = @('Owner')
            NormalizedRight             = $template.NormalizedRight
            ObjectType                  = 'Owner'
            ObjectTypeName              = 'Owner'
            InheritedObjectType         = 'None'
            InheritedObjectTypeName     = 'None'
            InheritanceType             = 'None'
            ObjectFlags                 = 'None'
            InheritanceFlags            = 'None'
            PropagationFlags            = 'None'
            IsInherited                 = $false
            AccessControlType           = 'Owner'
            RiskScore                   = $riskScore
            Severity                    = Get-ADPostureAclSeverity -Score $riskScore
            Tags                        = $tags
            Reason                      = $reason
            Remediation                 = $remediation
            AdminSdHolderImpact         = $adminSdHolderImpact
            PropagationMechanism        = if ($targetContext.IsAdminSdHolder) { 'SDProp' } else { $null }
            AttackTechniques            = @($template.AttackTechniques)
            EvidenceType                = 'SensitiveAclOwner'
            SourceDescriptorId          = if ($owner.SourceDescriptorId) { $owner.SourceDescriptorId } else { $owner.TargetDistinguishedName }
        })
    }

    if ($ShowProgress) {
        Write-Progress -Activity $activity -Completed
        $completeMessage = "ACL risk classification complete: $processedRules/$totalRules raw ACL entries evaluated, $($findings.Count) ACL findings produced."
        Write-Host $completeMessage
        if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
            Write-ADPostureLog -Message $completeMessage -Path $LogPath
        }
    }

    [pscustomobject]@{
        AclFindings = @($findings)
    }
}
