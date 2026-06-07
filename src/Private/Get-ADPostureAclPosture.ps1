function Get-ADPostureAclSchemaObjectTypeMap {
    [CmdletBinding()]
    param()

    $names = @(
        'ms-Mcs-AdmPwd',
        'ms-Mcs-AdmPwdExpirationTime',
        'msLAPS-PasswordExpirationTime',
        'msLAPS-Password',
        'msLAPS-EncryptedPassword',
        'msLAPS-EncryptedPasswordHistory',
        'msLAPS-EncryptedDSRMPassword',
        'msLAPS-EncryptedDSRMPasswordHistory',
        'msLAPS-CurrentPasswordVersion'
    )

    $map = @{}
    try {
        $rootDse = Get-ADRootDSE -ErrorAction Stop
        $filter = '(|' + (($names | ForEach-Object { "(lDAPDisplayName=$_)"} ) -join '') + ')'
        $schemaObjects = @(Get-ADObject -SearchBase $rootDse.schemaNamingContext -LDAPFilter $filter -Properties lDAPDisplayName,schemaIDGUID -ErrorAction Stop)
        foreach ($schemaObject in $schemaObjects) {
            if ($schemaObject.schemaIDGUID -and $schemaObject.lDAPDisplayName) {
                $map[([guid]$schemaObject.schemaIDGUID).Guid.ToLowerInvariant()] = [string]$schemaObject.lDAPDisplayName
            }
        }
    }
    catch {
        Write-Verbose "Could not resolve LAPS schema GUIDs: $($_.Exception.Message)"
    }

    $map
}

function Get-ADPostureAclSecurityDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    $adPath = "AD:\$DistinguishedName"
    try {
        return Get-Acl -LiteralPath $adPath -ErrorAction Stop
    }
    catch {
        $providerError = $_.Exception.Message
        try {
            $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DistinguishedName")
            $security = $entry.ObjectSecurity
            $owner = $null
            try {
                $owner = $security.GetOwner([System.Security.Principal.NTAccount]).Value
            }
            catch {
                $owner = $security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            }

            [pscustomobject]@{
                Owner = $owner
                Access = @($security.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]))
            }
        }
        catch {
            throw "AD provider failed for '$adPath' ($providerError). LDAP fallback also failed: $($_.Exception.Message)"
        }
    }
}

function Resolve-ADPostureAclTrustee {
    [CmdletBinding()]
    param(
        [object]$IdentityReference,
        [hashtable]$DomainParams,
        [hashtable]$Cache
    )

    if (-not $Cache) { $Cache = @{} }
    $raw = if ($null -ne $IdentityReference) { [string]$IdentityReference } else { '' }
    $cacheKey = $raw.ToLowerInvariant()
    if ($Cache.ContainsKey($cacheKey)) { return $Cache[$cacheKey] }

    if ((Get-Command Test-ADPostureAclBuiltinPrincipal -ErrorAction SilentlyContinue) -and (Test-ADPostureAclBuiltinPrincipal -Name $raw)) {
        $result = [pscustomobject]@{
            Name = $raw
            Sid = $null
            DistinguishedName = $null
            ObjectClass = $null
            Raw = $raw
            IsUnresolved = $false
        }
        $Cache[$cacheKey] = $result
        return $result
    }

    $name = $raw
    $sid = $null
    $distinguishedName = $null
    $objectClass = $null
    $isUnresolved = $false

    if ($raw -match '(S-\d-\d+(?:-\d+)+)') {
        $sid = $Matches[1]
    }
    elseif ($IdentityReference -and $IdentityReference.PSObject.Methods['Translate']) {
        try {
            $sid = $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Write-Verbose "Could not translate ACL trustee '$raw' to SID: $($_.Exception.Message)"
        }
    }

    if ($sid) {
        try {
            $lookupParams = if ($DomainParams) { $DomainParams } else { @{} }
            $adObject = Get-ADObject -Filter "ObjectSid -eq '$sid'" -Properties DisplayName,ObjectSid,ObjectClass,SamAccountName @lookupParams -ErrorAction Stop | Select-Object -First 1
            if ($adObject) {
                $distinguishedName = [string]$adObject.DistinguishedName
                $objectClassValue = $adObject.ObjectClass
                $objectClass = if ($objectClassValue -is [array]) { [string]$objectClassValue[-1] } else { [string]$objectClassValue }
                if (-not $name -or $name -eq $sid -or $name -match '^(?i:Account Unknown)') {
                    if ($adObject.SamAccountName) { $name = [string]$adObject.SamAccountName }
                    elseif ($adObject.DisplayName) { $name = [string]$adObject.DisplayName }
                    elseif ($adObject.Name) { $name = [string]$adObject.Name }
                }
            }
        }
        catch {
            Write-Verbose "Could not resolve ACL trustee SID '$sid' in AD: $($_.Exception.Message)"
        }
    }

    if ((-not $sid -and $raw -match '^(?i:Account Unknown|Unknown trustee)') -or
        ($sid -and -not $distinguishedName -and ($raw -eq $sid -or $raw -match '^(?i:Account Unknown)'))) {
        $isUnresolved = $true
    }

    $result = [pscustomobject]@{
        Name = $name
        Sid = $sid
        DistinguishedName = $distinguishedName
        ObjectClass = $objectClass
        Raw = $raw
        IsUnresolved = $isUnresolved
    }
    $Cache[$cacheKey] = $result
    $result
}

function ConvertTo-ADPostureAclEffectiveTrustee {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,
        [string]$DirectTrusteeName,
        [int]$NestingDepth = 1
    )

    $properties = $InputObject.PSObject.Properties
    $name = if ($properties['SamAccountName'] -and $properties['SamAccountName'].Value) {
        [string]$properties['SamAccountName'].Value
    }
    elseif ($properties['Name'] -and $properties['Name'].Value) {
        [string]$properties['Name'].Value
    }
    else {
        'Unknown effective trustee'
    }

    $sid = $null
    if ($properties['SID'] -and $properties['SID'].Value) {
        $sid = if ($properties['SID'].Value.PSObject.Properties['Value']) { [string]$properties['SID'].Value.Value } else { [string]$properties['SID'].Value }
    }
    elseif ($properties['ObjectSid'] -and $properties['ObjectSid'].Value) {
        $sid = if ($properties['ObjectSid'].Value.PSObject.Properties['Value']) { [string]$properties['ObjectSid'].Value.Value } else { [string]$properties['ObjectSid'].Value }
    }

    $objectClass = 'unknown'
    if ($properties['ObjectClass'] -and $properties['ObjectClass'].Value) {
        $classValue = $properties['ObjectClass'].Value
        $objectClass = if ($classValue -is [array]) { [string]$classValue[-1] } else { [string]$classValue }
    }

    [pscustomobject]@{
        Name              = $name
        Sid               = $sid
        DistinguishedName = if ($properties['DistinguishedName']) { [string]$properties['DistinguishedName'].Value } else { $null }
        ObjectClass       = $objectClass
        NestingDepth      = $NestingDepth
        Path              = if ($DirectTrusteeName) { "$name -> $DirectTrusteeName" } else { $name }
    }
}

function ConvertTo-ADPostureLdapFilterValue {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value) { return '' }
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([char]0, '\00')
}

function Resolve-ADPostureAclEffectiveTrustees {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Trustee,
        [hashtable]$DomainParams,
        [hashtable]$Cache,
        [int]$Limit = 100
    )

    if (-not $Trustee -or $Trustee.ObjectClass -ne 'group' -or -not $Trustee.DistinguishedName) { return @() }
    if ($Limit -le 0) { return @() }
    if (-not $Cache) { $Cache = @{} }
    $cacheKey = ([string]$Trustee.DistinguishedName).ToLowerInvariant()
    if ($Cache.ContainsKey($cacheKey)) { return @($Cache[$cacheKey]) }

    try {
        $lookupParams = if ($DomainParams) { $DomainParams } else { @{} }
        $escapedGroupDn = ConvertTo-ADPostureLdapFilterValue -Value ([string]$Trustee.DistinguishedName)
        $ldapFilter = "(memberOf:1.2.840.113556.1.4.1941:=$escapedGroupDn)"
        $pageSize = [Math]::Min(1000, [Math]::Max(1, $Limit))
        $members = @(Get-ADObject -LDAPFilter $ldapFilter -Properties SamAccountName,ObjectSid,ObjectClass,DistinguishedName -ResultPageSize $pageSize -ResultSetSize $Limit @lookupParams -ErrorAction Stop |
            ForEach-Object { ConvertTo-ADPostureAclEffectiveTrustee -InputObject $_ -DirectTrusteeName $Trustee.Name })
        $Cache[$cacheKey] = @($members)
        return @($members)
    }
    catch {
        Write-Verbose "Could not expand effective ACL trustees for '$($Trustee.Name)': $($_.Exception.Message)"
        $Cache[$cacheKey] = @()
        return @()
    }
}

function Get-ADPostureAclPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Targets,
        [string]$Domain,
        [hashtable]$DomainParams,
        [string]$LogPath,
        [int]$ProgressInterval = 100,
        [ValidateRange(0, 10000)]
        [int]$ReadDelayMilliseconds = 0,
        [ValidateRange(0, 10000)]
        [int]$EffectiveTrusteeLimit = 100
    )

    $rules = [System.Collections.Generic.List[object]]::new()
    $seenTargets = @{}
    $schemaObjectTypeMap = Get-ADPostureAclSchemaObjectTypeMap
    $targetList = @($Targets)
    $totalTargets = $targetList.Count
    $processedTargets = 0
    $activity = "Collecting AD ACL posture"
    $trusteeCache = @{}
    $effectiveTrusteeCache = @{}
    $collectionStarted = Get-Date

    foreach ($target in $targetList) {
        $processedTargets++
        $dn = [string]$target.DistinguishedName
        if (-not $dn -or $seenTargets.ContainsKey($dn.ToLowerInvariant())) { continue }
        $seenTargets[$dn.ToLowerInvariant()] = $true
        $percentComplete = if ($totalTargets -gt 0) { [Math]::Min(100, [Math]::Round(($processedTargets / $totalTargets) * 100, 0)) } else { 0 }

        Write-Progress -Activity $activity -Status "Reading ACL $processedTargets of $totalTargets - $dn" -PercentComplete $percentComplete
        if ($processedTargets -eq 1 -or $processedTargets -eq $totalTargets -or ($ProgressInterval -gt 0 -and ($processedTargets % $ProgressInterval) -eq 0)) {
            $message = "ACL progress: $processedTargets/$totalTargets targets processed. Current target: $dn"
            Write-Host $message
            if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
                Write-ADPostureLog -Message $message -Path $LogPath
            }
        }

        try {
            $acl = Get-ADPostureAclSecurityDescriptor -DistinguishedName $dn -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not read ACL for '$dn': $($_.Exception.Message)"
            continue
        }

        if ($acl.Owner) {
            $ownerTrustee = Resolve-ADPostureAclTrustee -IdentityReference $acl.Owner -DomainParams $DomainParams -Cache $trusteeCache
            $rules.Add([pscustomobject]@{
                Domain                  = $Domain
                TargetName              = $target.Name
                TargetDistinguishedName = $dn
                TargetCanonicalName     = $target.CanonicalName
                TargetObjectSid         = $target.ObjectSid
                TargetObjectGuid        = $target.ObjectGuid
                TargetObjectClass       = $target.ObjectClass
                IdentityReference       = [string]$acl.Owner
                OwnerName               = $ownerTrustee.Name
                OwnerSid                = $ownerTrustee.Sid
                OwnerDistinguishedName  = $ownerTrustee.DistinguishedName
                OwnerObjectClass        = $ownerTrustee.ObjectClass
                RawTrustee              = $ownerTrustee.Raw
                UnresolvedTrustee       = $ownerTrustee.IsUnresolved
                ActiveDirectoryRights   = 'Owner'
                AccessControlType       = 'Owner'
                ObjectType              = 'Owner'
                ObjectTypeName          = 'Owner'
                InheritedObjectType     = 'None'
                InheritedObjectTypeName = 'None'
                InheritanceType         = 'None'
                IsInherited             = $false
                SourceDescriptorId      = $dn
            })
        }

        foreach ($ace in @($acl.Access)) {
            $trustee = Resolve-ADPostureAclTrustee -IdentityReference $ace.IdentityReference -DomainParams $DomainParams -Cache $trusteeCache
            $effectiveTrustees = Resolve-ADPostureAclEffectiveTrustees -Trustee $trustee -DomainParams $DomainParams -Cache $effectiveTrusteeCache -Limit $EffectiveTrusteeLimit
            $objectType = [string]$ace.ObjectType
            $inheritedObjectType = [string]$ace.InheritedObjectType
            $objectTypeName = if ($schemaObjectTypeMap.ContainsKey($objectType.ToLowerInvariant())) { $schemaObjectTypeMap[$objectType.ToLowerInvariant()] } else { Get-ADPostureAclObjectTypeName -ObjectType $objectType }
            $inheritedObjectTypeName = if ($schemaObjectTypeMap.ContainsKey($inheritedObjectType.ToLowerInvariant())) { $schemaObjectTypeMap[$inheritedObjectType.ToLowerInvariant()] } else { Get-ADPostureAclObjectTypeName -ObjectType $inheritedObjectType }

            $rules.Add([pscustomobject]@{
                Domain                  = $Domain
                TargetName              = $target.Name
                TargetDistinguishedName = $dn
                TargetCanonicalName     = $target.CanonicalName
                TargetObjectSid         = $target.ObjectSid
                TargetObjectGuid        = $target.ObjectGuid
                TargetObjectClass       = $target.ObjectClass
                IdentityReference       = [string]$ace.IdentityReference
                TrusteeName             = $trustee.Name
                TrusteeSid              = $trustee.Sid
                TrusteeDistinguishedName = $trustee.DistinguishedName
                TrusteeObjectClass      = $trustee.ObjectClass
                RawTrustee              = $trustee.Raw
                UnresolvedTrustee       = $trustee.IsUnresolved
                EffectiveTrustees       = @($effectiveTrustees)
                ActiveDirectoryRights   = [string]$ace.ActiveDirectoryRights
                AccessControlType       = [string]$ace.AccessControlType
                ObjectType              = $objectType
                ObjectTypeName          = $objectTypeName
                InheritedObjectType     = $inheritedObjectType
                InheritedObjectTypeName = $inheritedObjectTypeName
                InheritanceType         = [string]$ace.InheritanceType
                ObjectFlags             = [string]$ace.ObjectFlags
                InheritanceFlags        = [string]$ace.InheritanceFlags
                PropagationFlags        = [string]$ace.PropagationFlags
                IsInherited             = [bool]$ace.IsInherited
                SourceDescriptorId      = $dn
            })
        }

        if ($ReadDelayMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $ReadDelayMilliseconds
        }
    }

    Write-Progress -Activity $activity -Completed
    $collectionElapsed = [int]((Get-Date) - $collectionStarted).TotalSeconds
    $completeMessage = "ACL posture collection complete in ${collectionElapsed}s: $processedTargets/$totalTargets targets processed, $($rules.Count) raw ACL entries normalized for risk analysis."
    Write-Host $completeMessage
    if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
        Write-ADPostureLog -Message $completeMessage -Path $LogPath
    }

    $analysisStarted = Get-Date
    $riskModel = ConvertTo-ADAclRiskModel -AccessRules @($rules) -Domain $Domain -LogPath $LogPath -ProgressInterval ([Math]::Max($ProgressInterval * 10, 1000)) -ShowProgress
    $analysisElapsed = [int]((Get-Date) - $analysisStarted).TotalSeconds
    $finalMessage = "ACL posture analysis complete in ${analysisElapsed}s: $(@($riskModel.AclFindings).Count) ACL findings ready for object-risk modeling."
    Write-Host $finalMessage
    if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
        Write-ADPostureLog -Message $finalMessage -Path $LogPath
    }

    $riskModel
}
