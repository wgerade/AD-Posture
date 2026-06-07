function ConvertTo-ADPostureAclTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,
        [string]$TargetType = 'DirectoryObject',
        [string]$NameFallback
    )

    $properties = $InputObject.PSObject.Properties
    $name = if ($properties['Name'] -and $properties['Name'].Value) { [string]$properties['Name'].Value } else { $NameFallback }
    if ($properties['DisplayName'] -and $properties['DisplayName'].Value) { $name = [string]$properties['DisplayName'].Value }

    $sid = $null
    if ($properties['SID'] -and $properties['SID'].Value) {
        $sid = if ($properties['SID'].Value.PSObject.Properties['Value']) { [string]$properties['SID'].Value.Value } else { [string]$properties['SID'].Value }
    }
    elseif ($properties['ObjectSid'] -and $properties['ObjectSid'].Value) {
        $sid = if ($properties['ObjectSid'].Value.PSObject.Properties['Value']) { [string]$properties['ObjectSid'].Value.Value } else { [string]$properties['ObjectSid'].Value }
    }

    $objectGuid = $null
    if ($properties['ObjectGUID'] -and $properties['ObjectGUID'].Value) { $objectGuid = $properties['ObjectGUID'].Value }

    $objectClass = $TargetType
    if ($properties['ObjectClass'] -and $properties['ObjectClass'].Value) {
        $objectClassValue = $properties['ObjectClass'].Value
        if ($objectClassValue -is [array]) { $objectClass = [string]$objectClassValue[-1] }
        else { $objectClass = [string]$objectClassValue }
    }

    $distinguishedName = if ($properties['DistinguishedName']) { [string]$properties['DistinguishedName'].Value } else { $null }
    $canonicalName = if ($properties['CanonicalName'] -and $properties['CanonicalName'].Value) { [string]$properties['CanonicalName'].Value } else { $null }

    [pscustomobject]@{
        Name                  = $name
        DistinguishedName     = $distinguishedName
        CanonicalName         = $canonicalName
        ObjectSid             = $sid
        ObjectGuid            = $objectGuid
        ObjectClass           = $objectClass
        AclTargetType         = $TargetType
    }
}

function Add-ADPostureAclTarget {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]]$Targets,
        [Parameter(Mandatory)]
        [hashtable]$SeenDistinguishedNames,
        [Parameter(Mandatory)]
        [object]$Target
    )

    $dn = [string]$Target.DistinguishedName
    if (-not $dn) { return }

    $key = $dn.ToLowerInvariant()
    if ($SeenDistinguishedNames.ContainsKey($key)) { return }

    $SeenDistinguishedNames[$key] = $true
    $Targets.Add($Target)
}

function Add-ADPostureAclTargetsFromQuery {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]]$Targets,
        [Parameter(Mandatory)]
        [hashtable]$SeenDistinguishedNames,
        [Parameter(Mandatory)]
        [scriptblock]$Query,
        [Parameter(Mandatory)]
        [string]$TargetType,
        [string]$LogPath,
        [string]$Description
    )

    try {
        foreach ($entry in @(& $Query)) {
            Add-ADPostureAclTarget -Targets $Targets -SeenDistinguishedNames $SeenDistinguishedNames -Target (ConvertTo-ADPostureAclTarget -InputObject $entry -TargetType $TargetType)
        }
    }
    catch {
        $message = "Could not expand ACL targets for $Description. $($_.Exception.Message)"
        Write-ADPostureLog -Message $message -Level Warning -Path $LogPath
        Write-Warning $message
    }
}

function Add-ADPostureAclTargetsFromSearchBase {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]]$Targets,
        [Parameter(Mandatory)]
        [hashtable]$SeenDistinguishedNames,
        [Parameter(Mandatory)]
        [string]$SearchBase,
        [Parameter(Mandatory)]
        [hashtable]$DomainParams,
        [string]$LogPath,
        [string]$Description
    )

    $ldapFilter = '(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer))'
    Add-ADPostureAclTargetsFromQuery -Targets $Targets -SeenDistinguishedNames $SeenDistinguishedNames -TargetType 'DirectoryObject' -LogPath $LogPath -Description $Description -Query {
        Get-ADObject -LDAPFilter $ldapFilter -SearchBase $SearchBase -SearchScope Subtree -Properties DisplayName,ObjectSid,ObjectGUID,ObjectClass,CanonicalName @DomainParams -ErrorAction Stop
    }
}

function Get-ADPostureAclTargets {
    [CmdletBinding()]
    param(
        [object[]]$BaseTargets,
        [Parameter(Mandatory)]
        [object]$Domain,
        [hashtable]$DomainParams,
        [switch]$IncludeOrganizationalUnits,
        [switch]$IncludeGpoContainers,
        [switch]$IncludePrivilegedUsers,
        [switch]$IncludePrivilegedComputers,
        [switch]$IncludePrivilegedGroups,
        [switch]$IncludeAllObjects,
        [string[]]$SearchBase,
        [string]$LogPath
    )

    if (-not $DomainParams) { $DomainParams = @{} }

    $targets = [System.Collections.Generic.List[object]]::new()
    $seen = @{}

    foreach ($target in @($BaseTargets)) {
        Add-ADPostureAclTarget -Targets $targets -SeenDistinguishedNames $seen -Target $target
    }

    if ($IncludeOrganizationalUnits) {
        Add-ADPostureAclTargetsFromQuery -Targets $targets -SeenDistinguishedNames $seen -TargetType 'organizationalUnit' -LogPath $LogPath -Description 'organizational units' -Query {
            Get-ADOrganizationalUnit -Filter * -Properties ObjectGUID,ObjectClass,CanonicalName @DomainParams -ErrorAction Stop
        }
    }

    if ($IncludeGpoContainers) {
        $policiesDn = "CN=Policies,CN=System,$($Domain.DistinguishedName)"
        Add-ADPostureAclTargetsFromQuery -Targets $targets -SeenDistinguishedNames $seen -TargetType 'groupPolicyContainer' -LogPath $LogPath -Description 'GPO containers' -Query {
            Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -SearchBase $policiesDn -Properties DisplayName,ObjectGUID,ObjectClass,CanonicalName @DomainParams -ErrorAction Stop
        }
    }

    if ($IncludePrivilegedUsers) {
        Add-ADPostureAclTargetsFromQuery -Targets $targets -SeenDistinguishedNames $seen -TargetType 'user' -LogPath $LogPath -Description 'privileged users' -Query {
            Get-ADUser -LDAPFilter '(adminCount=1)' -Properties SID,ObjectGUID,ObjectClass,AdminCount,CanonicalName @DomainParams -ErrorAction Stop
        }
    }

    if ($IncludePrivilegedComputers) {
        Add-ADPostureAclTargetsFromQuery -Targets $targets -SeenDistinguishedNames $seen -TargetType 'computer' -LogPath $LogPath -Description 'privileged computers' -Query {
            Get-ADComputer -LDAPFilter '(adminCount=1)' -Properties SID,ObjectGUID,ObjectClass,AdminCount,CanonicalName @DomainParams -ErrorAction Stop
        }
    }

    if ($IncludePrivilegedGroups) {
        Add-ADPostureAclTargetsFromQuery -Targets $targets -SeenDistinguishedNames $seen -TargetType 'group' -LogPath $LogPath -Description 'privileged groups' -Query {
            Get-ADGroup -LDAPFilter '(adminCount=1)' -Properties SID,ObjectGUID,ObjectClass,AdminCount,CanonicalName @DomainParams -ErrorAction Stop
        }
    }

    if ($IncludeAllObjects) {
        Add-ADPostureAclTargetsFromSearchBase -Targets $targets -SeenDistinguishedNames $seen -SearchBase $Domain.DistinguishedName -DomainParams $DomainParams -LogPath $LogPath -Description 'all domain ACL objects'
    }

    foreach ($base in @($SearchBase | Where-Object { $_ })) {
        Add-ADPostureAclTargetsFromSearchBase -Targets $targets -SeenDistinguishedNames $seen -SearchBase $base -DomainParams $DomainParams -LogPath $LogPath -Description "ACL search base '$base'"
    }

    @($targets)
}
