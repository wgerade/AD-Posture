function Get-ADPostureIdentityRiskSeverity {
    param([double]$RiskScore)

    if ($RiskScore -ge 10) { return 'Critical' }
    if ($RiskScore -ge 7) { return 'High' }
    if ($RiskScore -ge 4) { return 'Medium' }
    if ($RiskScore -gt 0) { return 'Low' }
    'Informational'
}

function Get-ADPostureIdentityRiskPrincipalName {
    param($Principal)

    foreach ($property in @('SamAccountName', 'sAMAccountName', 'Name', 'DisplayName')) {
        if ($Principal.PSObject.Properties[$property] -and -not [string]::IsNullOrWhiteSpace([string]$Principal.$property)) {
            return [string]$Principal.$property
        }
    }

    'Unknown principal'
}

function Get-ADPostureIdentityRiskPrincipalTier {
    param($Principal)

    if ($Principal.PSObject.Properties['PrivilegeTier'] -and $Principal.PrivilegeTier) { return [string]$Principal.PrivilegeTier }
    if ($Principal.PSObject.Properties['AdminCount'] -and [int]$Principal.AdminCount -eq 1) { return 'Tier 0' }
    if ($Principal.PSObject.Properties['adminCount'] -and [int]$Principal.adminCount -eq 1) { return 'Tier 0' }
    'Tier 1'
}

function Get-ADPostureIdentityRiskSidHistoryValues {
    param($Principal)

    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($property in @('SIDHistory', 'sIDHistory')) {
        if (-not $Principal.PSObject.Properties[$property] -or -not $Principal.$property) { continue }
        foreach ($value in @($Principal.$property)) {
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $values.Add([string]$value)
            }
        }
    }

    @($values)
}

function Get-ADPostureIdentityRiskAdminCountValue {
    param($Principal)

    foreach ($property in @('AdminCount', 'adminCount')) {
        if ($Principal.PSObject.Properties[$property] -and $null -ne $Principal.$property) {
            return [int]$Principal.$property
        }
    }

    $null
}

function Get-ADPostureIdentityRiskMemberOfValues {
    param($Principal)

    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($property in @('MemberOf', 'memberOf')) {
        if (-not $Principal.PSObject.Properties[$property] -or -not $Principal.$property) { continue }
        foreach ($value in @($Principal.$property)) {
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $values.Add([string]$value)
            }
        }
    }

    @($values)
}

function Get-ADPostureIdentityRiskProtectedGroupNames {
    @(
        'Administrators',
        'Account Operators',
        'Backup Operators',
        'Cert Publishers',
        'DnsAdmins',
        'Domain Admins',
        'Domain Controllers',
        'Enterprise Admins',
        'Enterprise Key Admins',
        'Group Policy Creator Owners',
        'Key Admins',
        'Print Operators',
        'Protected Users',
        'Read-only Domain Controllers',
        'Schema Admins',
        'Server Operators'
    )
}

function Test-ADPostureIdentityRiskProtectedGroupReference {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    foreach ($groupName in @(Get-ADPostureIdentityRiskProtectedGroupNames)) {
        $escaped = [regex]::Escape($groupName)
        if ($Value -match "^(?i:$escaped)$") { return $true }
        if ($Value -match "(?i)(^|,)CN=$escaped,") { return $true }
    }

    $false
}

function Test-ADPostureIdentityRiskCurrentProtectedContext {
    param($Principal)

    $name = Get-ADPostureIdentityRiskPrincipalName -Principal $Principal
    if (Test-ADPostureIdentityRiskProtectedGroupReference -Value $name) { return $true }

    foreach ($memberOf in @(Get-ADPostureIdentityRiskMemberOfValues -Principal $Principal)) {
        if (Test-ADPostureIdentityRiskProtectedGroupReference -Value $memberOf) { return $true }
    }

    $false
}

function New-ADPostureIdentityRiskFinding {
    param(
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$FindingType,
        [Parameter(Mandatory)][string]$RiskPattern,
        [Parameter(Mandatory)][double]$RiskScore,
        [string]$MitreId,
        [string]$Principal,
        [string]$PrincipalSam,
        [string]$PrincipalDn,
        [string]$PrincipalSid,
        [string]$PrincipalClass,
        [string]$PrivilegeTier,
        [string]$Setting,
        [object]$ObservedValue,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$Remediation,
        [string[]]$Tags = @()
    )

    [pscustomobject]@{
        IdentityRiskFindingId = 'identity-{0:000000}' -f $Index
        Domain = $Domain
        FindingType = $FindingType
        SourceDomain = 'ObjectRisk'
        MitreId = $MitreId
        RiskPattern = $RiskPattern
        Severity = Get-ADPostureIdentityRiskSeverity -RiskScore $RiskScore
        RiskScore = [Math]::Round($RiskScore, 2)
        Principal = $Principal
        PrincipalSam = $PrincipalSam
        PrincipalDn = $PrincipalDn
        PrincipalSid = $PrincipalSid
        PrincipalClass = $PrincipalClass
        PrivilegeTier = $PrivilegeTier
        Setting = $Setting
        ObservedValue = $ObservedValue
        Reason = $Reason
        Remediation = $Remediation
        Tags = @($Tags + 'IdentityRisk' + 'ObjectRisk' | Where-Object { $_ } | Sort-Object -Unique)
    }
}

function ConvertTo-ADPostureIdentityRiskModel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [object[]]$PrivilegedPrincipals = @(),
        [object[]]$AdminCountPrincipals = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $findingIndex = 0

    foreach ($principal in @($PrivilegedPrincipals)) {
        $sidHistory = @(Get-ADPostureIdentityRiskSidHistoryValues -Principal $principal)
        if (-not $sidHistory.Count) { continue }

        $name = Get-ADPostureIdentityRiskPrincipalName -Principal $principal
        $findingIndex++
        $findings.Add((New-ADPostureIdentityRiskFinding -Index $findingIndex -Domain $Domain -FindingType 'PrivilegedSidHistoryPresent' -RiskPattern 'SIDHistory on privileged identity' -RiskScore 8.0 -MitreId 'T1134.005' -Principal $name -PrincipalSam $name -PrincipalDn $principal.DistinguishedName -PrincipalSid $principal.ObjectSid -PrincipalClass $principal.ObjectClass -PrivilegeTier (Get-ADPostureIdentityRiskPrincipalTier -Principal $principal) -Setting 'sIDHistory' -ObservedValue (@($sidHistory) -join '; ') -Reason "Privileged identity '$name' has SIDHistory values that can alter effective authorization." -Remediation 'Validate the migration requirement, remove stale SIDHistory from privileged identities, or govern it with a time-bound exception.' -Tags @('SIDHistory', 'PrivilegeBoundary')))
    }

    foreach ($principal in @($AdminCountPrincipals)) {
        $adminCount = Get-ADPostureIdentityRiskAdminCountValue -Principal $principal
        if ($adminCount -ne 1) { continue }
        if (Test-ADPostureIdentityRiskCurrentProtectedContext -Principal $principal) { continue }

        $name = Get-ADPostureIdentityRiskPrincipalName -Principal $principal
        $memberOf = @(Get-ADPostureIdentityRiskMemberOfValues -Principal $principal)
        $observedValue = if ($memberOf.Count) { "adminCount=1; memberOf=$(@($memberOf) -join '; ')" } else { 'adminCount=1; no protected memberOf evidence observed' }
        $findingIndex++
        $findings.Add((New-ADPostureIdentityRiskFinding -Index $findingIndex -Domain $Domain -FindingType 'AdminCountOrphanedProtectedObject' -RiskPattern 'Stale AdminSDHolder protected state' -RiskScore 4.0 -MitreId 'T1098' -Principal $name -PrincipalSam $name -PrincipalDn $principal.DistinguishedName -PrincipalSid $principal.ObjectSid -PrincipalClass $principal.ObjectClass -PrivilegeTier 'Tier 0' -Setting 'adminCount' -ObservedValue $observedValue -Reason "Identity '$name' has adminCount=1 but no current protected-group membership was observed in local evidence. It may retain AdminSDHolder/SDProp protected ACL state from prior privilege." -Remediation 'Validate whether the identity is still privileged. If not, remove stale protected state by clearing adminCount only after restoring inheritance and reviewing effective permissions, or document an approved exception.' -Tags @('AdminCount', 'AdminSDHolder', 'SDProp', 'ProtectedObject')))
    }

    [pscustomobject]@{
        IdentityRiskFindings = @($findings)
    }
}

function Get-ADPostureIdentityRiskPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Domain,
        [hashtable]$DomainParams = @{},
        [string]$LogPath
    )

    $privilegedPrincipals = @()
    $adminCountPrincipals = @()
    try {
        $privilegedPrincipals = @(Get-ADObject -LDAPFilter '(&(adminCount=1)(sIDHistory=*))' -Properties sIDHistory,sAMAccountName,objectSid,objectClass,distinguishedName,adminCount @DomainParams -ErrorAction Stop)
    }
    catch {
        Write-ADPostureLog -Message "Could not read privileged SIDHistory identity evidence. $($_.Exception.Message)" -Level Warning -Path $LogPath
    }

    try {
        $adminCountPrincipals = @(Get-ADObject -LDAPFilter '(adminCount=1)' -Properties sAMAccountName,name,objectSid,objectClass,distinguishedName,adminCount,memberOf,sIDHistory @DomainParams -ErrorAction Stop)
    }
    catch {
        Write-ADPostureLog -Message "Could not read adminCount protected identity evidence. $($_.Exception.Message)" -Level Warning -Path $LogPath
    }

    ConvertTo-ADPostureIdentityRiskModel -Domain $Domain.DNSRoot -PrivilegedPrincipals @($privilegedPrincipals) -AdminCountPrincipals @($adminCountPrincipals)
}
