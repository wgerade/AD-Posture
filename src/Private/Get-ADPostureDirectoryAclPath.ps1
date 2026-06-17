function Get-ADPostureAdDriveQualifier {
    <#
    .SYNOPSIS
    Returns the AD provider drive name to use for directory ACL reads.
    .DESCRIPTION
    The default AD: drive always talks to the default domain context, which silently ignores an
    operator-selected -Server. When DomainParams carries a Server, a dedicated module-scoped drive
    bound to that server is created once and reused; if the drive cannot be created the default
    AD: drive is used so collection still works in the single-domain case.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$DomainParams
    )

    $server = if ($DomainParams -and $DomainParams['Server']) { [string]$DomainParams['Server'] } else { $null }
    if ([string]::IsNullOrWhiteSpace($server)) { return 'AD' }

    if (-not $script:ADPostureServerAdDrives) { $script:ADPostureServerAdDrives = @{} }
    $key = $server.ToLowerInvariant()
    if ($script:ADPostureServerAdDrives.ContainsKey($key)) { return $script:ADPostureServerAdDrives[$key] }

    $driveName = "ADPostureSrv$($script:ADPostureServerAdDrives.Count)"
    try {
        if (-not (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Root '' -Server $server -Scope Script -ErrorAction Stop | Out-Null
        }
        $script:ADPostureServerAdDrives[$key] = $driveName
    }
    catch {
        Write-Verbose "Could not create a server-bound AD drive for '$server'; ACL reads fall back to the default AD: drive. $($_.Exception.Message)"
        $script:ADPostureServerAdDrives[$key] = 'AD'
    }

    $script:ADPostureServerAdDrives[$key]
}

function Get-ADPostureAdAclPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName,
        [hashtable]$DomainParams
    )

    $drive = Get-ADPostureAdDriveQualifier -DomainParams $DomainParams
    "${drive}:\$DistinguishedName"
}

function Get-ADPostureLdapPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName,
        [hashtable]$DomainParams
    )

    $server = if ($DomainParams -and $DomainParams['Server']) { [string]$DomainParams['Server'] } else { $null }
    if ([string]::IsNullOrWhiteSpace($server)) { return "LDAP://$DistinguishedName" }
    "LDAP://$server/$DistinguishedName"
}
