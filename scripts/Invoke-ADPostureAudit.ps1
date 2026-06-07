#Requires -Version 5.1
<#
.SYNOPSIS
    Runs an AD Posture audit and optionally opens the dashboard.
.EXAMPLE
    .\Invoke-ADPostureAudit.ps1
.EXAMPLE
    .\Invoke-ADPostureAudit.ps1 -Full -OpenExecutive
.EXAMPLE
    .\Invoke-ADPostureAudit.ps1 -IncludeOptionalGroups -OpenDashboard
#>
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [string]$Server,
    [Parameter(ParameterSetName = 'Full')]
    [switch]$Full,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeOptionalGroups,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeAclPosture,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeAclOrganizationalUnits,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeAclGpoContainers,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeAclPrivilegedUsers,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeAclPrivilegedComputers,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeAclPrivilegedGroups,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeAclAllObjects,
    [Parameter(ParameterSetName = 'Default')]
    [string[]]$AclSearchBase,
    [ValidateRange(0, 10000)]
    [int]$AclReadDelayMilliseconds = 25,
    [ValidateRange(0, 10000)]
    [int]$AclEffectiveTrusteeLimit = 100,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeGpoPosture,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeGpoSysvolAcl,
    [Parameter(ParameterSetName = 'Default')]
    [string[]]$GpoSearchBase,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeAdcsPosture,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeKerberosAuthPosture,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeTrustPosture,
    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeDnsPosture,
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,
    [ValidateRange(0, 3650)]
    [int]$PasswordAgeDays = 365,
    [switch]$OpenDashboard,
    [switch]$OpenObjectRisk,
    [switch]$OpenAdcsPosture,
    [switch]$OpenKerberosAuthPosture,
    [switch]$OpenTrustPosture,
    [switch]$OpenDnsPosture,
    [switch]$OpenExecutive,
    [switch]$SkipTimelineRefresh,
    [string]$ModulePath
)

$ErrorActionPreference = 'Stop'

if (-not $ModulePath) {
    $scriptRootPath = if ($PSScriptRoot) {
        $PSScriptRoot
    }
    elseif ($PSCommandPath) {
        Split-Path -Parent $PSCommandPath
    }
    elseif ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    else {
        throw 'Unable to resolve script path. Run from the repository root or pass -ModulePath explicitly.'
    }

    $ModulePath = Join-Path $scriptRootPath '..'
}

$ModulePath = (Resolve-Path -LiteralPath $ModulePath).Path
Import-Module (Join-Path $ModulePath 'ADPosture.psd1') -Force

$auditParams = @{
    AclReadDelayMilliseconds = $AclReadDelayMilliseconds
    AclEffectiveTrusteeLimit = $AclEffectiveTrusteeLimit
    StaleDays = $StaleDays
    PasswordAgeDays = $PasswordAgeDays
    SkipTimelineRefresh = $SkipTimelineRefresh
}

if ($Server) { $auditParams['Server'] = $Server }

if ($Full) {
    $auditParams['Full'] = $true
}
else {
    $auditParams['IncludeOptionalGroups'] = $IncludeOptionalGroups
    $auditParams['IncludeAclPosture'] = $IncludeAclPosture
    $auditParams['IncludeAclOrganizationalUnits'] = $IncludeAclOrganizationalUnits
    $auditParams['IncludeAclGpoContainers'] = $IncludeAclGpoContainers
    $auditParams['IncludeAclPrivilegedUsers'] = $IncludeAclPrivilegedUsers
    $auditParams['IncludeAclPrivilegedComputers'] = $IncludeAclPrivilegedComputers
    $auditParams['IncludeAclPrivilegedGroups'] = $IncludeAclPrivilegedGroups
    $auditParams['IncludeAclAllObjects'] = $IncludeAclAllObjects
    $auditParams['IncludeGpoPosture'] = $IncludeGpoPosture
    $auditParams['IncludeGpoSysvolAcl'] = $IncludeGpoSysvolAcl
    $auditParams['IncludeAdcsPosture'] = $IncludeAdcsPosture
    $auditParams['IncludeKerberosAuthPosture'] = $IncludeKerberosAuthPosture
    $auditParams['IncludeTrustPosture'] = $IncludeTrustPosture
    $auditParams['IncludeDnsPosture'] = $IncludeDnsPosture
    if ($AclSearchBase) { $auditParams['AclSearchBase'] = $AclSearchBase }
    if ($GpoSearchBase) { $auditParams['GpoSearchBase'] = $GpoSearchBase }
}

$snapshot = Invoke-ADPostureAudit @auditParams

if ($OpenExecutive) {
    Open-ADPostureDashboard -View Executive
}
elseif ($OpenObjectRisk) {
    Open-ADPostureDashboard -View ObjectRisk
}
elseif ($OpenAdcsPosture) {
    Open-ADPostureDashboard -View AdcsPosture
}
elseif ($OpenKerberosAuthPosture) {
    Open-ADPostureDashboard -View KerberosAuthPosture
}
elseif ($OpenTrustPosture) {
    Open-ADPostureDashboard -View TrustPosture
}
elseif ($OpenDnsPosture) {
    Open-ADPostureDashboard -View DnsPosture
}
elseif ($OpenDashboard) {
    Open-ADPostureDashboard -View Current
}

$snapshot
