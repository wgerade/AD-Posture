function Get-ADPostureFindingDomain {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $Finding)

    if (-not [string]::IsNullOrWhiteSpace([string]$Finding.PostureDomain)) {
        return [string]$Finding.PostureDomain
    }

    switch -Regex ([string]$Finding.FindingType) {
        'ACL|AccessControl' { return 'ACL' }
        'GPO|GroupPolicy' { return 'GPO' }
        'ADCS|Certificate' { return 'ADCS' }
        'DNS' { return 'DNS' }
        'Kerberos|KRB' { return 'Kerberos' }
        'Trust' { return 'Trust' }
        'Identity|Account|Password|Authentication' { return 'IdentityRisk' }
        default { return 'SensitiveGroups' }
    }
}

function Get-ADPostureFrameworkCrosswalkCatalog {
    [CmdletBinding()]
    param()

    $moduleConfig = Get-ModuleConfig
    $configPath = $moduleConfig.ConfigPath
    $moduleRoot = $moduleConfig.ModuleRoot
    if ([string]::IsNullOrWhiteSpace([string]$moduleRoot)) {
        $moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    $configDir = if ([string]::IsNullOrWhiteSpace([string]$configPath)) {
        Join-Path $moduleRoot 'config'
    }
    elseif (Test-Path -LiteralPath $configPath -PathType Container) {
        $configPath
    }
    else {
        Split-Path -Parent $configPath
    }
    $path = Join-Path $configDir 'FrameworkCrosswalk.json'
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{ SchemaVersion = '1.0'; CatalogVersion = 'missing'; Mappings = @() }
    }

    try { Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
    catch {
        Write-Warning "Framework crosswalk catalog could not be loaded: $($_.Exception.Message)"
        [pscustomobject]@{ SchemaVersion = '1.0'; CatalogVersion = 'invalid'; Mappings = @() }
    }
}

function Get-ADPostureFrameworkMappings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object] $Finding,
        [object] $Catalog = (Get-ADPostureFrameworkCrosswalkCatalog)
    )

    $domain = Get-ADPostureFindingDomain -Finding $Finding
    $type = [string]$Finding.FindingType
    @($Catalog.Mappings | Where-Object {
        [string]$_.Domain -eq $domain -and
        ([string]::IsNullOrWhiteSpace([string]$_.FindingType) -or [string]$_.FindingType -eq $type)
    } | ForEach-Object {
        [pscustomobject]@{
            Framework      = [string]$_.Framework
            ControlId      = [string]$_.ControlId
            ControlName    = [string]$_.ControlName
            Rationale      = [string]$_.Rationale
            CatalogVersion = [string]$Catalog.CatalogVersion
        }
    })
}

function New-ADPostureOrphanedSensitiveGroupFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object] $GroupSummary,
        [string] $Domain
    )

    if ([int]$GroupSummary.MemberCount -ne 0 -or [string]::IsNullOrWhiteSpace([string]$GroupSummary.SensitiveGroup)) {
        return $null
    }

    $groupName = [string]$GroupSummary.SensitiveGroup
    $tier = if ([string]::IsNullOrWhiteSpace([string]$GroupSummary.PrivilegeTier)) { 'Tier 0' } else { [string]$GroupSummary.PrivilegeTier }
    $severity = if ($tier -match '0') { 'High' } else { 'Medium' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Domain|$groupName|OrphanedSensitiveGroup"))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
    }
    finally { $sha.Dispose() }

    [pscustomobject]@{
        FindingId                    = "orphan-$hash"
        FindingType                  = 'OrphanedSensitiveGroup'
        PostureDomain                = 'SensitiveGroups'
        Domain                       = $Domain
        SensitiveGroup               = $groupName
        MemberSam                    = $groupName
        MemberDisplay                = $groupName
        MemberDn                     = [string]$GroupSummary.GroupDistinguishedName
        AccountType                  = 'Group'
        PrivilegeTier                = $tier
        IsDirect                     = $true
        NestingDepth                 = 0
        RiskScore                    = if ($severity -eq 'High') { 6.0 } else { 4.0 }
        Severity                     = $severity
        RemediationDifficulty        = 'High'
        CleanupActions               = 'Validate ownership, dependencies, delegation, and business purpose before removing or redesigning the empty privileged group.'
        CanGenerateRemediationScript = $false
        RemediationBlockedReason     = 'Deleting privileged groups is never automated by this tool.'
        Tags                         = @('OrphanedSensitiveGroup', 'Governance')
    }
}

function Get-ADPostureFrameworkSummary {
    [CmdletBinding()]
    param([object[]] $Findings)

    @($Findings | ForEach-Object { @($_.FrameworkMappings) } | Group-Object Framework, ControlId | ForEach-Object {
        $sample = $_.Group | Select-Object -First 1
        [pscustomobject]@{
            Framework    = [string]$sample.Framework
            ControlId    = [string]$sample.ControlId
            ControlName  = [string]$sample.ControlName
            FindingCount = $_.Count
        }
    } | Sort-Object Framework, ControlId)
}
