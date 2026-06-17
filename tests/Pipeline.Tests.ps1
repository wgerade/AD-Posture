BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Resolve-ADPosturePipelineServer.ps1')
    . (Join-Path $repoRoot 'src\Private\Get-ModuleConfig.ps1')
    . (Join-Path $repoRoot 'src\Public\Invoke-ADPostureAudit.ps1')
    . (Join-Path $repoRoot 'src\Public\Open-ADPostureDashboard.ps1')

}

Describe 'Invoke-ADPostureAudit pipeline support' {
    It 'resolves a server from a pipeline string' {
        Resolve-ADPosturePipelineServer -InputObject 'dc01.contoso.com' | Should -Be 'dc01.contoso.com'
    }

    It 'resolves a server from common pipeline object properties' {
        $inputObject = [pscustomobject]@{ DNSHostName = 'dc02.contoso.com' }

        Resolve-ADPosturePipelineServer -InputObject $inputObject | Should -Be 'dc02.contoso.com'
    }

    It 'marks InputObject and Server for pipeline binding' {
        $command = Get-Command Invoke-ADPostureAudit

        $command.Parameters['InputObject'].Attributes.ValueFromPipeline | Should -Be $true
        $command.Parameters['Server'].Attributes.ValueFromPipelineByPropertyName | Should -Be $true
        $command.Parameters['Server'].Aliases -contains 'DNSHostName' | Should -Be $true
        $command.Parameters.ContainsKey('Full') | Should -Be $true
        $command.Parameters.ContainsKey('IncludeAclAllObjects') | Should -Be $true
        $command.Parameters.ContainsKey('AclSearchBase') | Should -Be $true
        $command.Parameters.ContainsKey('AclReadDelayMilliseconds') | Should -Be $true
        $command.Parameters.ContainsKey('AclEffectiveTrusteeLimit') | Should -Be $true
        $command.Parameters.ContainsKey('IncludeGpoPosture') | Should -Be $true
        $command.Parameters.ContainsKey('IncludeGpoSysvolAcl') | Should -Be $true
        $command.Parameters.ContainsKey('GpoSearchBase') | Should -Be $true
        $command.Parameters.ContainsKey('IncludeAdcsPosture') | Should -Be $true
        $command.Parameters.ContainsKey('IncludeKerberosAuthPosture') | Should -Be $true
        $command.Parameters.ContainsKey('IncludeTrustPosture') | Should -Be $true
        $command.Parameters.ContainsKey('IncludeDnsPosture') | Should -Be $true
        $command.Parameters.ContainsKey(('IncludeOs' + 'HardeningPosture')) | Should -Be $false
        $command.Parameters.ContainsKey(('IncludeDc' + 'HardeningResults')) | Should -Be $false
        $command.Parameters.ContainsKey(('Dc' + 'HardeningResultPath')) | Should -Be $false
        $command.Parameters.ContainsKey('SkipTimelineRefresh') | Should -Be $true
    }

    It 'expands Full into every posture collector and broad expansion' {
        function Test-ADModuleAvailable {}
        function Get-ModuleConfig { [pscustomobject]@{ ReportPath = $TestDrive } }
        function Get-ADSensitiveGroupCatalog { @() }
        function Get-ADPostureApprovedExceptionCatalog { @() }
        function Invoke-ADPostureAuditTarget {
            [CmdletBinding()]
            param(
                [string]$Server,
                [switch]$IncludeOptionalGroups,
                [switch]$IncludeAclPosture,
                [switch]$IncludeAclOrganizationalUnits,
                [switch]$IncludeAclGpoContainers,
                [switch]$IncludeAclPrivilegedUsers,
                [switch]$IncludeAclPrivilegedComputers,
                [switch]$IncludeAclPrivilegedGroups,
                [switch]$IncludeAclAllObjects,
                [string[]]$AclSearchBase,
                [int]$AclReadDelayMilliseconds,
                [int]$AclEffectiveTrusteeLimit,
                [switch]$IncludeGpoPosture,
                [switch]$IncludeGpoSysvolAcl,
                [string[]]$GpoSearchBase,
                [switch]$IncludeAdcsPosture,
                [switch]$IncludeKerberosAuthPosture,
                [switch]$IncludeTrustPosture,
                [switch]$IncludeDnsPosture,
                [int]$StaleDays,
                [int]$PasswordAgeDays,
                [string]$OutputDirectory,
                [string]$LogPath,
                $Config,
                $Catalog,
                $ApprovedExceptionCatalog
            )

            [pscustomobject]$PSBoundParameters
        }

        $result = Invoke-ADPostureAudit -Full -AclReadDelayMilliseconds 50 -AclEffectiveTrusteeLimit 25

        foreach ($name in @(
            'IncludeOptionalGroups',
            'IncludeAclPosture',
            'IncludeAclOrganizationalUnits',
            'IncludeAclGpoContainers',
            'IncludeAclPrivilegedUsers',
            'IncludeAclPrivilegedComputers',
            'IncludeAclPrivilegedGroups',
            'IncludeAclAllObjects',
            'IncludeGpoPosture',
            'IncludeGpoSysvolAcl',
            'IncludeAdcsPosture',
            'IncludeKerberosAuthPosture',
            'IncludeTrustPosture',
            'IncludeDnsPosture'
        )) {
            [bool]$result.$name | Should -Be $true
        }
        $result.AclReadDelayMilliseconds | Should -Be 50
        $result.AclEffectiveTrusteeLimit | Should -Be 25
        $result.PSObject.Properties[('IncludeOs' + 'HardeningPosture')] | Should -BeNullOrEmpty
        $result.PSObject.Properties[('IncludeDc' + 'HardeningResults')] | Should -BeNullOrEmpty
    }

    It 'does not allow Full to be combined with granular scope switches' {
        { Invoke-ADPostureAudit -Full -IncludeDnsPosture } | Should -Throw
        { Invoke-ADPostureAudit -Full -IncludeAclAllObjects } | Should -Throw
    }

    It 'exposes Full on the operational wrapper script' {
        $command = Get-Command (Join-Path $repoRoot 'scripts\Invoke-ADPostureAudit.ps1')

        $command.Parameters.ContainsKey('Full') | Should -Be $true
        $command.Parameters.ContainsKey('SkipTimelineRefresh') | Should -Be $true
    }

    It 'writes a stable latest snapshot alias for post-audit operator commands' {
        $source = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'src\Public\Invoke-ADPostureAudit.ps1')

        $source | Should -Match 'latest-snapshot\.json'
        $source | Should -Match 'Write-ADPostureAtomicTextFile -Path \$latestSnapshotPath'
        $source | Should -Match 'Write-ADPostureFileHashSidecar -Path \$latestSnapshotPath'
    }

    It 'does not export retired local baseline commands as public v1 APIs' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $repoRoot 'ADPosture.psd1')

        $manifest.FunctionsToExport -contains ('Invoke-ADPostureDc' + 'HardeningAudit') | Should -Be $false
        $manifest.FunctionsToExport -contains ('Import-ADPostureMicrosoftSecurity' + 'BaselineCatalog') | Should -Be $false
    }

    It 'exposes posture dashboard views without the retired coverage view' {
        $command = Get-Command Open-ADPostureDashboard
        $viewParameter = $command.Parameters['View']
        $validateSet = $viewParameter.Attributes |
            Where-Object { $_.TypeId.Name -eq 'ValidateSetAttribute' } |
            Select-Object -First 1

        $validateSet.ValidValues -contains 'AdcsPosture' | Should -Be $true
        $validateSet.ValidValues -contains 'KerberosAuthPosture' | Should -Be $true
        $validateSet.ValidValues -contains 'TrustPosture' | Should -Be $true
        $validateSet.ValidValues -contains 'DnsPosture' | Should -Be $true
        $validateSet.ValidValues -contains ('Os' + 'HardeningPosture') | Should -Be $false
        $validateSet.ValidValues -contains 'Current' | Should -Be $true
        $command.Parameters.ContainsKey('Static') | Should -Be $false
        $command.Parameters.ContainsKey('IdleTimeoutMinutes') | Should -Be $false
        Get-Command Start-ADPostureApi -ErrorAction SilentlyContinue | Should -Be $null
    }
}
