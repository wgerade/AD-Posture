$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\ConvertTo-ADPostureSafeLiteral.ps1')
. (Join-Path $repoRoot 'src\Private\Resolve-ADPostureSensitiveGroupIdentity.ps1')

$script:GroupLookupCalls = $null
$script:GroupsBySid = @{}
$script:GroupsByFilter = @{}

function Get-ADGroup {
    param(
        [string]$Identity,
        [string]$Filter,
        [string]$SearchBase,
        [string]$ErrorAction
    )

    $script:GroupLookupCalls.Add([pscustomobject]@{
        Identity = $Identity
        Filter = $Filter
        SearchBase = $SearchBase
    })

    if ($Identity) {
        if ($script:GroupsBySid.ContainsKey($Identity)) { return $script:GroupsBySid[$Identity] }
        if ($ErrorAction -eq 'Stop') { throw "Cannot find an object with identity: '$Identity'." }
        return $null
    }

    if ($Filter -and $script:GroupsByFilter.ContainsKey($Filter)) { return $script:GroupsByFilter[$Filter] }
    $null
}

function Reset-LookupState {
    $script:GroupLookupCalls = [System.Collections.Generic.List[object]]::new()
    $script:GroupsBySid = @{}
    $script:GroupsByFilter = @{}
}

function New-CatalogEntry {
    param([string]$Name, [string]$Tier)
    [pscustomobject]@{ Name = $Name; Tier = $Tier }
}

$wellKnownRids = [pscustomobject]@{
    'Domain Admins' = 512
    'Enterprise Admins' = 519
    'Backup Operators' = 551
    'Allowed RODC Password Replication Group' = 571
}

$domainSid = 'S-1-5-21-1111111111-2222222222-3333333333'
$rootSid = 'S-1-5-21-9999999999-8888888888-7777777777'
$builtinBase = 'CN=Builtin,DC=corp,DC=example'
$partitions = 'CN=Partitions,CN=Configuration,DC=corp,DC=example'

Describe 'Sensitive group SID-first resolution' {
    It 'resolves builtin groups by S-1-5-32 alias SID even when the name is localized' {
        Reset-LookupState
        $expected = [pscustomobject]@{ Name = 'Opers. de cópia'; DistinguishedName = 'CN=Opers. de cópia,CN=Builtin,DC=corp,DC=example'; SID = 'S-1-5-32-551' }
        $script:GroupsBySid['S-1-5-32-551'] = $expected

        $result = Resolve-ADPostureSensitiveGroupIdentity -CatalogEntry (New-CatalogEntry 'Backup Operators' 'Domain') -DomainSid $domainSid -ForestRootDomainSid $domainSid -BuiltinSearchBase $builtinBase -ForestPartitionsContainer $partitions -WellKnownRids $wellKnownRids

        $result.Name | Should Be 'Opers. de cópia'
        $script:GroupLookupCalls[0].Identity | Should Be 'S-1-5-32-551'
        @($script:GroupLookupCalls | Where-Object { $_.Filter }).Count | Should Be 0
    }

    It 'resolves domain groups by domain SID plus well-known RID' {
        Reset-LookupState
        $expected = [pscustomobject]@{ Name = 'Admins. do Domínio'; SID = "$domainSid-512" }
        $script:GroupsBySid["$domainSid-512"] = $expected

        $result = Resolve-ADPostureSensitiveGroupIdentity -CatalogEntry (New-CatalogEntry 'Domain Admins' 'Domain') -DomainSid $domainSid -ForestRootDomainSid $domainSid -BuiltinSearchBase $builtinBase -ForestPartitionsContainer $partitions -WellKnownRids $wellKnownRids

        $result.Name | Should Be 'Admins. do Domínio'
        $script:GroupLookupCalls[0].Identity | Should Be "$domainSid-512"
    }

    It 'prefers the forest root domain SID for forest-scoped groups' {
        Reset-LookupState
        $expected = [pscustomobject]@{ Name = 'Enterprise Admins'; SID = "$rootSid-519" }
        $script:GroupsBySid["$rootSid-519"] = $expected

        $result = Resolve-ADPostureSensitiveGroupIdentity -CatalogEntry (New-CatalogEntry 'Enterprise Admins' 'Forest') -DomainSid $domainSid -ForestRootDomainSid $rootSid -BuiltinSearchBase $builtinBase -ForestPartitionsContainer $partitions -WellKnownRids $wellKnownRids

        $result.Name | Should Be 'Enterprise Admins'
        $script:GroupLookupCalls[0].Identity | Should Be "$rootSid-519"
    }

    It 'treats RODC password replication groups as domain-relative, not builtin aliases' {
        Reset-LookupState
        $expected = [pscustomobject]@{ Name = 'Allowed RODC Password Replication Group'; SID = "$domainSid-571" }
        $script:GroupsBySid["$domainSid-571"] = $expected

        $result = Resolve-ADPostureSensitiveGroupIdentity -CatalogEntry (New-CatalogEntry 'Allowed RODC Password Replication Group' 'Domain') -DomainSid $domainSid -ForestRootDomainSid $domainSid -BuiltinSearchBase $builtinBase -ForestPartitionsContainer $partitions -WellKnownRids $wellKnownRids

        $result | Should Not BeNullOrEmpty
        $script:GroupLookupCalls[0].Identity | Should Be "$domainSid-571"
        @($script:GroupLookupCalls | Where-Object { $_.Identity -eq 'S-1-5-32-571' }).Count | Should Be 0
    }

    It 'falls back to the name-based lookup when SID resolution fails' {
        Reset-LookupState
        $expected = [pscustomobject]@{ Name = 'Backup Operators'; SID = 'S-1-5-32-551' }
        $script:GroupsByFilter["Name -eq 'Backup Operators'"] = $expected

        $result = Resolve-ADPostureSensitiveGroupIdentity -CatalogEntry (New-CatalogEntry 'Backup Operators' 'Builtin') -DomainSid $domainSid -ForestRootDomainSid $domainSid -BuiltinSearchBase $builtinBase -ForestPartitionsContainer $partitions -WellKnownRids $wellKnownRids

        $result.Name | Should Be 'Backup Operators'
        $script:GroupLookupCalls[0].Identity | Should Be 'S-1-5-32-551'
        $nameCall = $script:GroupLookupCalls | Where-Object { $_.Filter } | Select-Object -First 1
        $nameCall.SearchBase | Should Be $builtinBase
    }

    It 'uses the name-based lookup directly for groups without a well-known RID' {
        Reset-LookupState
        $expected = [pscustomobject]@{ Name = 'DnsAdmins' }
        $script:GroupsByFilter["Name -eq 'DnsAdmins'"] = $expected

        $result = Resolve-ADPostureSensitiveGroupIdentity -CatalogEntry (New-CatalogEntry 'DnsAdmins' 'Domain') -DomainSid $domainSid -ForestRootDomainSid $domainSid -BuiltinSearchBase $builtinBase -ForestPartitionsContainer $partitions -WellKnownRids $wellKnownRids

        $result.Name | Should Be 'DnsAdmins'
        @($script:GroupLookupCalls | Where-Object { $_.Identity }).Count | Should Be 0
    }
}
