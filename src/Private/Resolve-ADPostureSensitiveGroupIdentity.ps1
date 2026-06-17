function Resolve-ADPostureSensitiveGroupIdentity {
    <#
    .SYNOPSIS
    Resolves a sensitive-group catalog entry to an AD group, preferring well-known SIDs over display names.
    .DESCRIPTION
    Localized or renamed built-in groups (for example "Admins. do Dominio" on pt-BR domains) are not found by
    English name filters. When the catalog provides a well-known RID, the group is resolved by SID first:
    Builtin alias RIDs map to S-1-5-32-<rid>, domain-relative RIDs map to <domainSid>-<rid>, and
    forest-scoped groups prefer the forest root domain SID. The original name-based lookup remains as
    the fallback for groups without a fixed RID (DnsAdmins, Exchange groups, DnsUpdateProxy).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $CatalogEntry,

        [Parameter(Mandatory)]
        [string]$DomainSid,

        [string]$ForestRootDomainSid,

        [Parameter(Mandatory)]
        [string]$BuiltinSearchBase,

        [string]$ForestPartitionsContainer,

        [hashtable]$DomainParams = @{},

        $WellKnownRids
    )

    $rid = $null
    if ($WellKnownRids -and $WellKnownRids.PSObject.Properties[$CatalogEntry.Name]) {
        $rid = [int]$WellKnownRids.($CatalogEntry.Name)
    }

    # Builtin alias RIDs live under S-1-5-32. Domain-relative well-known RIDs (512-527, 571, 572) use the domain SID.
    $builtinAliasRids = @(544, 545, 546, 547, 548, 549, 550, 551, 552, 554, 555, 556, 557, 558, 559, 560, 561, 562, 568, 569, 573, 574, 575, 576, 577, 578, 579, 580, 582)

    if ($rid) {
        $sidCandidates = [System.Collections.Generic.List[string]]::new()
        if ($rid -in $builtinAliasRids) {
            $sidCandidates.Add("S-1-5-32-$rid")
        }
        else {
            $candidateSids = @($DomainSid)
            if ($ForestRootDomainSid -and $ForestRootDomainSid -ne $DomainSid) {
                if ($CatalogEntry.Tier -eq 'Forest' -or $rid -in @(518, 519, 527)) {
                    $candidateSids = @($ForestRootDomainSid, $DomainSid)
                }
                else {
                    $candidateSids = @($DomainSid, $ForestRootDomainSid)
                }
            }
            foreach ($baseSid in $candidateSids) {
                $sidCandidates.Add("$baseSid-$rid")
            }
        }

        foreach ($sid in $sidCandidates) {
            try {
                $identity = Get-ADGroup -Identity $sid @DomainParams -ErrorAction Stop
                if ($identity) { return $identity }
            }
            catch {
                Write-Verbose "Sensitive group '$($CatalogEntry.Name)' not resolved by SID '$sid': $($_.Exception.Message)"
            }
        }
    }

    $groupFilterName = ConvertTo-ADPostureADFilterLiteral -Value $CatalogEntry.Name
    if ($CatalogEntry.Tier -eq 'Builtin') {
        return Get-ADGroup -Filter "Name -eq '$groupFilterName'" -SearchBase $BuiltinSearchBase @DomainParams -ErrorAction Stop
    }

    if ($CatalogEntry.Tier -eq 'Forest') {
        $identity = $null
        if ($ForestPartitionsContainer) {
            $identity = Get-ADGroup -Filter "Name -eq '$groupFilterName'" -SearchBase $ForestPartitionsContainer @DomainParams -ErrorAction SilentlyContinue
        }
        if (-not $identity) {
            $identity = Get-ADGroup -Filter "Name -eq '$groupFilterName'" @DomainParams -ErrorAction SilentlyContinue
        }
        return $identity
    }

    Get-ADGroup -Filter "Name -eq '$groupFilterName'" @DomainParams -ErrorAction SilentlyContinue
}
