function Get-ADPostureTrustValue {
    param(
        [Parameter(Mandatory)]
        $Trust,
        [string[]]$Names = @()
    )

    foreach ($name in $Names) {
        if ($Trust.PSObject.Properties[$name] -and $null -ne $Trust.$name -and -not [string]::IsNullOrWhiteSpace([string]$Trust.$name)) {
            return $Trust.$name
        }
    }

    $null
}

function ConvertTo-ADPostureTrustBool {
    param(
        $Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    $text = ([string]$Value).Trim()
    if ($text -match '^(?i:true|yes|1|enabled)$') { return $true }
    if ($text -match '^(?i:false|no|0|disabled)$') { return $false }
    $Default
}

function ConvertTo-ADPostureTrustObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $InputObject,
        [string]$Domain
    )

    $name = Get-ADPostureTrustValue -Trust $InputObject -Names @('Name', 'Target', 'TrustPartner', 'TrustedDomain', 'FlatName')
    $partner = Get-ADPostureTrustValue -Trust $InputObject -Names @('Target', 'TrustPartner', 'Name', 'TrustedDomain', 'FlatName')
    $direction = [string](Get-ADPostureTrustValue -Trust $InputObject -Names @('Direction', 'TrustDirection'))
    $trustType = [string](Get-ADPostureTrustValue -Trust $InputObject -Names @('TrustType', 'TrustTypeName'))
    $attributesRaw = Get-ADPostureTrustValue -Trust $InputObject -Names @('TrustAttributes', 'trustAttributes')
    $attributes = if ($null -ne $attributesRaw -and "$attributesRaw" -match '^\d+$') { [int]$attributesRaw } else { $attributesRaw }
    $whenChanged = Get-ADPostureTrustValue -Trust $InputObject -Names @('WhenChanged', 'Modified')
    $whenCreated = Get-ADPostureTrustValue -Trust $InputObject -Names @('WhenCreated', 'Created')

    $selectiveAuth = ConvertTo-ADPostureTrustBool -Value (Get-ADPostureTrustValue -Trust $InputObject -Names @('SelectiveAuthentication')) -Default:$false
    $sidQuarantined = ConvertTo-ADPostureTrustBool -Value (Get-ADPostureTrustValue -Trust $InputObject -Names @('SIDFilteringQuarantined', 'SidFilteringQuarantined')) -Default:$false
    $sidForestAware = ConvertTo-ADPostureTrustBool -Value (Get-ADPostureTrustValue -Trust $InputObject -Names @('SIDFilteringForestAware', 'SidFilteringForestAware')) -Default:$false
    $forestTransitive = ConvertTo-ADPostureTrustBool -Value (Get-ADPostureTrustValue -Trust $InputObject -Names @('ForestTransitive')) -Default:$false
    $intraForest = ConvertTo-ADPostureTrustBool -Value (Get-ADPostureTrustValue -Trust $InputObject -Names @('IntraForest')) -Default:$false
    $tgtDelegation = ConvertTo-ADPostureTrustBool -Value (Get-ADPostureTrustValue -Trust $InputObject -Names @('TGTDelegation', 'TgtDelegation')) -Default:$false

    $isTransitive = ConvertTo-ADPostureTrustBool -Value (Get-ADPostureTrustValue -Trust $InputObject -Names @('IsTransitive')) -Default:$false
    if (-not $isTransitive -and $attributes -is [int]) {
        $isTransitive = (($attributes -band 0x1) -eq 0)
    }
    elseif (-not $isTransitive -and $forestTransitive) {
        $isTransitive = $true
    }

    $sidFilteringEnabled = $sidQuarantined -or $sidForestAware
    if ($attributes -is [int]) {
        $sidFilteringEnabled = $sidFilteringEnabled -or (($attributes -band 0x4) -ne 0) -or (($attributes -band 0x40) -ne 0)
    }

    [pscustomobject]@{
        Domain = $Domain
        TrustName = if ($name) { [string]$name } else { 'Unknown trust' }
        TrustPartner = if ($partner) { [string]$partner } else { [string]$name }
        TrustDirection = if ($direction) { $direction } else { 'Unknown' }
        TrustType = if ($trustType) { $trustType } else { 'Unknown' }
        TrustAttributes = $attributes
        DistinguishedName = Get-ADPostureTrustValue -Trust $InputObject -Names @('DistinguishedName')
        ObjectGuid = Get-ADPostureTrustValue -Trust $InputObject -Names @('ObjectGuid')
        IsTransitive = [bool]$isTransitive
        IntraForest = [bool]$intraForest
        ForestTransitive = [bool]$forestTransitive
        SelectiveAuthentication = [bool]$selectiveAuth
        SIDFilteringEnabled = [bool]$sidFilteringEnabled
        SIDFilteringQuarantined = [bool]$sidQuarantined
        SIDFilteringForestAware = [bool]$sidForestAware
        TGTDelegation = [bool]$tgtDelegation
        WhenCreated = if ($whenCreated -is [datetime]) { $whenCreated.ToString('o') } elseif ($whenCreated) { [string]$whenCreated } else { $null }
        WhenChanged = if ($whenChanged -is [datetime]) { $whenChanged.ToString('o') } elseif ($whenChanged) { [string]$whenChanged } else { $null }
    }
}

function Get-ADPostureTrustSeverity {
    param([double]$RiskScore)

    if ($RiskScore -ge 10) { return 'Critical' }
    if ($RiskScore -ge 7) { return 'High' }
    if ($RiskScore -ge 4) { return 'Medium' }
    if ($RiskScore -gt 0) { return 'Low' }
    'Informational'
}

function New-ADPostureTrustFinding {
    param(
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)]$Trust,
        [Parameter(Mandatory)][string]$FindingType,
        [Parameter(Mandatory)][string]$RiskPattern,
        [Parameter(Mandatory)][double]$RiskScore,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$Remediation,
        [Parameter(Mandatory)][string]$ScoreFormula,
        [object[]]$ScoreComponents = @(),
        [object[]]$AttackTechniques = @(),
        [string[]]$Tags = @()
    )

    [pscustomobject]@{
        TrustFindingId = 'trust-{0:000000}' -f $Index
        Domain = $Domain
        FindingType = $FindingType
        RiskPattern = $RiskPattern
        Severity = Get-ADPostureTrustSeverity -RiskScore $RiskScore
        RiskScore = [Math]::Round($RiskScore, 2)
        TrustName = $Trust.TrustName
        TrustPartner = $Trust.TrustPartner
        TrustDirection = $Trust.TrustDirection
        TrustType = $Trust.TrustType
        TrustAttributes = $Trust.TrustAttributes
        DistinguishedName = $Trust.DistinguishedName
        IsTransitive = [bool]$Trust.IsTransitive
        IntraForest = [bool]$Trust.IntraForest
        ForestTransitive = [bool]$Trust.ForestTransitive
        SelectiveAuthentication = [bool]$Trust.SelectiveAuthentication
        SIDFilteringEnabled = [bool]$Trust.SIDFilteringEnabled
        SIDFilteringQuarantined = [bool]$Trust.SIDFilteringQuarantined
        SIDFilteringForestAware = [bool]$Trust.SIDFilteringForestAware
        TGTDelegation = [bool]$Trust.TGTDelegation
        WhenCreated = $Trust.WhenCreated
        WhenChanged = $Trust.WhenChanged
        Reason = $Reason
        Remediation = $Remediation
        ScoreFormula = $ScoreFormula
        ScoreComponents = @($ScoreComponents)
        AttackTechniques = @($AttackTechniques)
        Tags = @($Tags + 'TrustPosture' | Sort-Object -Unique)
    }
}

function ConvertTo-ADPostureTrustRiskModel {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [object[]]$Trusts = @(),
        [int]$StaleDays = 365
    )

    $normalizedTrusts = @($Trusts | ForEach-Object { ConvertTo-ADPostureTrustObject -InputObject $_ -Domain $Domain })
    $findings = [System.Collections.Generic.List[object]]::new()
    $index = 0
    $staleCutoff = (Get-Date).AddDays(-1 * [Math]::Max(1, $StaleDays))

    foreach ($trust in $normalizedTrusts) {
        $isExternalOrForest = -not [bool]$trust.IntraForest
        $isInboundOrBidirectional = ([string]$trust.TrustDirection) -match '(?i)inbound|bidirectional|both|2|3'
        $isOutboundOrBidirectional = ([string]$trust.TrustDirection) -match '(?i)outbound|bidirectional|both|1|3'
        $trustChanged = $null
        if ($trust.WhenChanged) {
            try { $trustChanged = [datetime]$trust.WhenChanged } catch { $trustChanged = $null }
        }

        if ($isExternalOrForest -and $isInboundOrBidirectional -and -not [bool]$trust.SIDFilteringEnabled) {
            $index++
            $findings.Add((New-ADPostureTrustFinding -Index $index -Domain $Domain -Trust $trust -FindingType 'TrustSidFilteringDisabled' -RiskPattern 'SID filtering gap' -RiskScore 12.0 -Reason "Trust '$($trust.TrustName)' accepts inbound or bidirectional external/forest trust access without SID filtering/quarantine evidence." -Remediation 'Enable SID filtering/quarantine where compatible, document any exception, and validate administrative SIDs cannot cross the trust boundary.' -ScoreFormula 'Trust score = external inbound trust + SID filtering not enabled' -ScoreComponents @([pscustomobject]@{ Name = 'SID filtering'; Value = $trust.SIDFilteringEnabled; Reason = 'SID filtering reduces cross-boundary SID history abuse' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1484.002'; Name = 'Domain Trust Modification'; Tactic = 'Defense Evasion, Privilege Escalation' }, [pscustomobject]@{ Id = 'T1078'; Name = 'Valid Accounts'; Tactic = 'Initial Access, Privilege Escalation' }) -Tags @('TrustBoundary', 'SidFiltering', 'Tier0Exposure')))
        }

        if ($isExternalOrForest -and $isInboundOrBidirectional -and -not [bool]$trust.SelectiveAuthentication) {
            $index++
            $findings.Add((New-ADPostureTrustFinding -Index $index -Domain $Domain -Trust $trust -FindingType 'TrustSelectiveAuthenticationDisabled' -RiskPattern 'Broad trust authentication' -RiskScore 9.0 -Reason "Trust '$($trust.TrustName)' does not show selective authentication, allowing broader authentication across the trust boundary." -Remediation 'Enable selective authentication where possible and grant Allowed to Authenticate only to explicitly required principals.' -ScoreFormula 'Trust score = inbound external/forest trust + selective authentication disabled' -ScoreComponents @([pscustomobject]@{ Name = 'Selective authentication'; Value = $trust.SelectiveAuthentication; Reason = 'Limits who can authenticate to trusted resources' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1078'; Name = 'Valid Accounts'; Tactic = 'Initial Access, Privilege Escalation' }) -Tags @('TrustBoundary', 'SelectiveAuthentication')))
        }

        if ($isExternalOrForest -and [bool]$trust.IsTransitive) {
            $index++
            $findings.Add((New-ADPostureTrustFinding -Index $index -Domain $Domain -Trust $trust -FindingType 'TrustExternalTransitive' -RiskPattern 'Transitive trust blast radius' -RiskScore $(if ($trust.ForestTransitive) { 7.5 } else { 6.2 }) -Reason "Trust '$($trust.TrustName)' is external/forest-facing and transitive, increasing blast radius if either side is compromised." -Remediation 'Prefer non-transitive or selective trust paths for narrow business needs, and document the trust owner, business justification, and review cadence.' -ScoreFormula 'Trust score = external or forest-facing trust + transitivity' -ScoreComponents @([pscustomobject]@{ Name = 'Transitive'; Value = $trust.IsTransitive; Reason = 'Transitivity can extend access beyond the immediate trusted domain' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1484.002'; Name = 'Domain Trust Modification'; Tactic = 'Defense Evasion, Privilege Escalation' }) -Tags @('TrustBoundary', 'TransitiveTrust')))
        }

        if ([bool]$trust.ForestTransitive -and $isOutboundOrBidirectional) {
            $index++
            $findings.Add((New-ADPostureTrustFinding -Index $index -Domain $Domain -Trust $trust -FindingType 'TrustForestTransitiveExposure' -RiskPattern 'Forest trust exposure' -RiskScore 7.0 -Reason "Trust '$($trust.TrustName)' is forest-transitive, which can expose large identity/resource scopes if governance is weak." -Remediation 'Review forest trust scope, SID filtering, selective authentication, and resource ACLs; keep a named owner and quarterly review.' -ScoreFormula 'Trust score = forest transitive trust + outbound/bidirectional reach' -ScoreComponents @([pscustomobject]@{ Name = 'Forest transitive'; Value = $trust.ForestTransitive; Reason = 'Forest trusts create broad cross-forest reach' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1484.002'; Name = 'Domain Trust Modification'; Tactic = 'Defense Evasion, Privilege Escalation' }) -Tags @('ForestTrust', 'BlastRadius')))
        }

        if ([bool]$trust.TGTDelegation) {
            $index++
            $findings.Add((New-ADPostureTrustFinding -Index $index -Domain $Domain -Trust $trust -FindingType 'TrustTgtDelegationEnabled' -RiskPattern 'Cross-trust TGT delegation' -RiskScore 10.0 -Reason "Trust '$($trust.TrustName)' has TGT delegation enabled, which can amplify ticket delegation risk across the trust boundary." -Remediation 'Disable cross-trust TGT delegation unless explicitly required and approved; validate Kerberos delegation exposure on both sides.' -ScoreFormula 'Trust score = TGT delegation enabled' -ScoreComponents @([pscustomobject]@{ Name = 'TGT delegation'; Value = $trust.TGTDelegation; Reason = 'Delegated tickets can cross trust boundaries' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558'; Name = 'Steal or Forge Kerberos Tickets'; Tactic = 'Credential Access' }) -Tags @('Kerberos', 'Delegation', 'TrustBoundary')))
        }

        if ($trustChanged -and $trustChanged -lt $staleCutoff) {
            $index++
            $findings.Add((New-ADPostureTrustFinding -Index $index -Domain $Domain -Trust $trust -FindingType 'TrustStaleOrUnvalidated' -RiskPattern 'Stale trust governance' -RiskScore 4.0 -Reason "Trust '$($trust.TrustName)' has not changed since $($trustChanged.ToString('yyyy-MM-dd')); verify it is still owned and required." -Remediation 'Revalidate business owner, connected forest/domain, selective authentication, SID filtering, and resource ACL assumptions.' -ScoreFormula 'Trust score = trust metadata older than review threshold' -ScoreComponents @([pscustomobject]@{ Name = 'Days since change'; Value = [int]((Get-Date) - $trustChanged).TotalDays; Reason = 'Long-lived trusts need periodic governance review' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1484.002'; Name = 'Domain Trust Modification'; Tactic = 'Defense Evasion, Privilege Escalation' }) -Tags @('Governance', 'StaleTrust')))
        }

        if ($isExternalOrForest -and $null -eq $trust.TrustAttributes) {
            $index++
            $findings.Add((New-ADPostureTrustFinding -Index $index -Domain $Domain -Trust $trust -FindingType 'TrustUnknownSecurityAttributes' -RiskPattern 'Incomplete trust evidence' -RiskScore 3.5 -Reason "Trust '$($trust.TrustName)' is missing trust attribute evidence; security controls could not be fully evaluated." -Remediation 'Re-run with permissions that expose trust attributes and manually verify SID filtering, selective authentication, transitivity, and TGT delegation.' -ScoreFormula 'Trust score = external/forest trust + missing attribute evidence' -ScoreComponents @([pscustomobject]@{ Name = 'Trust attributes'; Value = 'Missing'; Reason = 'Incomplete data limits assurance' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1484.002'; Name = 'Domain Trust Modification'; Tactic = 'Defense Evasion, Privilege Escalation' }) -Tags @('IncompleteEvidence')))
        }
    }

    [pscustomobject]@{
        Trusts = @($normalizedTrusts)
        TrustFindings = @($findings)
    }
}

function Get-ADPostureTrustPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Domain,
        [hashtable]$DomainParams = @{},
        [string]$LogPath
    )

    Write-Host 'Trust posture collection: reading domain trust configuration.'
    if ($LogPath) {
        Write-ADPostureLog -Message 'Trust posture collection: reading domain trust configuration.' -Path $LogPath
    }

    try {
        $trusts = @(Get-ADTrust -Filter * @DomainParams -Properties * -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not enumerate domain trusts: $($_.Exception.Message)"
        if ($LogPath) {
            Write-ADPostureLog -Message "Could not enumerate domain trusts: $($_.Exception.Message)" -Level Warning -Path $LogPath
        }
        $trusts = @()
    }

    $domainName = if ($Domain.DNSRoot) { $Domain.DNSRoot } else { [string]$Domain }
    $model = ConvertTo-ADPostureTrustRiskModel -Domain $domainName -Trusts @($trusts)
    $message = "Trust posture collection complete: $(@($model.Trusts).Count) trusts, $(@($model.TrustFindings).Count) findings."
    Write-Host $message
    if ($LogPath) {
        Write-ADPostureLog -Message $message -Path $LogPath
    }

    $model
}
