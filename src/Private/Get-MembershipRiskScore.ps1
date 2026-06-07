function Get-MembershipRiskAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $GroupCatalogEntry,
        [Parameter(Mandatory)]
        $Enrichment,
        [int]$NestingDepth = 0,
        [bool]$IsDirect = $true
    )

    $base = [double]$GroupCatalogEntry.RiskWeight
    $components = [System.Collections.Generic.List[object]]::new()
    $technicalRisks = [System.Collections.Generic.List[string]]::new()
    $attackTechniques = [System.Collections.Generic.List[object]]::new()

    function Add-ScoreComponent {
        param(
            [string]$Name,
            [string]$Type,
            [double]$Value,
            [string]$Reason
        )

        $components.Add([PSCustomObject]@{
            Name   = $Name
            Type   = $Type
            Value  = [Math]::Round($Value, 2)
            Reason = $Reason
        })
    }

    function Add-AttackTechnique {
        param([string]$Id, [string]$Name, [string]$Tactic)
        $attackTechniques.Add([PSCustomObject]@{
            Id     = $Id
            Name   = $Name
            Tactic = $Tactic
        })
    }

    Add-ScoreComponent -Name 'Sensitive group weight' -Type 'Base' -Value $base -Reason "Catalog weight for $($GroupCatalogEntry.Name)"

    if ($base -le 0) {
        Add-ScoreComponent -Name 'Monitoring-only group' -Type 'Override' -Value 0 -Reason 'Group has no direct risk weight'
        return [PSCustomObject]@{
            Score              = 0.0
            Components         = @($components)
            Formula            = '0 (monitoring-only group)'
            TechnicalRisk      = 'Monitoring-only sensitive group membership'
            AttackTechniques   = @()
            RiskModel          = 'Base * account type * nesting * directness * account state + UAC bonus'
        }
    }

    # Account type
    $typeMultiplier = switch ($Enrichment.AccountType) {
        { $_ -match '^User' }           { 1.0 }
        { $_ -match '^ServiceAccount' } { 1.15 }
        'Computer'                      { 0.85 }
        'Group'                         { 0.9 }
        default                         { 1.0 }
    }
    Add-ScoreComponent -Name 'Account type multiplier' -Type 'Multiplier' -Value $typeMultiplier -Reason $Enrichment.AccountType
    if ($Enrichment.IsServiceAccount) {
        $technicalRisks.Add('Privileged service identity can become a persistent control path')
        Add-AttackTechnique -Id 'T1098' -Name 'Account Manipulation' -Tactic 'Persistence, Privilege Escalation'
    }
    elseif ($Enrichment.IsGroup) {
        $technicalRisks.Add('Nested group grants privilege through delegated membership changes')
        Add-AttackTechnique -Id 'T1098.007' -Name 'Additional Local or Domain Groups' -Tactic 'Persistence, Privilege Escalation'
    }
    elseif ($Enrichment.IsComputer -and -not $Enrichment.IsDomainController) {
        $technicalRisks.Add('Computer account in privileged path can be abused through machine credential control')
        Add-AttackTechnique -Id 'T1078' -Name 'Valid Accounts' -Tactic 'Defense Evasion, Persistence, Privilege Escalation, Initial Access'
    }
    else {
        Add-AttackTechnique -Id 'T1078.002' -Name 'Domain Accounts' -Tactic 'Defense Evasion, Persistence, Privilege Escalation, Initial Access'
    }

    # Nesting increases risk (less obvious indirect privilege)
    $nestPenalty = [Math]::Min(1.5, 1 + ($NestingDepth * 0.12))
    $directFactor = if ($IsDirect) { 1.0 } else { 1.08 }
    Add-ScoreComponent -Name 'Nesting multiplier' -Type 'Multiplier' -Value $nestPenalty -Reason "Depth $NestingDepth"
    Add-ScoreComponent -Name 'Access path multiplier' -Type 'Multiplier' -Value $directFactor -Reason $(if ($IsDirect) { 'Direct membership' } else { 'Indirect/nested membership' })
    if ($NestingDepth -gt 0 -or -not $IsDirect) {
        $technicalRisks.Add('Nested access path makes ownership, review, and removal harder')
        Add-AttackTechnique -Id 'T1098.007' -Name 'Additional Local or Domain Groups' -Tactic 'Persistence, Privilege Escalation'
    }

    # Disabled / unused accounts reduce effective score (still monitored)
    $stateFactor = 1.0
    if ($Enrichment.IsDisabled) { $stateFactor = 0.35 }
    elseif ($Enrichment.IsStale) { $stateFactor = 0.55 }
    Add-ScoreComponent -Name 'Account state multiplier' -Type 'Multiplier' -Value $stateFactor -Reason $(if ($Enrichment.IsDisabled) { 'Disabled account' } elseif ($Enrichment.IsStale) { 'Stale account' } else { 'Active account' })
    if ($Enrichment.IsStale -and -not $Enrichment.IsDisabled) {
        $technicalRisks.Add('Unused privileged account increases takeover window')
        Add-AttackTechnique -Id 'T1078.002' -Name 'Domain Accounts' -Tactic 'Defense Evasion, Persistence, Privilege Escalation, Initial Access'
    }
    if ($Enrichment.IsPasswordStale -and -not $Enrichment.IsDisabled) {
        $technicalRisks.Add('Privileged account password age exceeds the configured review threshold')
    }

    # Expected DC in Domain Controllers group
    if ($GroupCatalogEntry.ExcludeExpectedMembers -and $Enrichment.IsDomainController) {
        Add-ScoreComponent -Name 'Native AD architecture exclusion' -Type 'Override' -Value 0 -Reason 'Expected domain controller membership'
        return [PSCustomObject]@{
            Score              = 0.0
            Components         = @($components)
            Formula            = '0 (native AD architecture exclusion)'
            TechnicalRisk      = 'Native AD architecture object excluded from remediation scoring'
            AttackTechniques   = @()
            RiskModel          = 'Base * account type * nesting * directness * account state + UAC bonus'
        }
    }

    if ($Enrichment.IsExcluded) {
        Add-ScoreComponent -Name 'Policy exclusion' -Type 'Override' -Value 0 -Reason $Enrichment.ExclusionReason
        return [PSCustomObject]@{
            Score              = 0.0
            Components         = @($components)
            Formula            = '0 (excluded by native/policy/baseline rule)'
            TechnicalRisk      = 'Excluded from actionable scoring by policy'
            AttackTechniques   = @()
            RiskModel          = 'Base * account type * nesting * directness * account state + UAC bonus'
        }
    }

    $uacBonus = [double]($Enrichment.UacRiskBonus)
    if ($null -eq $uacBonus) { $uacBonus = 0 }
    Add-ScoreComponent -Name 'UAC risk bonus' -Type 'Additive' -Value $uacBonus -Reason $(if ($Enrichment.UserAccountControlSummary) { $Enrichment.UserAccountControlSummary } else { 'No privileged UAC concern' })
    if ($Enrichment.UacPrivilegedConcernCount -gt 0) {
        $technicalRisks.Add("Privileged UAC flags: $($Enrichment.UserAccountControlSummary)")
        if ($Enrichment.UacActiveFlagNames -match 'TRUSTED_FOR_DELEGATION|TRUSTED_TO_AUTH_FOR_DELEGATION') {
            Add-AttackTechnique -Id 'T1558' -Name 'Steal or Forge Kerberos Tickets' -Tactic 'Credential Access'
        }
    }
    if ($GroupCatalogEntry.RiskWeight -ge 5) {
        $technicalRisks.Add('Membership grants broad administrative control')
        Add-AttackTechnique -Id 'T1484.002' -Name 'Domain Trust Modification' -Tactic 'Defense Evasion, Persistence, Privilege Escalation'
    }

    $raw = ($base * $typeMultiplier * $nestPenalty * $directFactor * $stateFactor) + $uacBonus
    $score = [Math]::Round([Math]::Max(0.0, $raw), 2)
    $technicalRisk = if ($technicalRisks.Count) {
        (@($technicalRisks) | Select-Object -Unique) -join '; '
    }
    else {
        'Sensitive group membership requires validation'
    }

    [PSCustomObject]@{
        Score              = $score
        Components         = @($components)
        Formula            = "($base * $typeMultiplier * $nestPenalty * $directFactor * $stateFactor) + $uacBonus = $score"
        TechnicalRisk      = $technicalRisk
        AttackTechniques   = @($attackTechniques | Sort-Object Id -Unique)
        RiskModel          = 'Base * account type * nesting * directness * account state + UAC bonus'
    }
}

function Get-MembershipRiskScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $GroupCatalogEntry,
        [Parameter(Mandatory)]
        $Enrichment,
        [int]$NestingDepth = 0,
        [bool]$IsDirect = $true
    )

    (Get-MembershipRiskAssessment -GroupCatalogEntry $GroupCatalogEntry -Enrichment $Enrichment -NestingDepth $NestingDepth -IsDirect:$IsDirect).Score
}

function Get-RemediationDifficulty {
    param(
        $GroupCatalogEntry,
        $Enrichment,
        [double]$RiskScore
    )

    if ($RiskScore -le 0.5) { return 'Low' }
    if ($Enrichment.IsDisabled -or $Enrichment.IsStale) { return 'Low' }

    $base = $GroupCatalogEntry.DifficultyDefault
    if ($Enrichment.UacRemediationDifficulty) {
        $base = Get-HigherDifficulty $base $Enrichment.UacRemediationDifficulty
    }
    if ($Enrichment.IsServiceAccount -and $base -eq 'High') { return 'High' }
    if ($Enrichment.IsServiceAccount) { return 'Medium' }
    if ($GroupCatalogEntry.RiskWeight -ge 5 -and $Enrichment.IsUser) { return 'High' }
    if ($GroupCatalogEntry.RiskWeight -ge 4) { return 'Medium' }

    return $base
}

function Get-CleanupRecommendation {
    param($Enrichment, $GroupName, [double]$RiskScore)

    $actions = [System.Collections.Generic.List[string]]::new()

    if ($Enrichment.IsExcluded) {
        if ($Enrichment.IsApprovedException -and $Enrichment.ApprovedExceptionStatus -eq 'Active') {
            return @('No action - active approved baseline exception')
        }
        return @('No action - automatic exclusion applied')
    }
    if ($Enrichment.IsApprovedException -and $Enrichment.ApprovedExceptionStatus -eq 'Expired') {
        $actions.Add("Approved exception expired - revalidate owner/ticket or remove membership")
    }

    if ($Enrichment.IsDisabled) {
        $actions.Add('Remove disabled member from sensitive group (low operational impact)')
    }
    if ($Enrichment.IsStale -and -not $Enrichment.IsDisabled) {
        $staleThreshold = if ($Enrichment.StaleDaysThreshold) { [int]$Enrichment.StaleDaysThreshold } else { 90 }
        $actions.Add("Validate business need - account with no logon for $staleThreshold+ days")
    }
    if ($Enrichment.IsPasswordStale -and -not $Enrichment.IsDisabled) {
        $passwordThreshold = if ($Enrichment.PasswordAgeDaysThreshold) { [int]$Enrichment.PasswordAgeDaysThreshold } else { 365 }
        $actions.Add("Review privileged password age - password last set $passwordThreshold+ days ago")
    }
    if ($Enrichment.IsServiceAccount) {
        if ($Enrichment.AccountType -match '^ServiceAccount \((gMSA|sMSA)\)') {
            $actions.Add('Review managed service account membership and keep only approved service principals in sensitive groups')
        }
        else {
            $actions.Add('Remove standing service account privilege or document a formally approved service identity design')
        }
    }
    if ($Enrichment.IsComputer -and -not $Enrichment.IsDomainController) {
        $actions.Add('Avoid computer accounts in privileged groups; use least-privilege delegation with explicit ownership')
    }
    if ($GroupName -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins') -and $Enrichment.IsUser) {
        $actions.Add('Apply tiered administration model / PIM / JEA')
    }
    if ($RiskScore -ge 4) {
        $actions.Add('High priority in privilege reduction plan')
    }

    if ($Enrichment.UacPrivilegedConcernCount -gt 0 -and $Enrichment.UacActiveFlagNames) {
        $catalog = Get-UacFlagCatalog
        $added = 0
        foreach ($flag in ($catalog.flags | Sort-Object { [double]$_.riskWeight } -Descending)) {
            if ($added -ge 2) { break }
            if ($flag.privilegedAccountConcern -ne $true) { continue }
            if ($Enrichment.UacActiveFlagNames -notmatch $flag.name) { continue }
            $actions.Add("UAC ($($flag.name)): $($flag.remediationHint)")
            $added++
        }
    }

    if ($actions.Count -eq 0) {
        $actions.Add('Review business justification and document temporary exception')
    }

    return $actions
}
