function Get-UacFlagCatalog {
    $cfg = Get-ModuleConfig
    $path = [System.IO.Path]::Combine($cfg.ModuleRoot, 'config', 'UserAccountControlFlags.json')
    if (-not (Test-Path $path)) {
        throw "UAC catalog not found: $path"
    }
    Import-ADPostureJsonFile -Path $path -RequiredProperties @('accountTypeBits', 'flags', 'maxUacRiskBonus')
}

function Get-DifficultyRank {
    param([string]$Level)
    switch ($Level) {
        'High' { 3 }
        'Medium' { 2 }
        default { 1 }
    }
}

function Get-HigherDifficulty {
    param([string]$A, [string]$B)
    if ((Get-DifficultyRank $A) -ge (Get-DifficultyRank $B)) { $A } else { $B }
}

function Test-UacHideFlag {
    param($FlagDef, $Context)

    if (-not $FlagDef.showInDashboard) { return $true }
    $dup = $FlagDef.hideWhenDuplicateColumn
    if (-not $dup) { return $false }

    switch ($dup) {
        'AccountStatus' { return $Context.IsDisabled }
        'PasswordNeverExpires' { return $Context.PasswordNeverExpires }
        'PasswordExpiredOrStale' { return $Context.IsStale }
        default { return $false }
    }
}

function Get-UserAccountControlFriendly {
    <#
    .SYNOPSIS
    Full UAC assessment: category, display notes, risk bonus, remediation difficulty.
    #>
    param(
        [int]$Uac,
        [bool]$IsDisabled = $false,
        [bool]$PasswordNeverExpires = $false,
        [bool]$IsStale = $false
    )

    $empty = [PSCustomObject]@{
        Category                 = $null
        Notes                    = @()
        Summary                  = 'N/A'
        UacRiskBonus             = 0.0
        UacRemediationDifficulty = 'Low'
        ActiveFlags              = @()
        PrivilegedConcernCount   = 0
    }

    if ($null -eq $Uac) { return $empty }

    $catalog = Get-UacFlagCatalog
    $context = @{
        IsDisabled             = $IsDisabled
        PasswordNeverExpires   = $PasswordNeverExpires
        IsStale                = $IsStale
    }

    $category = 'Other Legacy Account'
    foreach ($typeBit in $catalog.accountTypeBits) {
        if ($Uac -band [int]$typeBit.bit) {
            $category = $typeBit.category
            break
        }
    }

    $active = [System.Collections.Generic.List[object]]::new()
    $displayNotes = [System.Collections.Generic.List[string]]::new()
    $riskSum = 0.0
    $maxDifficulty = 'Low'
    $concernCount = 0

    foreach ($flag in $catalog.flags) {
        $bit = [int]$flag.bit
        if (-not ($Uac -band $bit)) { continue }

        $riskW = [double]$flag.riskWeight
        $riskSum += $riskW
        $maxDifficulty = Get-HigherDifficulty $maxDifficulty $flag.remediationDifficulty

        if ($flag.privilegedAccountConcern -eq $true -and $riskW -gt 0) {
            $concernCount++
        }

        $hide = Test-UacHideFlag -FlagDef $flag -Context $context
        $row = [PSCustomObject]@{
            Name                   = $flag.name
            Label                  = $flag.friendlyLabel
            RiskWeight             = $riskW
            RemediationDifficulty  = $flag.remediationDifficulty
            RemediationHint        = $flag.remediationHint
            PrivilegedConcern      = [bool]$flag.privilegedAccountConcern
            HiddenInDashboard      = $hide
        }
        $active.Add($row)

        if (-not $hide) {
            $displayNotes.Add($flag.friendlyLabel)
        }
    }

    $maxBonus = [double]$catalog.maxUacRiskBonus
    $uacBonus = [Math]::Round([Math]::Min($maxBonus, [Math]::Max(0.0, $riskSum)), 2)

    $summary = $category
    if ($displayNotes.Count -gt 0) {
        $summary = "$category, $($displayNotes -join ', ')"
    }

    [PSCustomObject]@{
        Category                 = $category
        Notes                    = @($displayNotes)
        Summary                  = $summary
        UacRiskBonus             = $uacBonus
        UacRemediationDifficulty = $maxDifficulty
        ActiveFlags              = @($active)
        PrivilegedConcernCount   = $concernCount
    }
}
