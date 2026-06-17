function Get-ADSensitiveGroupCatalog {
    [CmdletBinding()]
    param(
        [string]$ConfigPath = (Get-ModuleConfig).ConfigPath
    )

    if (-not (Test-Path $ConfigPath)) {
        throw "Configuration file not found: $ConfigPath"
    }

    $raw = Import-ADPostureJsonFile -Path $ConfigPath -RequiredProperties @('groups')
    $seen = @{}
    $groups = @()

    foreach ($g in $raw.groups) {
        if ($seen.ContainsKey($g.name)) { continue }
        $seen[$g.name] = $true
        $groups += [PSCustomObject]@{
            Name                      = $g.name
            RiskWeight                  = [int]$g.riskWeight
            Tier                      = $g.tier
            DifficultyDefault         = $g.difficultyDefault
            Optional                  = [bool]($g.optional -eq $true)
            ExcludeExpectedMembers    = [bool]($g.excludeExpectedMembers -eq $true)
            Notes                     = $g.notes
        }
    }

    [PSCustomObject]@{
        Groups                  = $groups
        ExcludedAccounts        = @($raw.excludedAccounts)
        ExcludedSids            = @($raw.excludedSids)
        ExcludedSamPatterns     = @($raw.excludedSamAccountNamePatterns)
        WellKnownRids           = $raw.wellKnownRids
    }
}
