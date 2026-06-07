function Get-TieringModel {
    [CmdletBinding()]
    param(
        [string]$Path = (Get-ModuleConfig).TieringModelPath
    )

    if (-not (Test-Path $Path)) {
        throw "Tiering model not found: $Path"
    }

    Import-ADPostureJsonFile -Path $Path -RequiredProperties @('tiers', 'defaultTier')
}

function Resolve-ADPostureTier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [string]$AccountType,
        [bool]$IsDomainController = $false,
        $TieringModel = (Get-TieringModel)
    )

    if ($IsDomainController) {
        return [PSCustomObject]@{
            Tier        = 'Tier 0'
            Reason      = 'Domain controller account'
            Description = 'Identity control plane'
        }
    }

    foreach ($tier in $TieringModel.tiers) {
        if (@($tier.groups) -contains $GroupName) {
            return [PSCustomObject]@{
                Tier        = $tier.tier
                Reason      = $GroupName
                Description = $tier.description
            }
        }
    }

    foreach ($tier in $TieringModel.tiers) {
        foreach ($pattern in @($tier.accountTypePatterns)) {
            if ($AccountType -and $AccountType -like "$pattern*") {
                return [PSCustomObject]@{
                    Tier        = $tier.tier
                    Reason      = "Account type: $pattern"
                    Description = $tier.description
                }
            }
        }
    }

    [PSCustomObject]@{
        Tier        = $TieringModel.defaultTier
        Reason      = 'Default tier'
        Description = 'Default administrative boundary'
    }
}
