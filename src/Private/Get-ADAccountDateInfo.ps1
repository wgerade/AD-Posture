function Convert-ADFileTime {
    param($FileTime)
    if (-not $FileTime -or $FileTime -le 0) { return $null }
    try {
        return [DateTime]::FromFileTimeUtc([int64]$FileTime).ToLocalTime()
    }
    catch {
        return $null
    }
}

function Get-DaysSinceDate {
    param($Date)
    if (-not $Date -or $Date -eq [DateTime]::MinValue) { return $null }
    [int][Math]::Max(0, ((Get-Date) - $Date).TotalDays)
}

function Format-ADUsDate {
    param($Date)
    if (-not $Date -or $Date -eq [DateTime]::MinValue) { return $null }
    $Date.ToString('MM/dd/yyyy')
}

function New-ADAccountDateField {
    param($Date, [string]$Label = 'date')

    $days = Get-DaysSinceDate -Date $Date
    [PSCustomObject]@{
        Label       = $Label
        RawDate     = if ($Date -and $Date -ne [DateTime]::MinValue) { $Date } else { $null }
        UsDate      = Format-ADUsDate -Date $Date
        Days        = $days
        Display     = if ($Date -and $Date -ne [DateTime]::MinValue) {
            "$(Format-ADUsDate -Date $Date) ($days days)"
        }
        else {
            'N/A'
        }
    }
}
