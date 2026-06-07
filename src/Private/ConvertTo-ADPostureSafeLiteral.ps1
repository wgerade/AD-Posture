function ConvertTo-ADPosturePowerShellLiteral {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) { return '$null' }
    return "'$($Value.Replace("'", "''"))'"
}

function ConvertTo-ADPostureADFilterLiteral {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) { return '' }
    return $Value.Replace("'", "''")
}
