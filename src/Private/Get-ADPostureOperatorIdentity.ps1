function Get-ADPostureOperatorIdentity {
    <#
    .SYNOPSIS
    Returns the identity of the operator running the audit (DOMAIN\user) for report traceability.
    #>
    [CmdletBinding()]
    param()

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        if (-not [string]::IsNullOrWhiteSpace($identity)) { return $identity }
    }
    catch {
        Write-Verbose "Could not read the current Windows identity: $($_.Exception.Message)"
    }

    if ($env:USERDOMAIN -and $env:USERNAME) { return "$($env:USERDOMAIN)\$($env:USERNAME)" }
    if ($env:USERNAME) { return $env:USERNAME }
    'Unknown'
}
