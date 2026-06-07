function Resolve-ADPosturePipelineServer {
    [CmdletBinding()]
    param(
        [object]$InputObject,
        [string]$Server
    )

    if ($Server) { return $Server }
    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string]) {
        if ($InputObject.Trim()) { return $InputObject.Trim() }
        return $null
    }

    foreach ($propertyName in @('Server', 'DNSHostName', 'HostName', 'Domain', 'Name')) {
        $property = $InputObject.PSObject.Properties[$propertyName]
        if ($property -and $property.Value) {
            return [string]$property.Value
        }
    }

    throw "Pipeline input must be a server string or an object with Server, DNSHostName, HostName, Domain, or Name."
}

