$script:GetADPostureDashboardPayloadV11 = ${function:Get-ADPostureDashboardPayload}

function Get-ADPostureDashboardPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Snapshot,
        [switch]$RedactSensitiveAclEvidence
    )

    $payload = & $script:GetADPostureDashboardPayloadV11 @PSBoundParameters
    $payload.meta['schemaVersion'] = $Snapshot.SchemaVersion
    $payload.meta['auditId'] = $Snapshot.AuditId
    $payload.meta['frameworkCatalogVersion'] = $Snapshot.FrameworkCatalogVersion
    $payload['postureSummary'] = @($Snapshot.PostureSummary | Where-Object { $_.PostureDomain -ne 'OS & DC Hardening' })
    $payload['orphanedSensitiveGroupFindings'] = @($Snapshot.OrphanedSensitiveGroupFindings)
    $payload['frameworkSummary'] = @($Snapshot.FrameworkSummary)
    $payload['remediationPlaybooks'] = @($Snapshot.RemediationPlaybooks)
    $payload
}
