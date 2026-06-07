function Get-ADPostureTimelineHistoryPoints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DataDirectory
    )

    @(
        Get-ChildItem -Path $DataDirectory -Filter 'snapshot-*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime |
            ForEach-Object {
                $integrity = Test-ADPostureFileHashSidecar -Path $_.FullName
                if ($integrity.Status -eq 'Mismatch') {
                    Write-Warning "Skipping invalid timeline snapshot '$($_.FullName)': $($integrity.Message)"
                    return
                }

                try {
                    $snapshot = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
                }
                catch {
                    Write-Warning "Skipping unreadable timeline snapshot '$($_.FullName)': $($_.Exception.Message)"
                    return
                }

                [pscustomobject]@{
                    timestamp   = $snapshot.Timestamp
                    score       = [double]$snapshot.OverallRiskScore
                    actionable  = [int]$snapshot.ActionableCount
                    aclFindings = @($snapshot.AclFindings).Count
                    domain      = $snapshot.Domain
                    forest      = $snapshot.Forest
                    auditId     = $snapshot.AuditId
                    schemaVersion = $snapshot.SchemaVersion
                    file        = $_.Name
                    integrityStatus = $integrity.Status
                }
            }
    )
}
