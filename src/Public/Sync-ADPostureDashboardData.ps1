function Sync-ADPostureDashboardData {
    <#
    .SYNOPSIS
    Refreshes dashboard-data.js from the latest audit JSON (fixes empty HTML when opened locally).
    #>
    [CmdletBinding()]
    param(
        [string]$DashboardJsonPath
    )

    $cfg = Get-ModuleConfig

    if (-not $DashboardJsonPath) {
        $DashboardJsonPath = Join-Path $cfg.ReportPath 'latest-dashboard.json'
        if (-not (Test-Path $DashboardJsonPath)) {
            $latest = Get-ChildItem -Path $cfg.ReportPath -Filter '*-dashboard.json' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
            if ($latest) { $DashboardJsonPath = $latest.FullName }
        }
    }

    if (-not (Test-Path $DashboardJsonPath)) {
        throw "No dashboard JSON found. Run Invoke-ADPostureAudit first."
    }

    $raw = Get-Content $DashboardJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Warning "Dashboard data contains sensitive AD posture information. Keep dashboard-data.js local and out of source control."
    Write-ADPostureDashboardData -DashboardData $raw
    Write-Host "Dashboard data synced to: $(Join-Path $cfg.DashboardPath 'dashboard-data.js')" -ForegroundColor Green
}
