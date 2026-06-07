$ModuleRoot = $PSScriptRoot

Get-ChildItem -Path (Join-Path $ModuleRoot 'src\Private\*.ps1') -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
    . $_.FullName
}

Get-ChildItem -Path (Join-Path $ModuleRoot 'src\Public\*.ps1') -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
    . $_.FullName
}

Export-ModuleMember -Function @(
    'Invoke-ADPostureAudit'
    'Export-ADPostureReport'
    'Compare-ADPostureSnapshots'
    'New-ADPostureTimelineHistory'
    'New-ADPostureRemediationScript'
    'New-ADPostureRemediationPlaybook'
    'Invoke-ADPostureArtifactRetention'
    'Open-ADPostureDashboard'
    'Get-ADSensitiveGroupCatalog'
    'Sync-ADPostureDashboardData'
)
