function Get-ModuleConfig {
    [CmdletBinding()]
    param()

    $moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    @{
        ModuleRoot = $moduleRoot
        ConfigPath = [System.IO.Path]::Combine($moduleRoot, 'config', 'SensitiveGroups.json')
        TieringModelPath = [System.IO.Path]::Combine($moduleRoot, 'config', 'TieringModel.json')
        ApprovedExceptionsPath = [System.IO.Path]::Combine($moduleRoot, 'config', 'ApprovedExceptions.json')
        DataPath   = [System.IO.Path]::Combine($moduleRoot, 'data')
        ReportPath = [System.IO.Path]::Combine($moduleRoot, 'reports')
        DashboardPath = [System.IO.Path]::Combine($moduleRoot, 'dashboard')
    }
}
