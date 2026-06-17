function Get-ModuleConfig {
    <#
    .SYNOPSIS
    Resolves module catalog paths and writable output locations.
    .DESCRIPTION
    Static catalogs (sensitive groups, tiering, UAC flags, crosswalk) always load from the module folder.
    Generated artifacts (data, reports, dashboard bundle) and the operator-managed ApprovedExceptions.json
    default to the module folder, but honor the ADPOSTURE_OUTPUT_ROOT environment variable so the module
    can run from a read-only install location such as a PSModulePath under Program Files.
    #>
    [CmdletBinding()]
    param()

    $moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $outputRoot = $env:ADPOSTURE_OUTPUT_ROOT
    if ([string]::IsNullOrWhiteSpace($outputRoot)) { $outputRoot = $moduleRoot }

    @{
        ModuleRoot = $moduleRoot
        OutputRoot = $outputRoot
        ConfigPath = [System.IO.Path]::Combine($moduleRoot, 'config', 'SensitiveGroups.json')
        TieringModelPath = [System.IO.Path]::Combine($moduleRoot, 'config', 'TieringModel.json')
        ApprovedExceptionsPath = [System.IO.Path]::Combine($outputRoot, 'config', 'ApprovedExceptions.json')
        DataPath   = [System.IO.Path]::Combine($outputRoot, 'data')
        ReportPath = [System.IO.Path]::Combine($outputRoot, 'reports')
        DashboardPath = [System.IO.Path]::Combine($outputRoot, 'dashboard')
        DashboardSourcePath = [System.IO.Path]::Combine($moduleRoot, 'dashboard')
    }
}
