#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Validates RSAT/AD prerequisites and registers the module in the current profile.
#>
$modulePath = Resolve-Path (Join-Path $PSScriptRoot '..')
$profileDir = Split-Path $PROFILE.CurrentUserAllHosts -Parent

if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
}

$importLine = "Import-Module '$($modulePath.Path)' -DisableNameChecking"
if (-not (Test-Path $PROFILE.CurrentUserAllHosts) -or -not (Select-String -Path $PROFILE.CurrentUserAllHosts -Pattern 'ADPosture' -Quiet)) {
    Add-Content -Path $PROFILE.CurrentUserAllHosts -Value "`n# AD Posture (ADPosture module)`n$importLine"
}

Write-Host "Module installed at: $($modulePath.Path)" -ForegroundColor Green
Write-Host "Verify RSAT: Get-WindowsCapability -Online | Where-Object Name -like '*RSAT*ActiveDirectory*'" -ForegroundColor Yellow

if (Get-Module -ListAvailable ActiveDirectory) {
    Write-Host "ActiveDirectory module: OK" -ForegroundColor Green
}
else {
    Write-Host "Install AD Administration Tools / RSAT." -ForegroundColor Red
}
