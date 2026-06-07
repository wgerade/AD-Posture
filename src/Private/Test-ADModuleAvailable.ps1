function Test-ADModuleAvailable {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw @"
ActiveDirectory module not found.
Install RSAT / AD Administration Tools and import:
  Import-Module ActiveDirectory
Supported: Windows Server 2012 R2 through 2025 / Windows 10/11 with RSAT.
"@
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}
