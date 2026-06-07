function Write-ADPostureLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info',

        [string]$Path
    )

    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('o'), $Level.ToUpperInvariant(), $Message
    Write-Verbose $line

    if (-not $Path) { return }

    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
    }

    Add-Content -Path $Path -Value $line -Encoding UTF8 -ErrorAction Stop
}
