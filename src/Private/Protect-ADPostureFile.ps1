function Write-ADPostureAtomicTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [AllowEmptyString()]
        [string]$Value,

        [string]$Encoding = 'UTF8'
    )

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
    }

    $tempPath = Join-Path $directory ('.tmp-' + [System.IO.Path]::GetRandomFileName())
    try {
        Set-Content -LiteralPath $tempPath -Value $Value -Encoding $Encoding -ErrorAction Stop
        Move-Item -LiteralPath $tempPath -Destination $Path -Force -ErrorAction Stop
    }
    catch {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Protect-ADPostureSensitiveFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        return
    }

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }

        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)

        foreach ($rule in @($acl.Access)) {
            [void]$acl.RemoveAccessRule($rule)
        }

        $ownerRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $systemRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            'NT AUTHORITY\SYSTEM',
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $acl.AddAccessRule($ownerRule)
        $acl.AddAccessRule($systemRule)
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not restrict ACL on sensitive output '$Path': $($_.Exception.Message)"
    }
}

function Write-ADPostureFileHashSidecar {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Cannot hash missing file: $Path"
    }

    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    $sidecarPath = "$Path.sha256"
    Write-ADPostureAtomicTextFile -Path $sidecarPath -Value "$hash  $([System.IO.Path]::GetFileName($Path))"
    Protect-ADPostureSensitiveFile -Path $sidecarPath
    $hash
}

function Test-ADPostureFileHashSidecar {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $sidecarPath = "$Path.sha256"
    if (-not (Test-Path -LiteralPath $sidecarPath -PathType Leaf)) {
        return [pscustomobject]@{
            Status = 'Missing'
            Path = $Path
            SidecarPath = $sidecarPath
            ExpectedHash = $null
            ActualHash = $null
            Message = 'Integrity sidecar not found.'
        }
    }

    $expected = ((Get-Content -LiteralPath $sidecarPath -Raw -Encoding UTF8) -split '\s+')[0]
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    $status = if ($expected -and $actual -eq $expected) { 'Valid' } else { 'Mismatch' }

    [pscustomobject]@{
        Status = $status
        Path = $Path
        SidecarPath = $sidecarPath
        ExpectedHash = $expected
        ActualHash = $actual
        Message = if ($status -eq 'Valid') { 'Integrity sidecar matches.' } else { 'Integrity sidecar does not match file hash.' }
    }
}

function Import-ADPostureJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string[]]$RequiredProperties = @()
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "JSON file not found: $Path"
    }

    try {
        $value = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Invalid JSON in '$Path': $($_.Exception.Message)"
    }

    foreach ($property in $RequiredProperties) {
        if (-not $value.PSObject.Properties[$property]) {
            throw "Invalid JSON schema in '$Path': missing required property '$property'."
        }
    }

    $integrity = Test-ADPostureFileHashSidecar -Path $Path
    if ($integrity.Status -eq 'Mismatch') {
        Write-Warning "Integrity warning for '$Path': $($integrity.Message)"
    }

    $value
}
