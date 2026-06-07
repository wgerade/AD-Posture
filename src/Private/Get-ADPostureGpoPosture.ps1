function ConvertFrom-ADPostureGpLink {
    [CmdletBinding()]
    param(
        [string]$GpLink,
        [string]$ScopeName,
        [string]$ScopeDistinguishedName,
        [string]$ScopeObjectClass
    )

    if (-not $GpLink) { return @() }

    $links = [System.Collections.Generic.List[object]]::new()
    $pattern = '\[LDAP://(?<dn>[^\];]+);(?<options>\d+)\]'
    foreach ($match in [regex]::Matches($GpLink, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $options = [int]$match.Groups['options'].Value
        $links.Add([pscustomobject]@{
            GpoDistinguishedName = $match.Groups['dn'].Value
            LinkOptions = $options
            IsLinkDisabled = (($options -band 1) -eq 1)
            IsEnforced = (($options -band 2) -eq 2)
            ScopeName = $ScopeName
            ScopeDistinguishedName = $ScopeDistinguishedName
            ScopeObjectClass = $ScopeObjectClass
        })
    }

    @($links)
}

function Get-ADPostureGpoStatus {
    param([object]$Flags)

    $value = 0
    if ($null -ne $Flags -and "$Flags" -match '^\d+$') { $value = [int]$Flags }

    switch ($value) {
        1 { 'UserSettingsDisabled' }
        2 { 'ComputerSettingsDisabled' }
        3 { 'AllSettingsDisabled' }
        default { 'Enabled' }
    }
}

function New-ADPostureGpoFinding {
    param(
        [int]$Index,
        [string]$Domain,
        [string]$FindingType,
        [string]$Severity,
        [double]$RiskScore,
        [string]$Reason,
        [string]$Remediation,
        [object]$Gpo,
        [object]$Link,
        [string[]]$Tags = @(),
        [string]$SourceAclFindingId,
        [string]$DelegatedRight,
        [string]$TrusteeName,
        [string]$TrusteeSid,
        [string]$TrusteeDistinguishedName,
        [string]$TrusteeObjectClass,
        [string]$FileSystemPath,
        [string]$FileSystemRights,
        [string]$AccessControlType,
        [bool]$IsInherited = $false,
        [string]$ScopeTier,
        [string]$ScopeRiskContext,
        [double]$ScopeRiskMultiplier = 1.0,
        [string]$ScoreFormula,
        [object[]]$ScoreComponents = @()
    )

    $scopeContext = if ($ScopeTier -or $ScopeRiskContext) {
        [pscustomobject]@{
            ScopeTier = $ScopeTier
            ScopeRiskContext = $ScopeRiskContext
            ScopeRiskMultiplier = [Math]::Round($ScopeRiskMultiplier, 2)
        }
    }
    elseif ($Link) {
        Resolve-ADPostureGpoScopeContext -Link $Link
    }
    else {
        [pscustomobject]@{
            ScopeTier = $null
            ScopeRiskContext = $null
            ScopeRiskMultiplier = 1.0
        }
    }

    [pscustomobject]@{
        GpoFindingId = ('gpo-{0:d6}' -f $Index)
        Domain = $Domain
        FindingType = $FindingType
        Severity = $Severity
        RiskScore = [Math]::Round($RiskScore, 2)
        GpoName = if ($Gpo) { $Gpo.DisplayName } else { $null }
        GpoGuid = if ($Gpo) { $Gpo.Guid } else { $null }
        GpoDistinguishedName = if ($Gpo) { $Gpo.DistinguishedName } elseif ($Link) { $Link.GpoDistinguishedName } else { $null }
        GpoStatus = if ($Gpo) { $Gpo.Status } else { $null }
        GpoFileSysPath = if ($Gpo) { $Gpo.FileSysPath } else { $null }
        GpoWmiFilter = if ($Gpo) { $Gpo.WmiFilter } else { $null }
        ScopeName = if ($Link) { $Link.ScopeName } else { $null }
        ScopeDistinguishedName = if ($Link) { $Link.ScopeDistinguishedName } else { $null }
        ScopeObjectClass = if ($Link) { $Link.ScopeObjectClass } else { $null }
        LinkOptions = if ($Link) { $Link.LinkOptions } else { $null }
        IsLinkDisabled = if ($Link) { [bool]$Link.IsLinkDisabled } else { $false }
        IsEnforced = if ($Link) { [bool]$Link.IsEnforced } else { $false }
        ScopeTier = $scopeContext.ScopeTier
        ScopeRiskContext = $scopeContext.ScopeRiskContext
        ScopeRiskMultiplier = $scopeContext.ScopeRiskMultiplier
        SourceAclFindingId = $SourceAclFindingId
        DelegatedRight = $DelegatedRight
        TrusteeName = $TrusteeName
        TrusteeSid = $TrusteeSid
        TrusteeDistinguishedName = $TrusteeDistinguishedName
        TrusteeObjectClass = $TrusteeObjectClass
        FileSystemPath = $FileSystemPath
        FileSystemRights = $FileSystemRights
        AccessControlType = $AccessControlType
        IsInherited = $IsInherited
        Reason = $Reason
        Remediation = $Remediation
        ScoreFormula = $ScoreFormula
        ScoreComponents = @($ScoreComponents)
        Tags = @($Tags)
    }
}

function Resolve-ADPostureGpoScopeContext {
    param([object]$Link)

    $scopeDn = if ($Link) { [string]$Link.ScopeDistinguishedName } else { '' }
    $scopeName = if ($Link) { [string]$Link.ScopeName } else { '' }
    $scopeClass = if ($Link) { [string]$Link.ScopeObjectClass } else { '' }
    $scopeText = "$scopeName $scopeDn"

    if ($scopeClass -eq 'domainDNS') {
        return [pscustomobject]@{
            ScopeTier = 'Tier 0'
            ScopeRiskContext = 'Domain root policy scope'
            ScopeRiskMultiplier = 1.45
            Tags = @('DomainRootScope', 'Tier0Scope')
        }
    }

    if ($scopeDn -match '^(?i:OU=Domain Controllers,)' -or $scopeName -match '^(?i:Domain Controllers)$') {
        return [pscustomobject]@{
            ScopeTier = 'Tier 0'
            ScopeRiskContext = 'Domain Controllers policy scope'
            ScopeRiskMultiplier = 1.65
            Tags = @('DomainControllerScope', 'Tier0Scope')
        }
    }

    if ($scopeText -match '(?i)(Tier\s*0|Tier0|Privileged|Admin|Domain Admin|Enterprise Admin|Schema Admin)') {
        return [pscustomobject]@{
            ScopeTier = 'Tier 0'
            ScopeRiskContext = 'Privileged or tier-0 named policy scope'
            ScopeRiskMultiplier = 1.4
            Tags = @('PrivilegedScope', 'Tier0Scope')
        }
    }

    if ($scopeText -match '(?i)(Server|Tier\s*1|Tier1|Infrastructure|Database|SQL|Exchange)') {
        return [pscustomobject]@{
            ScopeTier = 'Tier 1'
            ScopeRiskContext = 'Server or infrastructure policy scope'
            ScopeRiskMultiplier = 1.2
            Tags = @('ServerScope', 'Tier1Scope')
        }
    }

    [pscustomobject]@{
        ScopeTier = 'Tier 2'
        ScopeRiskContext = 'General user/workstation or uncategorized OU policy scope'
        ScopeRiskMultiplier = 1.0
        Tags = @('GeneralScope')
    }
}

function Get-ADPostureGpoSeverity {
    param([double]$RiskScore)

    if ($RiskScore -ge 10) { return 'Critical' }
    if ($RiskScore -ge 7) { return 'High' }
    if ($RiskScore -ge 3) { return 'Medium' }
    if ($RiskScore -gt 0) { return 'Low' }
    'Informational'
}

function Get-ADPostureGpoDelegationBaseScore {
    param([string]$Right)

    switch ($Right) {
        'GenericAll' { 7.2 }
        'WriteDacl' { 6.8 }
        'WriteOwner' { 6.5 }
        'GenericWrite' { 5.5 }
        'AllExtendedRights' { 5.5 }
        'Delete' { 5.0 }
        default { 4.5 }
    }
}

function Test-ADPostureGpoBroadTrustee {
    param([object]$AclFinding)

    $name = [string]$AclFinding.TrusteeName
    $sid = [string]$AclFinding.TrusteeSid
    $raw = [string]$AclFinding.RawTrustee
    $text = "$name $sid $raw"

    if ($sid -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')) { return $true }
    if ($text -match '(?i)(Everyone|Todos|Authenticated Users|Usuarios autenticados|Usuários autenticados|Domain Users|Usuarios do dominio|Usuários do domínio)') { return $true }
    $false
}

function Test-ADPostureGpoWeakFileSystemTrustee {
    param([object]$IdentityReference)

    $name = [string]$IdentityReference
    $sid = ''
    try {
        $sid = ([System.Security.Principal.NTAccount]$IdentityReference).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $sid = ''
    }

    if ($sid -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546')) { return $true }
    if ($name -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546')) { return $true }
    if ($name -match '(?i)(^|\\)(Everyone|Todos|Authenticated Users|Usu[aá]rios autenticados|Domain Users|Usu[aá]rios do dom[ií]nio|Users|Guests)$') { return $true }
    $false
}

function Test-ADPostureGpoDangerousFileSystemRights {
    param([object]$Rights)

    $text = [string]$Rights
    if ($text -match '(?i)(FullControl|Modify|Write|ChangePermissions|TakeOwnership|CreateFiles|CreateDirectories|WriteData|AppendData|DeleteSubdirectoriesAndFiles|Delete|WriteAttributes|WriteExtendedAttributes)') {
        return $true
    }
    $false
}

function Test-ADPostureGpoExpectedSysvolPath {
    param(
        [string]$Path,
        [string]$Domain
    )

    if (-not $Path) { return $false }
    if ($Path -notmatch '^(?i:\\\\[^\\]+\\SYSVOL\\)') { return $false }
    if ($Domain -and $Path -notmatch ('(?i)\\\\[^\\]+\\SYSVOL\\' + [regex]::Escape($Domain) + '\\Policies\\')) { return $false }
    $true
}

function Test-ADPostureGpoAbsoluteExecutionPath {
    param([string]$Path)

    if (-not $Path) { return $false }
    if ($Path -match '^(?i)(\\\\|[A-Z]:[\\/])') { return $true }
    $false
}

function Test-ADPostureGpoBroadApplyPrincipal {
    param([string]$Principal)

    if (-not $Principal) { return $false }
    if ($Principal -in @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-32-546')) { return $true }
    if ($Principal -match '(?i)(^|\\)(Everyone|Todos|Domain Users|Usu[aÃ¡]rios do dom[iÃ­]nio|Users|Guests)$') { return $true }
    $false
}

function Get-ADPostureGpoSecurityFilterPrincipals {
    [CmdletBinding()]
    param([string]$DistinguishedName)

    if (-not $DistinguishedName) { return @() }

    $applyGroupPolicyGuid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
    try {
        $security = $null
        try {
            $security = Get-Acl -LiteralPath "AD:\$DistinguishedName" -ErrorAction Stop
        }
        catch {
            $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DistinguishedName")
            $security = [pscustomobject]@{
                Access = @($entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]))
            }
        }

        @($security.Access | Where-Object {
            [string]$_.AccessControlType -eq 'Allow' -and
            [string]$_.ObjectType -eq $applyGroupPolicyGuid
        } | ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.IdentityReference
                Right = 'ApplyGroupPolicy'
                IsInherited = [bool]$_.IsInherited
            }
        })
    }
    catch {
        @()
    }
}

function Test-ADPostureGpoBroadSecurityPrincipalText {
    param([string]$Value)

    if (-not $Value) { return $false }
    if ($Value -match '(?i)(\*?S-1-1-0|\*?S-1-5-11|\*?S-1-5-32-545|\*?S-1-5-32-546)') { return $true }
    if ($Value -match '(?i)(Everyone|Todos|Authenticated Users|Usu[aÃ¡]rios autenticados|Domain Users|Usu[aÃ¡]rios do dom[iÃ­]nio|Users|Guests)') { return $true }
    $false
}

function Get-ADPostureGpoScopeLinks {
    param(
        [object]$Gpo,
        [object[]]$Links = @()
    )

    if (-not $Gpo -or -not $Gpo.DistinguishedName) { return @() }
    @($Links | Where-Object {
        $_.GpoDistinguishedName -and
        ([string]$_.GpoDistinguishedName).Equals([string]$Gpo.DistinguishedName, [System.StringComparison]::OrdinalIgnoreCase)
    })
}

function Get-ADPostureGpoLinkScopeContext {
    param(
        [object]$Gpo,
        [object[]]$Links = @()
    )

    $matches = @(Get-ADPostureGpoScopeLinks -Gpo $Gpo -Links $Links)

    if (-not $matches.Count) {
        return [pscustomobject]@{
            Link = $null
            ScopeTier = 'Unlinked'
            ScopeRiskContext = 'GPO has no collected enabled link scope'
            ScopeRiskMultiplier = 0.65
            Tags = @('UnlinkedGpo')
        }
    }

    $best = $null
    foreach ($link in $matches) {
        if ($link.IsLinkDisabled) { continue }
        $scope = Resolve-ADPostureGpoScopeContext -Link $link
        if (-not $best -or $scope.ScopeRiskMultiplier -gt $best.ScopeRiskMultiplier) {
            $best = [pscustomobject]@{
                Link = $link
                ScopeTier = $scope.ScopeTier
                ScopeRiskContext = $scope.ScopeRiskContext
                ScopeRiskMultiplier = $scope.ScopeRiskMultiplier
                Tags = $scope.Tags
            }
        }
    }

    if ($best) { return $best }

    $link = $matches | Select-Object -First 1
    $scope = Resolve-ADPostureGpoScopeContext -Link $link
    [pscustomobject]@{
        Link = $link
        ScopeTier = $scope.ScopeTier
        ScopeRiskContext = "Disabled link only: $($scope.ScopeRiskContext)"
        ScopeRiskMultiplier = [Math]::Min(0.35, [double]$scope.ScopeRiskMultiplier)
        Tags = @($scope.Tags + 'DisabledGpoLink' | Sort-Object -Unique)
    }
}

function Get-ADPostureGpoExternalScriptPaths {
    [CmdletBinding()]
    param(
        [string]$RootPath,
        [string]$Domain,
        [int]$Limit = 50
    )

    if (-not $RootPath -or -not (Test-Path -LiteralPath $RootPath)) { return @() }

    $paths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $extensions = @('.ini', '.xml')
    try {
        $files = @(Get-ChildItem -LiteralPath $RootPath -Recurse -File -ErrorAction Stop |
            Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() } |
            Select-Object -First 200)
    }
    catch {
        return @()
    }

    $pathPattern = '(?i)(\\\\[^\s"''<>]+|[A-Z]:[\\/][^\s"''<>]+)'
    foreach ($file in $files) {
        try {
            $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
        }
        catch {
            continue
        }

        foreach ($match in [regex]::Matches($content, $pathPattern)) {
            $value = $match.Value.Trim()
            if (-not $value) { continue }
            if ($value -match '^(?i:\\\\[^\\]+\\SYSVOL\\)' -and (-not $Domain -or $value -match ([regex]::Escape("\SYSVOL\$Domain\")))) { continue }
            [void]$paths.Add($value)
            if ($paths.Count -ge $Limit) { break }
        }
        if ($paths.Count -ge $Limit) { break }
    }

    @($paths)
}

function Get-ADPostureGpoConfiguredScripts {
    [CmdletBinding()]
    param(
        [string]$RootPath,
        [string]$Domain,
        [int]$Limit = 100
    )

    if (-not $RootPath -or -not (Test-Path -LiteralPath $RootPath)) { return @() }

    $scripts = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $scriptIniNames = @('Scripts.ini', 'PSScripts.ini')

    try {
        $configFiles = @(Get-ChildItem -LiteralPath $RootPath -Recurse -File -ErrorAction Stop |
            Where-Object { $scriptIniNames -contains $_.Name } |
            Select-Object -First 80)
    }
    catch {
        return @()
    }

    foreach ($configFile in $configFiles) {
        $section = ''
        try {
            $lines = @(Get-Content -LiteralPath $configFile.FullName -ErrorAction Stop)
        }
        catch {
            continue
        }

        foreach ($line in $lines) {
            if ($line -match '^\s*\[(?<section>[^\]]+)\]\s*$') {
                $section = $matches['section']
                continue
            }

            $command = $null
            if ($line -match '^\s*\d+\s*(CmdLine|ScriptName)\s*=\s*(?<cmd>.+?)\s*$') {
                $command = $matches['cmd']
            }
            elseif ($line -match '(?<cmd>(?i)(\\\\[^\s"''<>]+|[A-Z]:[\\/][^\s"''<>]+))') {
                $command = $matches['cmd']
            }
            else {
                continue
            }

            $command = $command.Trim().Trim('"')
            if (-not $command) { continue }
            if ($command -match '^\s*(?<quoted>"[^"]+"|''[^'']+''|[^\s]+)') {
                $command = $matches['quoted'].Trim('"', "'")
            }

            $scriptPath = $command
            if (-not (Test-ADPostureGpoAbsoluteExecutionPath -Path $scriptPath)) {
                $scriptBasePath = $configFile.DirectoryName
                $sectionFolder = switch -Regex ($section) {
                    '^(?i:Startup)$' { 'Startup'; break }
                    '^(?i:Shutdown)$' { 'Shutdown'; break }
                    '^(?i:Logon)$' { 'Logon'; break }
                    '^(?i:Logoff)$' { 'Logoff'; break }
                    default { $null }
                }

                if ($sectionFolder) {
                    $currentFolder = Split-Path -Leaf $configFile.DirectoryName
                    $firstSegment = @($scriptPath -split '[\\/]', 2)[0]
                    if (
                        -not $currentFolder.Equals($sectionFolder, [System.StringComparison]::OrdinalIgnoreCase) -and
                        -not $firstSegment.Equals($sectionFolder, [System.StringComparison]::OrdinalIgnoreCase)
                    ) {
                        $scriptBasePath = Join-Path -Path $configFile.DirectoryName -ChildPath $sectionFolder
                    }
                }

                $scriptPath = Join-Path -Path $scriptBasePath -ChildPath $scriptPath
            }

            $isExpectedSysvol = Test-ADPostureGpoExpectedSysvolPath -Path $scriptPath -Domain $Domain
            $isExternal = (Test-ADPostureGpoAbsoluteExecutionPath -Path $scriptPath) -and -not $isExpectedSysvol -and -not $scriptPath.StartsWith($RootPath, [System.StringComparison]::OrdinalIgnoreCase)
            $key = $scriptPath
            if (-not $seen.Add($key)) { continue }

            $scripts.Add([pscustomobject]@{
                ConfigFile = $configFile.FullName
                ConfigSection = $section
                Command = $command
                ScriptPath = $scriptPath
                ScriptFolder = Split-Path -Parent $scriptPath
                IsExternal = [bool]$isExternal
                IsExpectedSysvolPath = [bool]$isExpectedSysvol
            })

            if ($scripts.Count -ge $Limit) { break }
        }
        if ($scripts.Count -ge $Limit) { break }
    }

    $standardScriptFolders = @(
        @{ Section = 'Startup'; Path = 'Machine\Scripts\Startup' },
        @{ Section = 'Shutdown'; Path = 'Machine\Scripts\Shutdown' },
        @{ Section = 'Logon'; Path = 'User\Scripts\Logon' },
        @{ Section = 'Logoff'; Path = 'User\Scripts\Logoff' }
    )
    $scriptExtensions = @('.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.exe')

    foreach ($folderSpec in $standardScriptFolders) {
        if ($scripts.Count -ge $Limit) { break }
        $folderPath = Join-Path -Path $RootPath -ChildPath $folderSpec.Path
        if (-not (Test-Path -LiteralPath $folderPath)) { continue }

        try {
            $scriptFiles = @(Get-ChildItem -LiteralPath $folderPath -File -ErrorAction Stop |
                Where-Object { $scriptExtensions -contains $_.Extension.ToLowerInvariant() } |
                Select-Object -First $Limit)
        }
        catch {
            continue
        }

        foreach ($scriptFile in $scriptFiles) {
            if ($scripts.Count -ge $Limit) { break }
            $key = $scriptFile.FullName
            if (-not $seen.Add($key)) { continue }

            $scripts.Add([pscustomobject]@{
                ConfigFile = $null
                ConfigSection = $folderSpec.Section
                Command = $scriptFile.Name
                ScriptPath = $scriptFile.FullName
                ScriptFolder = $scriptFile.DirectoryName
                IsExternal = $false
                IsExpectedSysvolPath = (Test-ADPostureGpoExpectedSysvolPath -Path $scriptFile.FullName -Domain $Domain)
            })
        }
    }

    @($scripts)
}

function Add-ADPostureGpoFileAclFindings {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [ref]$Index,
        [string]$Domain,
        [object]$Gpo,
        [object]$Scope,
        [string[]]$BaseTags = @(),
        [string]$Path,
        [string]$FindingType,
        [string]$PathKind,
        [string]$ScriptPath
    )

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return
    }

    foreach ($rule in @($acl.Access)) {
        if ([string]$rule.AccessControlType -ne 'Allow') { continue }
        if (-not (Test-ADPostureGpoWeakFileSystemTrustee -IdentityReference $rule.IdentityReference)) { continue }
        if (-not (Test-ADPostureGpoDangerousFileSystemRights -Rights $rule.FileSystemRights)) { continue }

        $baseScore = if ($FindingType -eq 'GpoScriptFileAclWeak') { 8.4 } else { 7.4 }
        $score = [Math]::Min(15, $baseScore * [double]$Scope.ScopeRiskMultiplier)
        $Index.Value++
        $Findings.Add((New-ADPostureGpoFinding `
            -Index $Index.Value `
            -Domain $Domain `
            -FindingType $FindingType `
            -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
            -RiskScore $score `
            -Gpo $Gpo `
            -Link $Scope.Link `
            -TrusteeName ([string]$rule.IdentityReference) `
            -DelegatedRight ([string]$rule.FileSystemRights) `
            -FileSystemPath $Path `
            -FileSystemRights ([string]$rule.FileSystemRights) `
            -AccessControlType ([string]$rule.AccessControlType) `
            -IsInherited ([bool]$rule.IsInherited) `
            -ScopeTier $Scope.ScopeTier `
            -ScopeRiskContext $Scope.ScopeRiskContext `
            -ScopeRiskMultiplier $Scope.ScopeRiskMultiplier `
            -Reason "Broad trustee '$($rule.IdentityReference)' can modify the $PathKind used by a configured GPO script. Script: $ScriptPath. Scope context: $($Scope.ScopeRiskContext)." `
            -Remediation 'Remove broad write/full-control permissions from GPO script files and script folders in SYSVOL. Keep script changes limited to approved GPO administrators and validate inherited permissions.' `
            -ScoreFormula "GPO script $PathKind ACL score = $baseScore * scope $($Scope.ScopeRiskMultiplier)" `
            -Tags @($BaseTags + 'GpoScriptAclWeak' + $FindingType + 'BroadTrustee' + 'ExecutionPath' | Sort-Object -Unique)))
    }
}

function New-ADPostureGpoSecurityFilterFindings {
    [CmdletBinding()]
    param(
        [int]$StartIndex,
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = $StartIndex

    foreach ($gpo in @($Gpos)) {
        $filters = @($gpo.SecurityFilterPrincipals)
        if (-not $filters.Count) { continue }

        $scope = Get-ADPostureGpoLinkScopeContext -Gpo $gpo -Links $Links
        if ($scope.ScopeTier -notin @('Tier 0', 'Tier 1')) { continue }

        foreach ($filter in $filters) {
            $principal = [string]$filter.Name
            if (-not (Test-ADPostureGpoBroadApplyPrincipal -Principal $principal)) { continue }

            $baseScore = if ($scope.ScopeTier -eq 'Tier 0') { 6.8 } else { 5.2 }
            $score = [Math]::Min(12, $baseScore * [double]$scope.ScopeRiskMultiplier)
            $index++
            $findings.Add((New-ADPostureGpoFinding `
                -Index $index `
                -Domain $Domain `
                -FindingType 'GpoBroadSecurityFiltering' `
                -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
                -RiskScore $score `
                -Gpo $gpo `
                -Link $scope.Link `
                -TrusteeName $principal `
                -DelegatedRight 'ApplyGroupPolicy' `
                -ScopeTier $scope.ScopeTier `
                -ScopeRiskContext $scope.ScopeRiskContext `
                -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                -Reason "GPO security filtering allows broad principal '$principal' to apply the policy. Scope context: $($scope.ScopeRiskContext)." `
                -Remediation 'Restrict GPO security filtering to explicit groups that match the intended population, especially for domain root, domain controller, server, and privileged scopes.' `
                -ScoreFormula "GPO security filtering score = $baseScore * scope $($scope.ScopeRiskMultiplier)" `
                -Tags @($scope.Tags + 'GpoSecurityFiltering' + 'BroadApplyPrincipal' | Sort-Object -Unique)))
        }
    }

    @($findings)
}

function New-ADPostureGpoWmiFilterFindings {
    [CmdletBinding()]
    param(
        [int]$StartIndex,
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = $StartIndex

    foreach ($gpo in @($Gpos)) {
        if (-not $gpo.WmiFilter) { continue }
        $scope = Get-ADPostureGpoLinkScopeContext -Gpo $gpo -Links $Links
        if ($scope.ScopeTier -notin @('Tier 0', 'Tier 1')) { continue }

        $baseScore = if ($scope.ScopeTier -eq 'Tier 0') { 5.6 } else { 4.2 }
        $score = [Math]::Min(10, $baseScore * [double]$scope.ScopeRiskMultiplier)
        $index++
        $findings.Add((New-ADPostureGpoFinding `
            -Index $index `
            -Domain $Domain `
            -FindingType 'GpoWmiFilterDependency' `
            -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
            -RiskScore $score `
            -Gpo $gpo `
            -Link $scope.Link `
            -DelegatedRight 'WmiFilter' `
            -ScopeTier $scope.ScopeTier `
            -ScopeRiskContext $scope.ScopeRiskContext `
            -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
            -Reason "Critical or infrastructure GPO '$($gpo.DisplayName)' depends on WMI filter '$($gpo.WmiFilter)'. If the filter is broken, too narrow, or changed, the policy may not apply to the intended systems. Scope context: $($scope.ScopeRiskContext)." `
            -Remediation 'Validate WMI filter query health, ownership, change control, and expected target count for critical or infrastructure-linked GPOs.' `
            -ScoreFormula "GPO WMI filter dependency score = $baseScore * scope $($scope.ScopeRiskMultiplier)" `
            -Tags @($scope.Tags + 'GpoWmiFilter' + 'ManualReviewRequired' | Sort-Object -Unique)))
    }

    @($findings)
}

function New-ADPostureGpoLoopbackFindings {
    [CmdletBinding()]
    param(
        [int]$StartIndex,
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = $StartIndex

    foreach ($gpo in @($Gpos)) {
        if (-not $gpo.FileSysPath -or -not (Test-Path -LiteralPath $gpo.FileSysPath)) { continue }
        $registryPath = Join-Path -Path $gpo.FileSysPath -ChildPath 'Machine\Registry.pol'
        if (-not (Test-Path -LiteralPath $registryPath)) { continue }

        try {
            $bytes = [System.IO.File]::ReadAllBytes($registryPath)
            $unicodeText = [System.Text.Encoding]::Unicode.GetString($bytes)
            $asciiText = [System.Text.Encoding]::ASCII.GetString($bytes)
            $text = "$unicodeText`n$asciiText"
        }
        catch {
            continue
        }

        if ($text -notmatch '(?i)UserPolicyMode') { continue }
        $scope = Get-ADPostureGpoLinkScopeContext -Gpo $gpo -Links $Links
        if ($scope.ScopeTier -notin @('Tier 0', 'Tier 1')) { continue }

        $mode = if ($text -match '(?i)(Replace|UserPolicyMode\D+2)') { 'Replace' } elseif ($text -match '(?i)(Merge|UserPolicyMode\D+1)') { 'Merge' } else { 'Configured' }
        $baseScore = if ($mode -eq 'Replace') { 6.2 } else { 5.2 }
        $score = [Math]::Min(11, $baseScore * [double]$scope.ScopeRiskMultiplier)
        $index++
        $findings.Add((New-ADPostureGpoFinding `
            -Index $index `
            -Domain $Domain `
            -FindingType 'GpoLoopbackProcessing' `
            -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
            -RiskScore $score `
            -Gpo $gpo `
            -Link $scope.Link `
            -DelegatedRight "Loopback$mode" `
            -FileSystemPath $registryPath `
            -ScopeTier $scope.ScopeTier `
            -ScopeRiskContext $scope.ScopeRiskContext `
            -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
            -Reason "GPO configures user policy loopback processing ($mode). On server, jump, privileged, or domain-controller scopes this changes user policy application based on the computer and can unexpectedly expand or replace user controls. Scope context: $($scope.ScopeRiskContext)." `
            -Remediation 'Validate loopback mode, target scope, and intended user policy impact; restrict use to documented server/RDS/jump-server designs.' `
            -ScoreFormula "GPO loopback score = $baseScore * scope $($scope.ScopeRiskMultiplier)" `
            -Tags @($scope.Tags + 'GpoLoopback' + $mode | Sort-Object -Unique)))
    }

    @($findings)
}

function New-ADPostureGpoSecurityOptionFindings {
    [CmdletBinding()]
    param(
        [int]$StartIndex,
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = $StartIndex

    foreach ($gpo in @($Gpos)) {
        if (-not $gpo.FileSysPath -or -not (Test-Path -LiteralPath $gpo.FileSysPath)) { continue }
        $templatePath = Join-Path -Path $gpo.FileSysPath -ChildPath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        if (-not (Test-Path -LiteralPath $templatePath)) { continue }

        try {
            $content = Get-Content -LiteralPath $templatePath -Raw -ErrorAction Stop
        }
        catch {
            continue
        }

        $scope = Get-ADPostureGpoLinkScopeContext -Gpo $gpo -Links $Links
        $rules = @(
            @{
                Name = 'SeDebugPrivilege'
                Pattern = '(?im)^\s*SeDebugPrivilege\s*=\s*(?<value>.*(?:\*S-1-1-0|\*S-1-5-11|\*S-1-5-32-545|\*S-1-5-32-546).*)$'
                FindingType = 'GpoRiskyUserRight'
                BaseScore = 8.2
                Reason = 'Debug programs right is granted to a broad principal, enabling credential access and process tampering on affected systems.'
                Remediation = 'Restrict SeDebugPrivilege to local Administrators or a tightly controlled administrative group.'
            },
            @{
                Name = 'SeRemoteInteractiveLogonRight'
                Pattern = '(?im)^\s*SeRemoteInteractiveLogonRight\s*=\s*(?<value>.*(?:\*S-1-1-0|\*S-1-5-11|\*S-1-5-32-545|\*S-1-5-32-546).*)$'
                FindingType = 'GpoRiskyUserRight'
                BaseScore = 7.4
                Reason = 'Remote interactive logon is granted to a broad principal, expanding interactive access to systems in scope.'
                Remediation = 'Restrict remote interactive logon to approved admin or remote access groups.'
            },
            @{
                Name = 'SeImpersonatePrivilege'
                Pattern = '(?im)^\s*SeImpersonatePrivilege\s*=\s*(?<value>.*(?:\*S-1-1-0|\*S-1-5-11|\*S-1-5-32-545|\*S-1-5-32-546).*)$'
                FindingType = 'GpoRiskyUserRight'
                BaseScore = 7.0
                Reason = 'Impersonate client after authentication is granted to a broad principal, increasing local privilege escalation paths on affected systems.'
                Remediation = 'Restrict SeImpersonatePrivilege to trusted service identities and approved local administrators.'
            },
            @{
                Name = 'SeBackupPrivilege'
                Pattern = '(?im)^\s*SeBackupPrivilege\s*=\s*(?<value>.*(?:\*S-1-1-0|\*S-1-5-11|\*S-1-5-32-545|\*S-1-5-32-546).*)$'
                FindingType = 'GpoRiskyUserRight'
                BaseScore = 7.0
                Reason = 'Back up files and directories is granted to a broad principal, allowing sensitive local data extraction even when file ACLs would normally deny access.'
                Remediation = 'Restrict backup privilege to approved backup operators and managed service accounts.'
            },
            @{
                Name = 'SeTcbPrivilege'
                Pattern = '(?im)^\s*SeTcbPrivilege\s*=\s*(?<value>.+)$'
                FindingType = 'GpoRiskyUserRight'
                BaseScore = 8.8
                Reason = 'Act as part of the operating system is assigned by policy. This is rarely required and can grant very high local security authority impact.'
                Remediation = 'Remove SeTcbPrivilege assignments unless a documented Microsoft-supported requirement exists.'
            },
            @{
                Name = 'EnableLUA'
                Pattern = '(?im)^\s*MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA\s*=\s*4\s*,\s*0\s*$'
                FindingType = 'GpoRiskySecurityOption'
                BaseScore = 7.0
                Reason = 'UAC is disabled by policy, reducing local privilege boundary protections on affected systems.'
                Remediation = 'Keep UAC enabled unless a formally approved exception exists for an isolated scope.'
            },
            @{
                Name = 'LMCompatibilityLevel'
                Pattern = '(?im)^\s*MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel\s*=\s*4\s*,\s*[012]\s*$'
                FindingType = 'GpoRiskySecurityOption'
                BaseScore = 6.5
                Reason = 'LM/NTLM compatibility is configured at a weak level, increasing downgrade and credential relay exposure.'
                Remediation = 'Use a hardened LMCompatibilityLevel aligned with current domain authentication policy.'
            },
            @{
                Name = 'NoLMHash'
                Pattern = '(?im)^\s*MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash\s*=\s*4\s*,\s*0\s*$'
                FindingType = 'GpoRiskySecurityOption'
                BaseScore = 6.2
                Reason = 'Policy allows storage of LM password hashes, increasing exposure if local or domain password material is dumped.'
                Remediation = 'Enable NoLMHash and validate password-change/rotation after the setting applies.'
            },
            @{
                Name = 'RestrictAnonymous'
                Pattern = '(?im)^\s*MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous\s*=\s*4\s*,\s*0\s*$'
                FindingType = 'GpoRiskySecurityOption'
                BaseScore = 5.8
                Reason = 'Anonymous enumeration restrictions are weak, increasing unauthenticated discovery of users, groups, and shares on affected systems.'
                Remediation = 'Harden anonymous access restrictions according to the organization baseline.'
            },
            @{
                Name = 'EveryoneIncludesAnonymous'
                Pattern = '(?im)^\s*MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous\s*=\s*4\s*,\s*1\s*$'
                FindingType = 'GpoRiskySecurityOption'
                BaseScore = 6.0
                Reason = 'Anonymous users are included in Everyone permissions, broadening access granted to Everyone on affected systems.'
                Remediation = 'Disable EveryoneIncludesAnonymous unless a tightly scoped legacy compatibility exception exists.'
            },
            @{
                Name = 'LimitBlankPasswordUse'
                Pattern = '(?im)^\s*MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse\s*=\s*4\s*,\s*0\s*$'
                FindingType = 'GpoRiskySecurityOption'
                BaseScore = 6.6
                Reason = 'Local accounts with blank passwords can be used beyond console logon, increasing lateral movement exposure.'
                Remediation = 'Keep blank-password network logon restrictions enabled and remove blank local passwords.'
            },
            @{
                Name = 'LocalAccountTokenFilterPolicy'
                Pattern = '(?im)^\s*MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountTokenFilterPolicy\s*=\s*4\s*,\s*1\s*$'
                FindingType = 'GpoRiskySecurityOption'
                BaseScore = 6.8
                Reason = 'Remote UAC token filtering is disabled for local accounts, increasing remote administrative impact from local credential compromise.'
                Remediation = 'Keep remote UAC token filtering enabled unless a formally approved management exception exists.'
            }
        )

        foreach ($rule in $rules) {
            if ($content -notmatch $rule.Pattern) { continue }
            if ($rule.FindingType -eq 'GpoRiskyUserRight' -and $Matches['value'] -and -not (Test-ADPostureGpoBroadSecurityPrincipalText -Value $Matches['value']) -and $rule.Name -ne 'SeTcbPrivilege') { continue }
            $score = [Math]::Min(15, [double]$rule.BaseScore * [double]$scope.ScopeRiskMultiplier)
            $matchedValue = if ($Matches['value']) { $Matches['value'].Trim() } else { $rule.Name }
            $index++
            $findings.Add((New-ADPostureGpoFinding `
                -Index $index `
                -Domain $Domain `
                -FindingType $rule.FindingType `
                -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
                -RiskScore $score `
                -Gpo $gpo `
                -Link $scope.Link `
                -DelegatedRight $rule.Name `
                -FileSystemPath $templatePath `
                -ScopeTier $scope.ScopeTier `
                -ScopeRiskContext $scope.ScopeRiskContext `
                -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                -Reason "$($rule.Reason) Setting: $matchedValue. Scope context: $($scope.ScopeRiskContext)." `
                -Remediation $rule.Remediation `
                -ScoreFormula "GPO security option score = $($rule.BaseScore) * scope $($scope.ScopeRiskMultiplier)" `
                -Tags @($scope.Tags + 'GpoSecurityOption' + $rule.Name | Sort-Object -Unique)))
        }
    }

    @($findings)
}

function New-ADPostureGpoScriptContentFindings {
    [CmdletBinding()]
    param(
        [int]$StartIndex,
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = $StartIndex
    $scriptRules = @(
        @{ Name = 'CredentialLiteral'; Pattern = '(?im)(password|passwd|pwd)\s*[:=]\s*["'']?[^"''\s]{4,}'; BaseScore = 8.0; Reason = 'Script appears to contain a password-like literal, which can expose reusable credentials to anyone who can read the GPO script or SYSVOL copy.'; Remediation = 'Remove hard-coded credentials and use a managed secret or approved deployment mechanism.' },
        @{ Name = 'LocalAdminModification'; Pattern = '(?im)(net\s+localgroup\s+administrators\b.*\s/add|Add-LocalGroupMember\b.*\bAdministrators\b)'; BaseScore = 7.6; Reason = 'Script modifies local Administrators membership, which can grant broad local privilege across every computer in the linked GPO scope.'; Remediation = 'Replace script-based local admin changes with controlled local group policy or endpoint privilege management.' },
        @{ Name = 'RemoteDownloadExecution'; Pattern = '(?im)(Invoke-WebRequest|iwr|DownloadString|Invoke-Expression|\biex\b|Start-BitsTransfer)'; BaseScore = 7.0; Reason = 'Script downloads or dynamically executes content, which can turn the linked GPO scope into a remote code execution path if the source is changed or intercepted.'; Remediation = 'Avoid dynamic download/execute behavior in GPO scripts; use signed, versioned, internally hosted deployment artifacts.' },
        @{ Name = 'DefenderOrFirewallDisabled'; Pattern = '(?im)(Set-MpPreference\s+.*DisableRealtimeMonitoring\s+\$?true|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off)'; BaseScore = 8.0; Reason = 'Script disables endpoint protection or firewall controls, reducing detection and network protection across the linked GPO scope.'; Remediation = 'Remove security-control disablement from GPO scripts or document a tightly scoped approved exception.' }
    )
    $scriptRegexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline

    foreach ($gpo in @($Gpos)) {
        if (-not $gpo.FileSysPath -or -not (Test-Path -LiteralPath $gpo.FileSysPath)) { continue }
        $scope = Get-ADPostureGpoLinkScopeContext -Gpo $gpo -Links $Links
        $reported = 0

        foreach ($script in @(Get-ADPostureGpoConfiguredScripts -RootPath $gpo.FileSysPath -Domain $Domain)) {
            if ($reported -ge 8) { break }
            if ($script.IsExternal -or -not $script.ScriptPath) { continue }
            if (-not $script.ScriptPath.StartsWith($gpo.FileSysPath, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            if (-not (Test-Path -LiteralPath $script.ScriptPath)) { continue }

            try {
                $item = Get-Item -LiteralPath $script.ScriptPath -ErrorAction Stop
                if ($item.Length -gt 262144) { continue }
                $content = Get-Content -LiteralPath $script.ScriptPath -Raw -ErrorAction Stop
            }
            catch {
                continue
            }
            $contentText = [string]$content
            if ([string]::IsNullOrWhiteSpace($contentText)) { continue }

            foreach ($rule in $scriptRules) {
                if (-not [regex]::IsMatch($contentText, [string]$rule.Pattern, $scriptRegexOptions)) { continue }
                $score = [Math]::Min(15, [double]$rule.BaseScore * [double]$scope.ScopeRiskMultiplier)
                $index++
                $reported++
                $findings.Add((New-ADPostureGpoFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'GpoRiskyScriptContent' `
                    -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
                    -RiskScore $score `
                    -Gpo $gpo `
                    -Link $scope.Link `
                    -DelegatedRight $rule.Name `
                    -FileSystemPath $script.ScriptPath `
                    -ScopeTier $scope.ScopeTier `
                    -ScopeRiskContext $scope.ScopeRiskContext `
                    -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                    -Reason "$($rule.Reason) Script: $($script.ScriptPath). Scope context: $($scope.ScopeRiskContext)." `
                    -Remediation $rule.Remediation `
                    -ScoreFormula "GPO script content score = $($rule.BaseScore) * scope $($scope.ScopeRiskMultiplier)" `
                    -Tags @($scope.Tags + 'GpoScriptContent' + $rule.Name + 'ExecutionPath' | Sort-Object -Unique)))
            }
        }
    }

    @($findings)
}

function Get-ADPostureGpoXmlAttributeValue {
    param(
        [System.Xml.XmlNode]$Node,
        [string[]]$Names
    )

    if (-not $Node -or -not $Node.Attributes) { return $null }
    foreach ($name in $Names) {
        $attribute = $Node.Attributes[$name]
        if ($attribute -and $attribute.Value) { return [string]$attribute.Value }
    }
    $null
}

function New-ADPostureGpoPreferenceFindings {
    [CmdletBinding()]
    param(
        [int]$StartIndex,
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = $StartIndex
    $preferenceRules = @(
        @{ Type = 'GpoPreferenceCredential'; BaseScore = 9.0; Tags = @('GpoPreference', 'CredentialExposure'); Reason = 'Group Policy Preference XML contains credential material or a cpassword-like field. This can expose reusable credentials from SYSVOL to any principal that can read the policy files.'; Remediation = 'Remove stored credentials from GPP items, rotate exposed passwords, and replace the configuration with a managed deployment or secret-management process.' },
        @{ Type = 'GpoPreferenceLocalAdmin'; BaseScore = 7.8; Tags = @('GpoPreference', 'LocalAdminModification'); Reason = 'Group Policy Preference modifies local Administrators membership, which can grant local privilege across every computer in the linked scope.'; Remediation = 'Use controlled local group policy or endpoint privilege management with explicit ownership and review.' },
        @{ Type = 'GpoPreferenceScheduledTask'; BaseScore = 7.4; Tags = @('GpoPreference', 'ScheduledTaskExecution'); Reason = 'Group Policy Preference creates or updates a scheduled task, creating a remote execution path across systems in the linked scope.'; Remediation = 'Validate the task command, run-as identity, source path, and change-control process; remove broad or unnecessary task deployment.' },
        @{ Type = 'GpoPreferenceServiceControl'; BaseScore = 7.2; Tags = @('GpoPreference', 'ServiceControl'); Reason = 'Group Policy Preference creates or modifies a service, which can become persistent code execution or privilege control on affected systems.'; Remediation = 'Validate service binary paths, service accounts, and ownership; restrict service deployment to approved managed tooling.' },
        @{ Type = 'GpoPreferenceExternalPath'; BaseScore = 6.2; Tags = @('GpoPreference', 'ExternalScriptPath', 'ExternalAclNotQueried'); Reason = 'Group Policy Preference references an external executable or script path. The audit does not connect to external file paths; only normal GPO SYSVOL paths are ACL-validated.'; Remediation = 'Move executable content into controlled policy storage or review external share ACLs and ownership through a separate approved process.' }
    )

    foreach ($gpo in @($Gpos)) {
        if (-not $gpo.FileSysPath -or -not (Test-Path -LiteralPath $gpo.FileSysPath)) { continue }
        $preferencesRoot = Join-Path -Path $gpo.FileSysPath -ChildPath 'Machine\Preferences'
        $userPreferencesRoot = Join-Path -Path $gpo.FileSysPath -ChildPath 'User\Preferences'
        $roots = @($preferencesRoot, $userPreferencesRoot) | Where-Object { Test-Path -LiteralPath $_ }
        if (-not @($roots).Count) { continue }

        $scope = Get-ADPostureGpoLinkScopeContext -Gpo $gpo -Links $Links
        $reportedKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $xmlFiles = @()
        foreach ($root in $roots) {
            try {
                $xmlFiles += @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.xml' -ErrorAction Stop | Select-Object -First 200)
            }
            catch {
                continue
            }
        }

        foreach ($file in $xmlFiles) {
            try {
                [xml]$xml = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            }
            catch {
                continue
            }

            $allNodes = @($xml.SelectNodes('//*'))
            foreach ($node in $allNodes) {
                $nodeName = [string]$node.Name
                $nodeText = $node.OuterXml
                $hits = [System.Collections.Generic.List[object]]::new()

                if ($nodeText -match '(?i)(cpassword\s*=|password\s*=|userName\s*=|runAs\s*=)') {
                    $hits.Add($preferenceRules[0])
                }
                if ($nodeText -match '(?i)(Administrators|Builtin\\Administrators|S-1-5-32-544)' -and $nodeName -match '(?i)(Group|Groups|LocalUsers|User)') {
                    $hits.Add($preferenceRules[1])
                }
                if ($nodeName -match '(?i)(Task|ScheduledTasks|ImmediateTask)') {
                    $hits.Add($preferenceRules[2])
                }
                if ($nodeName -match '(?i)(Service|Services)') {
                    $hits.Add($preferenceRules[3])
                }

                $candidatePaths = @(
                    (Get-ADPostureGpoXmlAttributeValue -Node $node -Names @('path', 'imagePath', 'appName', 'program', 'command', 'runAs', 'targetPath', 'fromPath'))
                ) | Where-Object { $_ }
                foreach ($candidatePath in $candidatePaths) {
                    if ((Test-ADPostureGpoAbsoluteExecutionPath -Path $candidatePath) -and -not (Test-ADPostureGpoExpectedSysvolPath -Path $candidatePath -Domain $Domain)) {
                        $hits.Add($preferenceRules[4])
                    }
                }

                foreach ($rule in @($hits)) {
                    $key = "$($file.FullName)|$($rule.Type)|$nodeName"
                    if (-not $reportedKeys.Add($key)) { continue }

                    $score = [Math]::Min(15, [double]$rule.BaseScore * [double]$scope.ScopeRiskMultiplier)
                    $index++
                    $findings.Add((New-ADPostureGpoFinding `
                        -Index $index `
                        -Domain $Domain `
                        -FindingType $rule.Type `
                        -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
                        -RiskScore $score `
                        -Gpo $gpo `
                        -Link $scope.Link `
                        -DelegatedRight $nodeName `
                        -FileSystemPath $file.FullName `
                        -ScopeTier $scope.ScopeTier `
                        -ScopeRiskContext $scope.ScopeRiskContext `
                        -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                        -Reason "$($rule.Reason) Preference file: $($file.FullName). Scope context: $($scope.ScopeRiskContext)." `
                        -Remediation $rule.Remediation `
                        -ScoreFormula "GPO preference score = $($rule.BaseScore) * scope $($scope.ScopeRiskMultiplier)" `
                        -Tags @($scope.Tags + $rule.Tags | Sort-Object -Unique)))
                }
            }
        }
    }

    @($findings)
}

function New-ADPostureGpoPathAclFindings {
    [CmdletBinding()]
    param(
        [int]$StartIndex,
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = $StartIndex

    foreach ($gpo in @($Gpos)) {
        $scope = Get-ADPostureGpoLinkScopeContext -Gpo $gpo -Links $Links
        $baseTags = @($scope.Tags + 'GpoFileSystem' | Where-Object { $_ } | Sort-Object -Unique)

        if ($gpo.FileSysPath -and (Test-ADPostureGpoExpectedSysvolPath -Path $gpo.FileSysPath -Domain $Domain)) {
            try {
                $acl = Get-Acl -LiteralPath $gpo.FileSysPath -ErrorAction Stop
                foreach ($rule in @($acl.Access)) {
                    if ([string]$rule.AccessControlType -ne 'Allow') { continue }
                    if (-not (Test-ADPostureGpoWeakFileSystemTrustee -IdentityReference $rule.IdentityReference)) { continue }
                    if (-not (Test-ADPostureGpoDangerousFileSystemRights -Rights $rule.FileSystemRights)) { continue }

                    $score = [Math]::Min(15, 6.8 * [double]$scope.ScopeRiskMultiplier)
                    $index++
                    $findings.Add((New-ADPostureGpoFinding `
                        -Index $index `
                        -Domain $Domain `
                        -FindingType 'GpoSysvolAclWeak' `
                        -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
                        -RiskScore $score `
                        -Gpo $gpo `
                        -Link $scope.Link `
                        -TrusteeName ([string]$rule.IdentityReference) `
                        -DelegatedRight ([string]$rule.FileSystemRights) `
                        -FileSystemPath $gpo.FileSysPath `
                        -FileSystemRights ([string]$rule.FileSystemRights) `
                        -AccessControlType ([string]$rule.AccessControlType) `
                        -IsInherited ([bool]$rule.IsInherited) `
                        -ScopeTier $scope.ScopeTier `
                        -ScopeRiskContext $scope.ScopeRiskContext `
                        -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                        -Reason "Broad trustee '$($rule.IdentityReference)' can modify the GPO SYSVOL folder. Scope context: $($scope.ScopeRiskContext)." `
                        -Remediation 'Remove broad write/full-control permissions from the GPO SYSVOL folder and keep policy file changes limited to approved GPO administrators.' `
                        -ScoreFormula "GPO SYSVOL ACL score = 6.8 * scope $($scope.ScopeRiskMultiplier)" `
                        -Tags @($baseTags + 'SysvolAclWeak' + 'BroadTrustee' | Sort-Object -Unique)))
                }
            }
            catch {
                $score = [Math]::Min(8, 3.5 * [double]$scope.ScopeRiskMultiplier)
                $index++
                $findings.Add((New-ADPostureGpoFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'GpoSysvolAclUnvalidated' `
                    -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
                    -RiskScore $score `
                    -Gpo $gpo `
                    -Link $scope.Link `
                    -FileSystemPath $gpo.FileSysPath `
                    -ScopeTier $scope.ScopeTier `
                    -ScopeRiskContext $scope.ScopeRiskContext `
                    -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                    -Reason "Could not validate the GPO SYSVOL folder ACL at '$($gpo.FileSysPath)': $($_.Exception.Message)" `
                    -Remediation 'Validate SYSVOL availability and review the GPO folder ACL from a trusted management host.' `
                    -ScoreFormula "GPO SYSVOL ACL unvalidated score = 3.5 * scope $($scope.ScopeRiskMultiplier)" `
                    -Tags @($baseTags + 'SysvolAclUnvalidated' | Sort-Object -Unique)))
            }
        }

        $configuredScripts = @(Get-ADPostureGpoConfiguredScripts -RootPath $gpo.FileSysPath -Domain $Domain)
        $externalScriptPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($script in @($configuredScripts)) {
            $isOutsideGpoSysvol = $script.ScriptPath -and -not ([string]$script.ScriptPath).StartsWith([string]$gpo.FileSysPath, [System.StringComparison]::OrdinalIgnoreCase)
            $isExternalExecutionPath = $script.IsExternal -or (
                (Test-ADPostureGpoAbsoluteExecutionPath -Path $script.ScriptPath) -and
                $isOutsideGpoSysvol -and
                -not (Test-ADPostureGpoExpectedSysvolPath -Path $script.ScriptPath -Domain $Domain)
            ) -or $isOutsideGpoSysvol

            if ($isExternalExecutionPath) {
                if ($script.ScriptPath) {
                    [void]$externalScriptPaths.Add([string]$script.ScriptPath)
                }
                continue
            }
            $scriptTags = @($baseTags + 'GpoScript' + 'ExecutionPath' | Sort-Object -Unique)

            Add-ADPostureGpoFileAclFindings `
                -Findings $findings `
                -Index ([ref]$index) `
                -Domain $Domain `
                -Gpo $gpo `
                -Scope $scope `
                -BaseTags $scriptTags `
                -Path $script.ScriptPath `
                -FindingType 'GpoScriptFileAclWeak' `
                -PathKind 'script file' `
                -ScriptPath $script.ScriptPath

            Add-ADPostureGpoFileAclFindings `
                -Findings $findings `
                -Index ([ref]$index) `
                -Domain $Domain `
                -Gpo $gpo `
                -Scope $scope `
                -BaseTags $scriptTags `
                -Path $script.ScriptFolder `
                -FindingType 'GpoScriptFolderAclWeak' `
                -PathKind 'script folder' `
                -ScriptPath $script.ScriptPath
        }

        foreach ($externalPath in @(Get-ADPostureGpoExternalScriptPaths -RootPath $gpo.FileSysPath -Domain $Domain)) {
            [void]$externalScriptPaths.Add([string]$externalPath)
        }

        foreach ($externalPath in @($externalScriptPaths)) {
            $score = [Math]::Min(10, 5.8 * [double]$scope.ScopeRiskMultiplier)
            $index++
            $findings.Add((New-ADPostureGpoFinding `
                -Index $index `
                -Domain $Domain `
                -FindingType 'GpoExternalScriptPath' `
                -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
                -RiskScore $score `
                -Gpo $gpo `
                -Link $scope.Link `
                -FileSystemPath $externalPath `
                -ScopeTier $scope.ScopeTier `
                -ScopeRiskContext $scope.ScopeRiskContext `
                -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                -Reason "GPO references an execution path outside its normal SYSVOL policy folder: $externalPath. The audit does not connect to external file paths; only the GPO SYSVOL path is ACL-validated." `
                -Remediation 'Move scripts into controlled SYSVOL/GPO storage, or validate the external share ACL, ownership, and change-control process through an approved separate review path.' `
                -ScoreFormula "GPO external script path score = 5.8 * scope $($scope.ScopeRiskMultiplier)" `
                -Tags @($baseTags + 'ExternalScriptPath' + 'ExternalAclNotQueried' + 'ExecutionPath' | Sort-Object -Unique)))
        }

        if ($gpo.HasScripts -and -not @($configuredScripts).Count) {
            $score = [Math]::Min(8, 4.2 * [double]$scope.ScopeRiskMultiplier)
            $index++
            $findings.Add((New-ADPostureGpoFinding `
                -Index $index `
                -Domain $Domain `
                -FindingType 'GpoScriptMetadataUnparsed' `
                -Severity (Get-ADPostureGpoSeverity -RiskScore $score) `
                -RiskScore $score `
                -Gpo $gpo `
                -Link $scope.Link `
                -FileSystemPath $gpo.FileSysPath `
                -ScopeTier $scope.ScopeTier `
                -ScopeRiskContext $scope.ScopeRiskContext `
                -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                -Reason "GPO has the script client-side extension enabled, but no configured script path could be extracted from SYSVOL metadata under '$($gpo.FileSysPath)'. This can hide startup/shutdown/logon/logoff execution paths from automated review." `
                -Remediation 'Open the GPO in GPMC and validate configured scripts manually, then verify SYSVOL metadata, replication, and audit account read permissions.' `
                -ScoreFormula "GPO unparsed script metadata score = 4.2 * scope $($scope.ScopeRiskMultiplier)" `
                -Tags @($baseTags + 'GpoScriptMetadata' + 'ScriptMetadataUnparsed' + 'ManualReviewRequired' | Sort-Object -Unique)))
        }
    }

    @($findings)
}

function New-ADPostureGpoDelegationFindings {
    [CmdletBinding()]
    param(
        [int]$StartIndex,
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @(),
        [object[]]$AclFindings = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = $StartIndex
    $gpoByDn = @{}
    foreach ($gpo in @($Gpos)) {
        if ($gpo.DistinguishedName) {
            $gpoByDn[[string]$gpo.DistinguishedName.ToLowerInvariant()] = $gpo
        }
    }

    $linksByGpoDn = @{}
    foreach ($link in @($Links)) {
        if (-not $link.GpoDistinguishedName) { continue }
        $key = ([string]$link.GpoDistinguishedName).ToLowerInvariant()
        if (-not $linksByGpoDn.ContainsKey($key)) { $linksByGpoDn[$key] = [System.Collections.Generic.List[object]]::new() }
        $linksByGpoDn[$key].Add($link)
    }

    $controlRights = @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'AllExtendedRights', 'Delete')
    foreach ($acl in @($AclFindings)) {
        if ($controlRights -notcontains [string]$acl.NormalizedRight) { continue }
        if ([string]$acl.TargetObjectClass -ne 'groupPolicyContainer') { continue }
        if (-not $acl.TargetDistinguishedName) { continue }

        $gpoKey = ([string]$acl.TargetDistinguishedName).ToLowerInvariant()
        if (-not $gpoByDn.ContainsKey($gpoKey)) { continue }

        $gpo = $gpoByDn[$gpoKey]
        $linksForGpo = if ($linksByGpoDn.ContainsKey($gpoKey)) { @($linksByGpoDn[$gpoKey]) } else { @($null) }
        foreach ($link in $linksForGpo) {
            $scope = if ($link) {
                Resolve-ADPostureGpoScopeContext -Link $link
            }
            else {
                [pscustomobject]@{
                    ScopeTier = 'Unlinked'
                    ScopeRiskContext = 'GPO has no collected enabled link scope'
                    ScopeRiskMultiplier = 0.65
                    Tags = @('UnlinkedGpo')
                }
            }

            $baseScore = Get-ADPostureGpoDelegationBaseScore -Right $acl.NormalizedRight
            $linkMultiplier = 1.0
            $linkTags = @()
            if ($link -and $link.IsEnforced) {
                $linkMultiplier += 0.15
                $linkTags += 'EnforcedGpoLink'
            }
            if ($link -and $link.IsLinkDisabled) {
                $linkMultiplier = 0.35
                $linkTags += 'DisabledGpoLink'
            }
            if ($gpo.Status -eq 'AllSettingsDisabled') {
                $linkMultiplier = [Math]::Min($linkMultiplier, 0.45)
                $linkTags += 'DisabledGpo'
            }

            $broadTrustee = Test-ADPostureGpoBroadTrustee -AclFinding $acl
            $trusteeMultiplier = if ($broadTrustee) { 1.2 } else { 1.0 }
            $score = [Math]::Min(15, $baseScore * $scope.ScopeRiskMultiplier * $linkMultiplier * $trusteeMultiplier)
            $severity = Get-ADPostureGpoSeverity -RiskScore $score
            $tags = @($acl.Tags + $scope.Tags + $linkTags + 'GpoDelegation' + 'GpoControlPath' | Where-Object { $_ } | Sort-Object -Unique)
            if ($broadTrustee) { $tags = @($tags + 'BroadTrustee' | Sort-Object -Unique) }

            $reason = "Trustee '$($acl.TrusteeName)' has $($acl.NormalizedRight) over GPO '$($gpo.DisplayName)'. Scope context: $($scope.ScopeRiskContext)."
            if ($broadTrustee) {
                $reason += ' Trustee is broad/default population, increasing blast radius.'
            }
            if ($link -and $link.IsEnforced) {
                $reason += ' Link is enforced, increasing policy precedence impact.'
            }
            if ($link -and $link.IsLinkDisabled) {
                $reason += ' Link is currently disabled, reducing immediate applicability.'
            }

            $index++
            $findings.Add((New-ADPostureGpoFinding `
                -Index $index `
                -Domain $Domain `
                -FindingType 'GpoDelegationControl' `
                -Severity $severity `
                -RiskScore $score `
                -Gpo $gpo `
                -Link $link `
                -SourceAclFindingId $acl.AclFindingId `
                -DelegatedRight $acl.NormalizedRight `
                -TrusteeName $acl.TrusteeName `
                -TrusteeSid $acl.TrusteeSid `
                -TrusteeDistinguishedName $acl.TrusteeDistinguishedName `
                -TrusteeObjectClass $acl.TrusteeObjectClass `
                -ScopeTier $scope.ScopeTier `
                -ScopeRiskContext $scope.ScopeRiskContext `
                -ScopeRiskMultiplier $scope.ScopeRiskMultiplier `
                -Reason $reason `
                -Remediation 'Remove broad or standing GPO edit rights; restrict GPO delegation to an approved GPO administration group and validate the linked scope.' `
                -ScoreFormula "GPO delegation score = $baseScore * scope $($scope.ScopeRiskMultiplier) * link $linkMultiplier * trustee $trusteeMultiplier" `
                -ScoreComponents @(
                    [pscustomobject]@{ Name = 'Delegated right'; Value = $acl.NormalizedRight; Weight = $baseScore },
                    [pscustomobject]@{ Name = 'Scope'; Value = $scope.ScopeRiskContext; Weight = $scope.ScopeRiskMultiplier },
                    [pscustomobject]@{ Name = 'Link state'; Value = if ($link) { "Disabled=$($link.IsLinkDisabled); Enforced=$($link.IsEnforced)" } else { 'Unlinked' }; Weight = $linkMultiplier },
                    [pscustomobject]@{ Name = 'Trustee breadth'; Value = if ($broadTrustee) { 'Broad trustee' } else { 'Specific trustee' }; Weight = $trusteeMultiplier }
                ) `
                -Tags $tags))
        }
    }

    @($findings)
}

function ConvertTo-ADPostureGpoRiskModel {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [object[]]$Gpos = @(),
        [object[]]$Links = @(),
        [object[]]$AclFindings = @(),
        [switch]$IncludeSysvolAcl
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = 0
    $gpoByDn = @{}
    foreach ($gpo in @($Gpos)) {
        if ($gpo.DistinguishedName) {
            $gpoByDn[[string]$gpo.DistinguishedName.ToLowerInvariant()] = $gpo
        }
    }

    foreach ($gpo in @($Gpos)) {
        if (-not $gpo.FileSysPath) {
            $index++
            $findings.Add((New-ADPostureGpoFinding -Index $index -Domain $Domain -FindingType 'GpoMissingSysvolPath' -Severity 'High' -RiskScore 6.5 -Gpo $gpo -Reason 'GPO container has no SYSVOL path, which can indicate a broken or incomplete policy object.' -Remediation 'Validate SYSVOL replication and remove or repair the orphaned GPO.' -Tags @('GpoIntegrity', 'SysvolExposure')))
        }
        elseif ($gpo.FileSysPath -notmatch '^(?i:\\\\[^\\]+\\SYSVOL\\)') {
            $index++
            $findings.Add((New-ADPostureGpoFinding -Index $index -Domain $Domain -FindingType 'GpoUnusualSysvolPath' -Severity 'High' -RiskScore 7.0 -Gpo $gpo -Reason 'GPO points to an unusual file system path outside the expected SYSVOL UNC pattern.' -Remediation 'Review the GPO file system path and ensure policy files are hosted only from expected SYSVOL locations.' -Tags @('GpoIntegrity', 'UnusualPath')))
        }
    }

    foreach ($link in @($Links)) {
        $gpo = $null
        $key = ([string]$link.GpoDistinguishedName).ToLowerInvariant()
        if ($gpoByDn.ContainsKey($key)) { $gpo = $gpoByDn[$key] }

        if (-not $gpo) { continue }
    }

    $delegationFindings = @(New-ADPostureGpoDelegationFindings -StartIndex $index -Domain $Domain -Gpos @($Gpos) -Links @($Links) -AclFindings @($AclFindings))
    foreach ($finding in $delegationFindings) {
        $findings.Add($finding)
    }
    $index += @($delegationFindings).Count

    if ($IncludeSysvolAcl) {
        $pathFindings = @(New-ADPostureGpoPathAclFindings -StartIndex $index -Domain $Domain -Gpos @($Gpos) -Links @($Links))
        foreach ($finding in $pathFindings) {
            $findings.Add($finding)
        }
        $index += @($pathFindings).Count

        $securityOptionFindings = @(New-ADPostureGpoSecurityOptionFindings -StartIndex $index -Domain $Domain -Gpos @($Gpos) -Links @($Links))
        foreach ($finding in $securityOptionFindings) {
            $findings.Add($finding)
        }
        $index += @($securityOptionFindings).Count

        $scriptContentFindings = @(New-ADPostureGpoScriptContentFindings -StartIndex $index -Domain $Domain -Gpos @($Gpos) -Links @($Links))
        foreach ($finding in $scriptContentFindings) {
            $findings.Add($finding)
        }
        $index += @($scriptContentFindings).Count

        $preferenceFindings = @(New-ADPostureGpoPreferenceFindings -StartIndex $index -Domain $Domain -Gpos @($Gpos) -Links @($Links))
        foreach ($finding in $preferenceFindings) {
            $findings.Add($finding)
        }
        $index += @($preferenceFindings).Count

        $loopbackFindings = @(New-ADPostureGpoLoopbackFindings -StartIndex $index -Domain $Domain -Gpos @($Gpos) -Links @($Links))
        foreach ($finding in $loopbackFindings) {
            $findings.Add($finding)
        }
        $index += @($loopbackFindings).Count
    }

    $securityFilterFindings = @(New-ADPostureGpoSecurityFilterFindings -StartIndex $index -Domain $Domain -Gpos @($Gpos) -Links @($Links))
    foreach ($finding in $securityFilterFindings) {
        $findings.Add($finding)
    }
    $index += @($securityFilterFindings).Count

    $wmiFilterFindings = @(New-ADPostureGpoWmiFilterFindings -StartIndex $index -Domain $Domain -Gpos @($Gpos) -Links @($Links))
    foreach ($finding in $wmiFilterFindings) {
        $findings.Add($finding)
    }

    [pscustomobject]@{
        Gpos = @($Gpos)
        GpoLinks = @($Links)
        GpoFindings = @($findings)
    }
}

function ConvertTo-ADPostureGpoObject {
    param([object]$InputObject)

    $properties = $InputObject.PSObject.Properties
    $flags = if ($properties['flags']) { $properties['flags'].Value } else { 0 }
    $fileSysPath = if ($properties['gPCFileSysPath']) { [string]$properties['gPCFileSysPath'].Value } else { $null }
    $machineExtensions = if ($properties['gPCMachineExtensionNames']) { [string]$properties['gPCMachineExtensionNames'].Value } else { '' }
    $userExtensions = if ($properties['gPCUserExtensionNames']) { [string]$properties['gPCUserExtensionNames'].Value } else { '' }
    $hasScriptExtension = ($machineExtensions + ' ' + $userExtensions) -match '(?i)(Scripts|42B5FAAE-6536-11D2-AE5A-0000F87571E3|40B6664F-4972-11D1-A7CA-0000F87571E3)'
    $securityFilters = if ($properties['SecurityFilterPrincipals']) { @($properties['SecurityFilterPrincipals'].Value) } else { @() }

    [pscustomobject]@{
        DisplayName = if ($properties['DisplayName']) { [string]$properties['DisplayName'].Value } elseif ($properties['Name']) { [string]$properties['Name'].Value } else { $null }
        Name = if ($properties['Name']) { [string]$properties['Name'].Value } else { $null }
        Guid = if ($properties['Name']) { ([string]$properties['Name'].Value).Trim('{}') } else { $null }
        DistinguishedName = if ($properties['DistinguishedName']) { [string]$properties['DistinguishedName'].Value } else { $null }
        FileSysPath = $fileSysPath
        Status = Get-ADPostureGpoStatus -Flags $flags
        Flags = $flags
        MachineExtensionNames = $machineExtensions
        UserExtensionNames = $userExtensions
        WmiFilter = if ($properties['gPCWQLFilter']) { [string]$properties['gPCWQLFilter'].Value } else { $null }
        HasScripts = [bool]$hasScriptExtension
        SecurityFilterPrincipals = @($securityFilters)
    }
}

function ConvertTo-ADPostureGpoScope {
    param([object]$InputObject)

    $properties = $InputObject.PSObject.Properties
    [pscustomobject]@{
        Name = if ($properties['Name']) { [string]$properties['Name'].Value } else { $null }
        DistinguishedName = if ($properties['DistinguishedName']) { [string]$properties['DistinguishedName'].Value } else { $null }
        ObjectClass = if ($properties['ObjectClass']) {
            $classValue = $properties['ObjectClass'].Value
            if ($classValue -is [array]) { [string]$classValue[-1] } else { [string]$classValue }
        } else { $null }
        GpLink = if ($properties['gPLink']) { [string]$properties['gPLink'].Value } else { $null }
    }
}

function Get-ADPostureGpoPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Domain,
        [hashtable]$DomainParams,
        [string[]]$SearchBase,
        [switch]$IncludeSysvolAcl,
        [string]$LogPath
    )

    $queryParams = if ($DomainParams) { $DomainParams } else { @{} }
    $domainDn = $Domain.DistinguishedName
    $policiesDn = "CN=Policies,CN=System,$domainDn"
    $gpos = @()
    $scopes = [System.Collections.Generic.List[object]]::new()

    Write-Host "GPO posture collection: reading GPO containers and linked scopes."
    if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
        Write-ADPostureLog -Message 'GPO posture collection: reading GPO containers and linked scopes.' -Path $LogPath
    }

    try {
        $gpos = @(Get-ADObject -SearchBase $policiesDn -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties DisplayName,gPCFileSysPath,flags,gPCMachineExtensionNames,gPCUserExtensionNames,gPCWQLFilter @queryParams -ErrorAction Stop |
            ForEach-Object { ConvertTo-ADPostureGpoObject -InputObject $_ })
    }
    catch {
        Write-Warning "Could not enumerate GPO containers under '$policiesDn': $($_.Exception.Message)"
        $gpos = @()
    }

    foreach ($gpo in @($gpos)) {
        if (-not $gpo.DistinguishedName) { continue }
        $filters = @(Get-ADPostureGpoSecurityFilterPrincipals -DistinguishedName $gpo.DistinguishedName)
        try {
            $gpo | Add-Member -NotePropertyName SecurityFilterPrincipals -NotePropertyValue $filters -Force
        }
        catch {
            Write-Verbose "Could not attach GPO security filter metadata for '$($gpo.DisplayName)': $($_.Exception.Message)"
        }
    }

    try {
        $domainScope = Get-ADObject -Identity $domainDn -Properties gPLink,ObjectClass @queryParams -ErrorAction Stop
        $scopes.Add((ConvertTo-ADPostureGpoScope -InputObject $domainScope))
    }
    catch {
        Write-Warning "Could not read domain gPLink for '$domainDn': $($_.Exception.Message)"
    }

    $scopeBases = if ($SearchBase) { @($SearchBase) } else { @($domainDn) }
    foreach ($base in $scopeBases) {
        try {
            Get-ADOrganizationalUnit -SearchBase $base -LDAPFilter '(gPLink=*)' -Properties gPLink @queryParams -ErrorAction Stop |
                ForEach-Object { $scopes.Add((ConvertTo-ADPostureGpoScope -InputObject $_)) }
        }
        catch {
            Write-Warning "Could not enumerate linked OU scopes under '$base': $($_.Exception.Message)"
        }
    }

    $links = [System.Collections.Generic.List[object]]::new()
    foreach ($scope in @($scopes)) {
        foreach ($link in @(ConvertFrom-ADPostureGpLink -GpLink $scope.GpLink -ScopeName $scope.Name -ScopeDistinguishedName $scope.DistinguishedName -ScopeObjectClass $scope.ObjectClass)) {
            $links.Add($link)
        }
    }

    $message = "GPO posture collection complete: $(@($gpos).Count) GPOs, $($links.Count) links."
    Write-Host $message
    if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
        Write-ADPostureLog -Message $message -Path $LogPath
    }

    ConvertTo-ADPostureGpoRiskModel -Domain $Domain.DNSRoot -Gpos @($gpos) -Links @($links) -IncludeSysvolAcl:$IncludeSysvolAcl
}
