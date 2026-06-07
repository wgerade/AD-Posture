$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\Get-ADPostureGpoPosture.ps1')

Describe 'GPO posture model' {
    It 'parses GPO links with disabled and enforced flags' {
        $links = ConvertFrom-ADPostureGpLink `
            -GpLink '[LDAP://CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System,DC=contoso,DC=local;3]' `
            -ScopeName 'Tier0' `
            -ScopeDistinguishedName 'OU=Tier0,DC=contoso,DC=local' `
            -ScopeObjectClass 'organizationalUnit'

        @($links).Count | Should Be 1
        $links[0].IsLinkDisabled | Should Be $true
        $links[0].IsEnforced | Should Be $true
        $links[0].ScopeName | Should Be 'Tier0'
    }

    It 'keeps hygiene/link metadata out of the risk queue while still reporting risky GPO integrity paths' {
        $gpoDn = 'CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Tier0 Lockdown'
                Guid = '11111111-1111-1111-1111-111111111111'
                DistinguishedName = $gpoDn
                FileSysPath = '\\contoso.local\SYSVOL\contoso.local\Policies\{11111111-1111-1111-1111-111111111111}'
                Status = 'AllSettingsDisabled'
                HasScripts = $true
            },
            [pscustomobject]@{
                DisplayName = 'Odd Path'
                Guid = '22222222-2222-2222-2222-222222222222'
                DistinguishedName = 'CN={22222222-2222-2222-2222-222222222222},CN=Policies,CN=System,DC=contoso,DC=local'
                FileSysPath = 'C:\Temp\Policy'
                Status = 'Enabled'
                HasScripts = $false
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 2
                IsLinkDisabled = $false
                IsEnforced = $true
                ScopeName = 'contoso.local'
                ScopeDistinguishedName = 'DC=contoso,DC=local'
                ScopeObjectClass = 'domainDNS'
            },
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 1
                IsLinkDisabled = $true
                IsEnforced = $false
                ScopeName = 'Workstations'
                ScopeDistinguishedName = 'OU=Workstations,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            },
            [pscustomobject]@{
                GpoDistinguishedName = 'CN={99999999-9999-9999-9999-999999999999},CN=Policies,CN=System,DC=contoso,DC=local'
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Stale'
                ScopeDistinguishedName = 'OU=Stale,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links

        @($model.GpoFindings | Where-Object FindingType -eq 'GpoUnusualSysvolPath').Count | Should Be 1
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoEnforcedLink').Count | Should Be 0
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoAllSettingsDisabled').Count | Should Be 0
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoScriptSettings').Count | Should Be 0
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoDisabledLink').Count | Should Be 0
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoOrphanedLink').Count | Should Be 0
    }

    It 'reports external script paths without querying ACLs outside SYSVOL' {
        $root = Join-Path $TestDrive 'GpoRoot'
        $scripts = Join-Path $root 'Machine\Scripts\Startup'
        New-Item -ItemType Directory -Path $scripts -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $scripts 'Scripts.ini') -Value @(
            '[Startup]'
            '0CmdLine=\\fileserver01\deploy\startup.ps1'
            '0Parameters='
        )

        $gpoDn = 'CN={44444444-4444-4444-4444-444444444444},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'External Startup Script'
                Guid = '44444444-4444-4444-4444-444444444444'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $external = @($model.GpoFindings | Where-Object FindingType -eq 'GpoExternalScriptPath')

        @($external).Count | Should Be 1
        $external[0].FileSystemPath | Should Be '\\fileserver01\deploy\startup.ps1'
        $external[0].ScopeTier | Should Be 'Tier 0'
        $external[0].Tags -contains 'ExternalAclNotQueried' | Should Be $true
        @($model.GpoFindings | Where-Object FindingType -like 'GpoExternalScriptAcl*').Count | Should Be 0
    }

    It 'reports configured drive-letter PowerShell script paths as external execution dependencies' {
        $root = Join-Path $TestDrive 'DriveMappedScriptGpoRoot'
        $scripts = Join-Path $root 'Machine\Scripts\Startup'
        New-Item -ItemType Directory -Path $scripts -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $scripts 'PSScripts.ini') -Value @(
            '[Startup]'
            '0CmdLine=Z:\Projects\New-ADPostureLabAccounts.ps1'
            '0Parameters='
        )

        $gpoDn = 'CN={45454545-4545-4545-4545-454545454545},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Drive Letter Startup Script'
                Guid = '45454545-4545-4545-4545-454545454545'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Workstations'
                ScopeDistinguishedName = 'OU=Workstations,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $external = @($model.GpoFindings | Where-Object FindingType -eq 'GpoExternalScriptPath')

        @($external).Count | Should Be 1
        $external[0].FileSystemPath | Should Be 'Z:\Projects\New-ADPostureLabAccounts.ps1'
        $external[0].Reason | Should Match 'does not connect to external file paths'
    }

    It 'reports forward-slash drive-letter script paths as external execution dependencies' {
        $root = Join-Path $TestDrive 'ForwardSlashDriveMappedScriptGpoRoot'
        $scripts = Join-Path $root 'Machine\Scripts\Startup'
        New-Item -ItemType Directory -Path $scripts -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $scripts 'PSScripts.ini') -Value @(
            '[Startup]'
            '0CmdLine=Z:/Projects/New-ADPostureLabAccounts.ps1'
            '0Parameters='
        )

        $gpoDn = 'CN={46464646-4646-4646-4646-464646464646},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Forward Slash Drive Letter Script'
                Guid = '46464646-4646-4646-4646-464646464646'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Workstations'
                ScopeDistinguishedName = 'OU=Workstations,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $external = @($model.GpoFindings | Where-Object FindingType -eq 'GpoExternalScriptPath')

        @($external).Count | Should Be 1
        $external[0].FileSystemPath | Should Be 'Z:/Projects/New-ADPostureLabAccounts.ps1'
    }

    It 'reports script metadata that cannot be parsed instead of staying silent' {
        $root = Join-Path $TestDrive 'UnparsedScriptMetadataGpoRoot'
        New-Item -ItemType Directory -Path (Join-Path $root 'Machine\Scripts') -Force | Out-Null

        $gpoDn = 'CN={48484848-4848-4848-4848-484848484848},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Unparsed Script Metadata'
                Guid = '48484848-4848-4848-4848-484848484848'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $unparsed = @($model.GpoFindings | Where-Object FindingType -eq 'GpoScriptMetadataUnparsed')

        @($unparsed).Count | Should Be 1
        $unparsed[0].Reason | Should Match 'no configured script path could be extracted'
    }

    It 'reports weak ACLs on configured GPO script files and folders in SYSVOL' {
        $root = Join-Path $TestDrive 'ScriptGpoRoot'
        $scripts = Join-Path $root 'Machine\Scripts\Startup'
        New-Item -ItemType Directory -Path $scripts -Force | Out-Null
        $scriptFile = Join-Path $scripts 'Startup.ps1'
        Set-Content -LiteralPath (Join-Path $scripts 'PSScripts.ini') -Value @(
            '[Startup]'
            '0CmdLine=Startup.ps1'
            '0Parameters='
        )
        Set-Content -LiteralPath $scriptFile -Value 'Write-Host startup'

        $everyone = ([System.Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([System.Security.Principal.NTAccount])
        $folderAcl = Get-Acl -LiteralPath $scripts
        $folderRule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, 'Modify', 'None', 'None', 'Allow')
        $folderAcl.AddAccessRule($folderRule)
        Set-Acl -LiteralPath $scripts -AclObject $folderAcl
        $fileAcl = Get-Acl -LiteralPath $scriptFile
        $fileRule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, 'FullControl', 'Allow')
        $fileAcl.AddAccessRule($fileRule)
        Set-Acl -LiteralPath $scriptFile -AclObject $fileAcl

        $gpoDn = 'CN={55555555-5555-5555-5555-555555555555},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Startup Script ACL'
                Guid = '55555555-5555-5555-5555-555555555555'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $fileFindings = @($model.GpoFindings | Where-Object FindingType -eq 'GpoScriptFileAclWeak')
        $folderFindings = @($model.GpoFindings | Where-Object FindingType -eq 'GpoScriptFolderAclWeak')
        $configured = @($model.GpoFindings | Where-Object FindingType -eq 'GpoConfiguredScript')

        @($fileFindings).Count | Should BeGreaterThan 0
        @($folderFindings).Count | Should BeGreaterThan 0
        @($configured).Count | Should Be 0
        $fileFindings[0].FileSystemPath | Should Be $scriptFile
        $folderFindings[0].FileSystemPath | Should Be $scripts
        $fileFindings[0].Tags -contains 'ExecutionPath' | Should Be $true
    }

    It 'resolves classic Scripts.ini entries into Startup and Shutdown subfolders' {
        $root = Join-Path $TestDrive 'ClassicScriptGpoRoot'
        $scriptsRoot = Join-Path $root 'Machine\Scripts'
        $shutdown = Join-Path $scriptsRoot 'Shutdown'
        New-Item -ItemType Directory -Path $shutdown -Force | Out-Null
        $scriptFile = Join-Path $shutdown 'Script.BAT'
        Set-Content -LiteralPath (Join-Path $scriptsRoot 'Scripts.ini') -Value @(
            '[Shutdown]'
            '0CmdLine=Script.BAT'
            '0Parameters='
        )
        Set-Content -LiteralPath $scriptFile -Value 'echo shutdown'

        $everyone = ([System.Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([System.Security.Principal.NTAccount])
        $fileAcl = Get-Acl -LiteralPath $scriptFile
        $fileRule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, 'FullControl', 'Allow')
        $fileAcl.AddAccessRule($fileRule)
        Set-Acl -LiteralPath $scriptFile -AclObject $fileAcl

        $gpoDn = 'CN={66666666-6666-6666-6666-666666666666},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Classic Shutdown Script'
                Guid = '66666666-6666-6666-6666-666666666666'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Workstations'
                ScopeDistinguishedName = 'OU=Workstations,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $configured = @($model.GpoFindings | Where-Object FindingType -eq 'GpoConfiguredScript')
        $fileFindings = @($model.GpoFindings | Where-Object FindingType -eq 'GpoScriptFileAclWeak')

        @($configured).Count | Should Be 0
        @($fileFindings).Count | Should BeGreaterThan 0
        $fileFindings[0].FileSystemPath | Should Be $scriptFile
    }

    It 'discovers scripts from standard GPO script folders when metadata parsing is unavailable' {
        $root = Join-Path $TestDrive 'FolderOnlyScriptGpoRoot'
        $startup = Join-Path $root 'Machine\Scripts\Startup'
        New-Item -ItemType Directory -Path $startup -Force | Out-Null
        $scriptFile = Join-Path $startup 'PowerShellScript.ps1'
        Set-Content -LiteralPath $scriptFile -Value 'Write-Host startup'

        $everyone = ([System.Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([System.Security.Principal.NTAccount])
        $fileAcl = Get-Acl -LiteralPath $scriptFile
        $fileRule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, 'FullControl', 'Allow')
        $fileAcl.AddAccessRule($fileRule)
        Set-Acl -LiteralPath $scriptFile -AclObject $fileAcl

        $gpoDn = 'CN={77777777-7777-7777-7777-777777777777},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Folder Only Startup Script'
                Guid = '77777777-7777-7777-7777-777777777777'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $configured = @($model.GpoFindings | Where-Object FindingType -eq 'GpoConfiguredScript')
        $fileFindings = @($model.GpoFindings | Where-Object FindingType -eq 'GpoScriptFileAclWeak')

        @($configured).Count | Should Be 0
        @($fileFindings).Count | Should BeGreaterThan 0
        $fileFindings[0].FileSystemPath | Should Be $scriptFile
    }

    It 'reports broad security filtering only on critical or infrastructure scopes' {
        $gpoDn = 'CN={88888888-8888-8888-8888-888888888888},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Broad DC Apply'
                Guid = '88888888-8888-8888-8888-888888888888'
                DistinguishedName = $gpoDn
                FileSysPath = '\\contoso.local\SYSVOL\contoso.local\Policies\{88888888-8888-8888-8888-888888888888}'
                Status = 'Enabled'
                HasScripts = $false
                SecurityFilterPrincipals = @([pscustomobject]@{ Name = 'Everyone'; Right = 'ApplyGroupPolicy'; IsInherited = $false })
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links
        $filterFindings = @($model.GpoFindings | Where-Object FindingType -eq 'GpoBroadSecurityFiltering')

        @($filterFindings).Count | Should Be 1
        $filterFindings[0].TrusteeName | Should Be 'Everyone'
        $filterFindings[0].ScopeTier | Should Be 'Tier 0'
    }

    It 'reports risky security options from GptTmpl.inf' {
        $root = Join-Path $TestDrive 'RiskySecurityOptionsGpo'
        $secEdit = Join-Path $root 'Machine\Microsoft\Windows NT\SecEdit'
        New-Item -ItemType Directory -Path $secEdit -Force | Out-Null
        $templatePath = Join-Path $secEdit 'GptTmpl.inf'
        Set-Content -LiteralPath $templatePath -Value @(
            '[Privilege Rights]'
            'SeDebugPrivilege = *S-1-5-32-544,*S-1-1-0'
            'SeImpersonatePrivilege = *S-1-5-11'
            '[Registry Values]'
            'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,0'
            'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,1'
        )

        $gpoDn = 'CN={99999999-9999-9999-9999-999999999998},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Risky Security Options'
                Guid = '99999999-9999-9999-9999-999999999998'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $false
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $userRight = @($model.GpoFindings | Where-Object { $_.FindingType -eq 'GpoRiskyUserRight' -and $_.DelegatedRight -eq 'SeDebugPrivilege' })
        $impersonateRight = @($model.GpoFindings | Where-Object { $_.FindingType -eq 'GpoRiskyUserRight' -and $_.DelegatedRight -eq 'SeImpersonatePrivilege' })
        $securityOption = @($model.GpoFindings | Where-Object { $_.FindingType -eq 'GpoRiskySecurityOption' -and $_.DelegatedRight -eq 'EnableLUA' })
        $anonymousOption = @($model.GpoFindings | Where-Object { $_.FindingType -eq 'GpoRiskySecurityOption' -and $_.DelegatedRight -eq 'EveryoneIncludesAnonymous' })

        @($userRight).Count | Should Be 1
        @($impersonateRight).Count | Should Be 1
        @($securityOption).Count | Should Be 1
        @($anonymousOption).Count | Should Be 1
        $userRight[0].FileSystemPath | Should Be $templatePath
        $securityOption[0].ScopeTier | Should Be 'Tier 0'
    }

    It 'reports WMI filter dependencies on critical or infrastructure scopes' {
        $gpoDn = 'CN={BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'WMI Filtered DC Policy'
                Guid = 'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB'
                DistinguishedName = $gpoDn
                FileSysPath = '\\contoso.local\SYSVOL\contoso.local\Policies\{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}'
                Status = 'Enabled'
                HasScripts = $false
                WmiFilter = 'contoso.local;{11111111-1111-1111-1111-111111111111};Windows 10 Only'
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links
        $wmi = @($model.GpoFindings | Where-Object FindingType -eq 'GpoWmiFilterDependency')

        @($wmi).Count | Should Be 1
        $wmi[0].ScopeTier | Should Be 'Tier 0'
        $wmi[0].Reason | Should Match 'depends on WMI filter'
    }

    It 'reports loopback processing on critical or infrastructure scopes' {
        $root = Join-Path $TestDrive 'LoopbackGpo'
        New-Item -ItemType Directory -Path (Join-Path $root 'Machine') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'Machine\Registry.pol') -Value 'Software\Policies\Microsoft\Windows\System UserPolicyMode 2 Replace'

        $gpoDn = 'CN={CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Server Loopback'
                Guid = 'CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $false
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Servers'
                ScopeDistinguishedName = 'OU=Servers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $loopback = @($model.GpoFindings | Where-Object FindingType -eq 'GpoLoopbackProcessing')

        @($loopback).Count | Should Be 1
        $loopback[0].DelegatedRight | Should Be 'LoopbackReplace'
        $loopback[0].ScopeTier | Should Be 'Tier 1'
    }

    It 'reports risky Group Policy Preferences for credentials, local admins, tasks, services, and external paths' {
        $root = Join-Path $TestDrive 'RiskyPreferencesGpo'
        $groups = Join-Path $root 'Machine\Preferences\Groups'
        $tasks = Join-Path $root 'Machine\Preferences\ScheduledTasks'
        $services = Join-Path $root 'Machine\Preferences\Services'
        New-Item -ItemType Directory -Path $groups,$tasks,$services -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $groups 'Groups.xml') -Value '<Groups><Group name="Administrators"><Properties groupName="Administrators" userName="contoso\svc" cpassword="abcd"/></Group></Groups>'
        Set-Content -LiteralPath (Join-Path $tasks 'ScheduledTasks.xml') -Value '<ScheduledTasks><Task name="Deploy" runAs="contoso\svc" appName="\\fileserver\share\deploy.ps1"/></ScheduledTasks>'
        Set-Content -LiteralPath (Join-Path $services 'Services.xml') -Value '<Services><Service name="BadSvc" imagePath="Z:\Tools\agent.exe"/></Services>'

        $gpoDn = 'CN={DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Risky Preferences'
                Guid = 'DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $false
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl

        @($model.GpoFindings | Where-Object FindingType -eq 'GpoPreferenceCredential').Count | Should BeGreaterThan 0
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoPreferenceLocalAdmin').Count | Should BeGreaterThan 0
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoPreferenceScheduledTask').Count | Should BeGreaterThan 0
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoPreferenceServiceControl').Count | Should BeGreaterThan 0
        @($model.GpoFindings | Where-Object FindingType -eq 'GpoPreferenceExternalPath').Count | Should BeGreaterThan 0
    }

    It 'reports risky script content inside SYSVOL scripts' {
        $root = Join-Path $TestDrive 'RiskyScriptContentGpo'
        $startup = Join-Path $root 'Machine\Scripts\Startup'
        New-Item -ItemType Directory -Path $startup -Force | Out-Null
        $scriptFile = Join-Path $startup 'Startup.ps1'
        Set-Content -LiteralPath $scriptFile -Value @(
            '$password = "P@ssw0rd123"'
            'Add-LocalGroupMember -Group Administrators -Member contoso\helpdesk'
        )

        $gpoDn = 'CN={99999999-9999-9999-9999-999999999999},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Risky Script Content'
                Guid = '99999999-9999-9999-9999-999999999999'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Servers'
                ScopeDistinguishedName = 'OU=Servers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $scriptFindings = @($model.GpoFindings | Where-Object FindingType -eq 'GpoRiskyScriptContent')

        @($scriptFindings).Count | Should Be 2
        $scriptFindings[0].FileSystemPath | Should Be $scriptFile
        @($scriptFindings | Where-Object DelegatedRight -eq 'CredentialLiteral').Count | Should Be 1
        @($scriptFindings | Where-Object DelegatedRight -eq 'LocalAdminModification').Count | Should Be 1
    }

    It 'does not report risky script content for empty SYSVOL scripts' {
        $root = Join-Path $TestDrive 'EmptyScriptContentGpo'
        $startup = Join-Path $root 'Machine\Scripts\Startup'
        New-Item -ItemType Directory -Path $startup -Force | Out-Null
        $scriptFile = Join-Path $startup 'PowerShellScript.ps1'
        New-Item -ItemType File -Path $scriptFile -Force | Out-Null

        $gpoDn = 'CN={AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'Empty Script Content'
                Guid = 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'
                DistinguishedName = $gpoDn
                FileSysPath = $root
                Status = 'Enabled'
                HasScripts = $true
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Workstations'
                ScopeDistinguishedName = 'OU=Workstations,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -IncludeSysvolAcl
        $scriptFindings = @($model.GpoFindings | Where-Object FindingType -eq 'GpoRiskyScriptContent')

        @($scriptFindings).Count | Should Be 0
    }

    It 'correlates GPO ACL delegation with linked scope criticality' {
        $gpoDn = 'CN={BFEAF247-07B5-44D2-ADEA-60C06C4D98DD},CN=Policies,CN=System,DC=contoso,DC=local'
        $gpos = @(
            [pscustomobject]@{
                DisplayName = 'New Group Policy Object'
                Guid = 'BFEAF247-07B5-44D2-ADEA-60C06C4D98DD'
                DistinguishedName = $gpoDn
                FileSysPath = '\\contoso.local\SYSVOL\contoso.local\Policies\{BFEAF247-07B5-44D2-ADEA-60C06C4D98DD}'
                Status = 'Enabled'
                HasScripts = $false
            }
        )
        $links = @(
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Domain Controllers'
                ScopeDistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            },
            [pscustomobject]@{
                GpoDistinguishedName = $gpoDn
                LinkOptions = 0
                IsLinkDisabled = $false
                IsEnforced = $false
                ScopeName = 'Workstations'
                ScopeDistinguishedName = 'OU=Workstations,DC=contoso,DC=local'
                ScopeObjectClass = 'organizationalUnit'
            }
        )
        $aclFindings = @(
            [pscustomobject]@{
                AclFindingId = 'acl-000100'
                TargetName = 'New Group Policy Object'
                TargetDistinguishedName = $gpoDn
                TargetObjectClass = 'groupPolicyContainer'
                TrusteeName = 'Everyone'
                TrusteeSid = 'S-1-1-0'
                TrusteeDistinguishedName = $null
                TrusteeObjectClass = 'wellKnownPrincipal'
                RawTrustee = 'Everyone'
                NormalizedRight = 'GenericAll'
                Tags = @('SensitiveAclTarget', 'SensitiveAclTrustee')
            }
        )

        $model = ConvertTo-ADPostureGpoRiskModel -Domain 'contoso.local' -Gpos $gpos -Links $links -AclFindings $aclFindings
        $delegation = @($model.GpoFindings | Where-Object FindingType -eq 'GpoDelegationControl')
        $dcFinding = $delegation | Where-Object ScopeName -eq 'Domain Controllers' | Select-Object -First 1
        $labFinding = $delegation | Where-Object ScopeName -eq 'Workstations' | Select-Object -First 1

        @($delegation).Count | Should Be 2
        $dcFinding.Severity | Should Be 'Critical'
        $dcFinding.ScopeTier | Should Be 'Tier 0'
        $dcFinding.Tags -contains 'DomainControllerScope' | Should Be $true
        $dcFinding.RiskScore | Should BeGreaterThan $labFinding.RiskScore
        $labFinding.Severity | Should Be 'High'
        $labFinding.ScopeTier | Should Be 'Tier 2'
        $labFinding.Tags -contains 'BroadTrustee' | Should Be $true
    }

    It 'normalizes synthetic AD GPO objects' {
        $gpo = [pscustomobject]@{
            DisplayName = 'Login Scripts'
            Name = '{33333333-3333-3333-3333-333333333333}'
            DistinguishedName = 'CN={33333333-3333-3333-3333-333333333333},CN=Policies,CN=System,DC=contoso,DC=local'
            gPCFileSysPath = '\\contoso.local\SYSVOL\contoso.local\Policies\{33333333-3333-3333-3333-333333333333}'
            flags = 1
            gPCMachineExtensionNames = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}]'
            gPCUserExtensionNames = ''
            gPCWQLFilter = 'contoso.local;{22222222-2222-2222-2222-222222222222};Workstation Filter'
        }

        $normalized = ConvertTo-ADPostureGpoObject -InputObject $gpo

        $normalized.DisplayName | Should Be 'Login Scripts'
        $normalized.Guid | Should Be '33333333-3333-3333-3333-333333333333'
        $normalized.Status | Should Be 'UserSettingsDisabled'
        $normalized.HasScripts | Should Be $true
        $normalized.WmiFilter | Should Match 'Workstation Filter'
    }
}
