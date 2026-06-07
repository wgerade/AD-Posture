$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\ConvertTo-ADPostureSafeLiteral.ps1')
. (Join-Path $repoRoot 'src\Public\New-ADPostureRemediationScript.ps1')
. (Join-Path $repoRoot 'src\Public\New-ADPostureRemediationScriptSafe.ps1')

function Test-ADModuleAvailable { }
function Get-ModuleConfig { [pscustomobject]@{ ReportPath = $TestDrive } }

Describe 'Security hardening helpers' {
    It 'quotes PowerShell literals without allowing quote breakout' {
        ConvertTo-ADPosturePowerShellLiteral -Value "adm'; Remove-Item C:\*" | Should Be "'adm''; Remove-Item C:\*'"
    }

    It 'escapes AD filter literals' {
        ConvertTo-ADPostureADFilterLiteral -Value "Domain Admins' or Name -like '*" | Should Be "Domain Admins'' or Name -like ''*"
    }

    It 'generates remediation scripts with escaped inputs and runtime AD filters' {
        $out = Join-Path $TestDrive 'remediate.ps1'

        New-ADPostureRemediationScript `
            -SensitiveGroup "Domain Admins'; Get-ADUser * #" `
            -MemberSamAccountName "adm'; Remove-ADGroupMember x #" `
            -RemovalGroupIdentity "Nested Admins'; Get-ADGroup * #" `
            -Server "dc01'; Invoke-Expression x #" `
            -WhatIfOnly `
            -OutputPath $out | Out-Null

        $content = Get-Content -Path $out -Raw

        $content | Should Match "\`$MemberSamAccountName = 'adm''; Remove-ADGroupMember x #'"
        $content | Should Match "\`$SensitiveGroup = 'Domain Admins''; Get-ADUser \* #'"
        $content | Should Match "\`$RemovalGroupIdentity = 'Nested Admins''; Get-ADGroup \* #'"
        $content | Should Match "\`$Server = 'dc01''; Invoke-Expression x #'"
        $content | Should Match 'ConvertTo-ADFilterLiteral'
        $content | Should Match 'Get-ADUser -Filter \$memberFilter @serverParams'
        $content | Should Match 'Get-ADGroup -Filter \$memberFilter @serverParams'
        $content | Should Match 'Get-ADGroup -Identity \$RemovalGroupIdentity -Properties member'
        $content | Should Match 'is not a direct member'
        $content | Should Match 'Remove-ADGroupMember .* -WhatIf'
    }

    It 'uses the sensitive group as the default removal group' {
        $out = Join-Path $TestDrive 'default-removal-group-remediate.ps1'

        New-ADPostureRemediationScript `
            -SensitiveGroup 'Domain Admins' `
            -MemberSamAccountName 'adm.one' `
            -WhatIfOnly `
            -OutputPath $out | Out-Null

        (Get-Content -Path $out -Raw) | Should Match "\`$RemovalGroupIdentity = 'Domain Admins'"
    }
}
