$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
. (Join-Path $repoRoot 'src\Private\Get-ADPostureKerberosAuthPosture.ps1')

Describe 'Kerberos/Auth posture model' {
    It 'does not report AS-REP disabled on an otherwise ordinary account' {
        $principal = [pscustomobject]@{
            SamAccountName = 'user-nopreauth'
            DistinguishedName = 'CN=user-nopreauth,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1001'
            objectClass = @('top', 'person', 'user')
            userAccountControl = 0x400200
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)

        @($model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosAsRepRoastableAccount').Count | Should Be 0
    }

    It 'reports AS-REP roastable accounts when pre-auth is disabled on a sensitive account' {
        $principal = [pscustomobject]@{
            SamAccountName = 'da-nopreauth'
            DistinguishedName = 'CN=da-nopreauth,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1101'
            objectClass = @('top', 'person', 'user')
            userAccountControl = 0x410200
            adminCount = 1
            memberOf = @('CN=Domain Admins,CN=Users,DC=contoso,DC=local')
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)

        $finding = $model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosAsRepRoastableAccount' | Select-Object -First 1
        $finding | Should Not BeNullOrEmpty
        $finding.RiskPattern | Should Be 'AS-REP Roast'
        $finding.Tags -contains 'ASREP' | Should Be $true
    }

    It 'reports Kerberoastable service principals and weak no-AES posture' {
        $principal = [pscustomobject]@{
            SamAccountName = 'svc-sql'
            DistinguishedName = 'CN=svc-sql,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1002'
            objectClass = @('top', 'person', 'user')
            userAccountControl = 0x200
            servicePrincipalName = @('MSSQLSvc/sql01.contoso.local:1433')
            'msDS-SupportedEncryptionTypes' = 4
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)

        @($model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosRoastableServiceAccount').Count | Should Be 1
        @($model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosRc4OnlyOrNoAes').Count | Should Be 1
    }

    It 'reports DES-only Kerberos encryption' {
        $principal = [pscustomobject]@{
            SamAccountName = 'svc-des'
            DistinguishedName = 'CN=svc-des,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1003'
            objectClass = @('top', 'person', 'user')
            userAccountControl = 0x200
            servicePrincipalName = @('HTTP/legacy.contoso.local')
            'msDS-SupportedEncryptionTypes' = 3
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)

        $finding = $model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosDesOnlyAccount' | Select-Object -First 1
        $finding | Should Not BeNullOrEmpty
        $finding.Tags -contains 'DES' | Should Be $true
    }

    It 'reports unconstrained, constrained, and resource-based constrained delegation' {
        $principal = [pscustomobject]@{
            SamAccountName = 'web01$'
            DistinguishedName = 'CN=web01,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1004'
            objectClass = @('top', 'computer')
            userAccountControl = 0x1081000
            servicePrincipalName = @('HTTP/web01.contoso.local')
            'msDS-AllowedToDelegateTo' = @('HOST/app01.contoso.local')
            'msDS-AllowedToActOnBehalfOfOtherIdentity' = 'O:BAG:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2001)'
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)

        @($model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosUnconstrainedDelegation').Count | Should Be 1
        @($model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosConstrainedDelegation').Count | Should Be 1
        @($model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosResourceBasedConstrainedDelegation').Count | Should Be 1
    }

    It 'handles RBCD ActiveDirectorySecurity values from live AD without method invocation errors' {
        $principal = [pscustomobject]@{
            SamAccountName = 'app01$'
            DistinguishedName = 'CN=app01,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1006'
            objectClass = @('top', 'computer')
            userAccountControl = 0x1000
            servicePrincipalName = @('HOST/app01.contoso.local')
            'msDS-AllowedToActOnBehalfOfOtherIdentity' = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)

        @($model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosResourceBasedConstrainedDelegation').Count | Should Be 1
    }

    It 'flattens live AD Kerberos principals before snapshot and dashboard serialization' {
        $principal = [pscustomobject]@{
            SamAccountName = 'app02$'
            DistinguishedName = 'CN=app02,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1007'
            objectClass = @('top', 'computer')
            userAccountControl = 0x1000
            servicePrincipalName = @('HOST/app02.contoso.local')
            'msDS-AllowedToDelegateTo' = @('HOST/backend01.contoso.local')
            'msDS-AllowedToActOnBehalfOfOtherIdentity' = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)
        $row = @($model.KerberosAuthPrincipals)[0]

        $row.HasResourceBasedConstrainedDelegation | Should Be $true
        $row.ResourceBasedConstrainedDelegationValueTypes -contains 'System.DirectoryServices.ActiveDirectorySecurity' | Should Be $true
        $row.PSObject.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity'] | Should BeNullOrEmpty
        $row.PSObject.Properties['ResourceBasedConstrainedDelegation'] | Should BeNullOrEmpty
        { $model | ConvertTo-Json -Depth 12 } | Should Not Throw
    }

    It 'reports privileged accounts without delegation protection' {
        $principal = [pscustomobject]@{
            SamAccountName = 'tier0-admin'
            DistinguishedName = 'CN=tier0-admin,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1005'
            objectClass = @('top', 'person', 'user')
            userAccountControl = 0x200
            adminCount = 1
            memberOf = @('CN=Domain Admins,CN=Users,DC=contoso,DC=local')
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)

        $finding = $model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosSensitiveAccountDelegable' | Select-Object -First 1
        $finding | Should Not BeNullOrEmpty
        $finding.PrivilegeTier | Should Be 'Tier 0'
    }

    It 'treats Protected Users membership as privileged delegation protection evidence' {
        $principal = [pscustomobject]@{
            SamAccountName = 'tier0-protected'
            DistinguishedName = 'CN=tier0-protected,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-1008'
            objectClass = @('top', 'person', 'user')
            userAccountControl = 0x200
            adminCount = 1
            memberOf = @(
                'CN=Domain Admins,CN=Users,DC=contoso,DC=local',
                'CN=Protected Users,CN=Users,DC=contoso,DC=local'
            )
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal)

        @($model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosSensitiveAccountDelegable').Count | Should Be 0
        $snapshot = @($model.KerberosAuthPrincipals)[0]
        $snapshot.IsProtectedUsersMember | Should Be $true
        $snapshot.DelegationProtectionMethod | Should Be 'ProtectedUsers'
    }

    It 'reports stale krbtgt password age in Kerberos/Auth posture' {
        $principal = [pscustomobject]@{
            SamAccountName = 'krbtgt'
            DistinguishedName = 'CN=krbtgt,CN=Users,DC=contoso,DC=local'
            ObjectSid = 'S-1-5-21-1-502'
            objectClass = @('top', 'person', 'user')
            userAccountControl = 0x202
            PasswordLastSet = [datetime]'2025-01-01'
        }

        $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain 'contoso.local' -Principals @($principal) -AsOf ([datetime]'2026-06-03') -KrbtgtPasswordAgeDays 180

        $finding = $model.KerberosAuthFindings | Where-Object FindingType -eq 'KerberosKrbtgtPasswordStale' | Select-Object -First 1
        $finding | Should Not BeNullOrEmpty
        $finding.Tags -contains 'Krbtgt' | Should Be $true
    }
}
