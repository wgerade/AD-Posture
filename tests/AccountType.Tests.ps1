BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Resolve-ADPrincipalAccountType.ps1')
    . (Join-Path $repoRoot 'src\Private\Resolve-ADNativeIdentity.ps1')

}

Describe 'AD principal account type resolution' {
    It 'classifies gMSA from objectCategory CN as service account' {
        $principal = [pscustomobject]@{
            objectClass        = 'user'
            objectCategory     = 'CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=contoso,DC=com'
            SamAccountName     = 'svc-web$'
            DistinguishedName  = 'CN=svc-web,CN=Managed Service Accounts,DC=contoso,DC=com'
        }

        $result = Resolve-ADPrincipalAccountType -Principal $principal

        $result.Kind | Should -Be 'GroupManagedServiceAccount'
        $result.AccountType | Should -Be 'ServiceAccount (gMSA)'
    }

    It 'classifies gMSA from objectClass as service account' {
        $principal = [pscustomobject]@{
            objectClass        = @('top', 'person', 'organizationalPerson', 'user', 'msDS-GroupManagedServiceAccount')
            objectCategory     = $null
            SamAccountName     = 'svc-sql$'
            DistinguishedName  = 'CN=svc-sql,CN=Managed Service Accounts,DC=contoso,DC=com'
        }

        $result = Resolve-ADPrincipalAccountType -Principal $principal

        $result.Kind | Should -Be 'GroupManagedServiceAccount'
        $result.AccountType | Should -Be 'ServiceAccount (gMSA)'
    }

    It 'classifies sMSA from objectCategory CN as service account' {
        $principal = [pscustomobject]@{
            objectClass        = 'user'
            objectCategory     = 'CN=ms-DS-Managed-Service-Account,CN=Schema,CN=Configuration,DC=contoso,DC=com'
            SamAccountName     = 'svc-legacy$'
            DistinguishedName  = 'CN=svc-legacy,CN=Managed Service Accounts,DC=contoso,DC=com'
        }

        $result = Resolve-ADPrincipalAccountType -Principal $principal

        $result.Kind | Should -Be 'ManagedServiceAccount'
        $result.AccountType | Should -Be 'ServiceAccount (sMSA)'
    }

    It 'marks Enterprise Domain Controllers as native AD authority identity' {
        $principal = [pscustomobject]@{
            Name = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
            SamAccountName = 'ENTERPRISE DOMAIN CONTROLLERS'
            SID = [pscustomobject]@{ Value = 'S-1-5-9' }
        }

        $result = Resolve-ADNativeIdentity -Principal $principal -AccountType 'Unknown'

        $result.IsNativeIdentity | Should -Be $true
        $result.IsRemediableIdentity | Should -Be $false
        $result.NativeIdentityCategory | Should -Be 'Native AD authority'
    }

    It 'marks built-in domain RID principals as non-remediable native identities' {
        $principal = [pscustomobject]@{
            Name = 'Administrator'
            SamAccountName = 'Administrator'
            SID = [pscustomobject]@{ Value = 'S-1-5-21-1000-1000-1000-500' }
        }

        $result = Resolve-ADNativeIdentity -Principal $principal -AccountType 'User'

        $result.IsNativeIdentity | Should -Be $true
        $result.IsRemediableIdentity | Should -Be $false
        $result.NativeIdentityCategory | Should -Be 'Built-in domain principal'
    }
}
