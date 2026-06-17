BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ADPostureAdcsPosture.ps1')

}

Describe 'ADCS posture model' {
    It 'normalizes certificate template posture attributes' {
        $template = ConvertTo-ADPostureAdcsTemplateObject -InputObject ([pscustomobject]@{
            Name = 'UserAuth'
            DisplayName = 'User Authentication'
            DistinguishedName = 'CN=UserAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2')
            'msPKI-Certificate-Name-Flag' = 1
            'msPKI-Enrollment-Flag' = 0
            'msPKI-Private-Key-Flag' = 16
            'msPKI-RA-Signature' = 0
            'msPKI-Template-Schema-Version' = 2
            EnrollmentPrincipals = @('CONTOSO\Domain Users')
            AutoEnrollmentPrincipals = @('CONTOSO\Domain Users')
            ControlPrincipals = @()
        })

        $template.DisplayName | Should -Be 'User Authentication'
        $template.EnrolleeSuppliesSubject | Should -Be $true
        $template.ManagerApprovalRequired | Should -Be $false
        $template.ExportablePrivateKey | Should -Be $true
        $template.AutoEnrollmentPrincipals[0] | Should -Be 'CONTOSO\Domain Users'
        $template.ExtendedKeyUsage[0] | Should -Be '1.3.6.1.5.5.7.3.2'
    }

    It 'reports ESC1-like authentication templates with broad enrollment and no issuance gate' {
        $template = [pscustomobject]@{
            Name = 'UserAuth'
            DisplayName = 'User Authentication'
            DistinguishedName = 'CN=UserAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            SchemaVersion = 2
            EnrolleeSuppliesSubject = $true
            ManagerApprovalRequired = $false
            RequiredRaSignatures = 0
            ExportablePrivateKey = $false
            ExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
            EnrollmentPrincipals = @('CONTOSO\Domain Users')
            ControlPrincipals = @()
        }

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates @($template)
        $finding = @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsEsc1LikeTemplate') | Select-Object -First 1

        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsEsc1LikeTemplate').Count | Should -Be 1
        $finding.Severity | Should -Be 'Critical'
        $finding.RiskPattern | Should -Be 'ESC1-like'
        $finding.Tags -contains 'BroadEnrollment' | Should -Be $true
    }

    It 'does not report ESC1-like exposure when manager approval is required' {
        $template = [pscustomobject]@{
            Name = 'GovernedAuth'
            DisplayName = 'Governed Authentication'
            DistinguishedName = 'CN=GovernedAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            SchemaVersion = 2
            EnrolleeSuppliesSubject = $true
            ManagerApprovalRequired = $true
            RequiredRaSignatures = 0
            ExportablePrivateKey = $false
            ExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
            EnrollmentPrincipals = @('CONTOSO\Domain Users')
            ControlPrincipals = @()
        }

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates @($template)

        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsEsc1LikeTemplate').Count | Should -Be 0
    }

    It 'reports broad enrollment-agent templates and broad template-control delegation' {
        $templates = @(
            [pscustomobject]@{
                Name = 'EnrollmentAgent'
                DisplayName = 'Enrollment Agent'
                DistinguishedName = 'CN=EnrollmentAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
                SchemaVersion = 2
                EnrolleeSuppliesSubject = $false
                ManagerApprovalRequired = $false
                RequiredRaSignatures = 0
                ExportablePrivateKey = $false
                ExtendedKeyUsage = @('1.3.6.1.4.1.311.20.2.1')
                EnrollmentPrincipals = @('Authenticated Users')
                ControlPrincipals = @()
            },
            [pscustomobject]@{
                Name = 'Workstation'
                DisplayName = 'Workstation Authentication'
                DistinguishedName = 'CN=Workstation,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
                SchemaVersion = 2
                EnrolleeSuppliesSubject = $false
                ManagerApprovalRequired = $false
                RequiredRaSignatures = 0
                ExportablePrivateKey = $false
                ExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
                EnrollmentPrincipals = @('CONTOSO\Workstations')
                ControlPrincipals = @('Everyone')
            }
        )

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates $templates

        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsEnrollmentAgentBroadEnrollment').Count | Should -Be 1
        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsTemplateControlDelegation').Count | Should -Be 1
    }

    It 'reports exportable private keys on broadly enrollable authentication templates' {
        $template = [pscustomobject]@{
            Name = 'ExportableUser'
            DisplayName = 'Exportable User Auth'
            DistinguishedName = 'CN=ExportableUser,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            SchemaVersion = 2
            EnrolleeSuppliesSubject = $false
            ManagerApprovalRequired = $false
            RequiredRaSignatures = 0
            ExportablePrivateKey = $true
            ExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
            EnrollmentPrincipals = @('Domain Users')
            ControlPrincipals = @()
        }

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates @($template)

        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsExportableAuthPrivateKey').Count | Should -Be 1
    }

    It 'enriches template findings with publishing CAs' {
        $template = [pscustomobject]@{
            Name = 'UserAuth'
            DisplayName = 'User Authentication'
            DistinguishedName = 'CN=UserAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            SchemaVersion = 2
            EnrolleeSuppliesSubject = $true
            ManagerApprovalRequired = $false
            RequiredRaSignatures = 0
            ExportablePrivateKey = $false
            ExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
            EnrollmentPrincipals = @('Domain Users')
            AutoEnrollmentPrincipals = @()
            ControlPrincipals = @()
        }
        $ca = [pscustomobject]@{
            Name = 'CONTOSO-CA'
            DisplayName = 'CONTOSO-CA'
            DistinguishedName = 'CN=CONTOSO-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            CertificateTemplates = @('UserAuth')
            ControlPrincipals = @()
        }

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates @($template) -Cas @($ca)
        $finding = @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsEsc1LikeTemplate') | Select-Object -First 1

        $finding.PublishedCaNames[0] | Should -Be 'CONTOSO-CA'
        $finding.Tags -contains 'PublishedToCA' | Should -Be $true
    }

    It 'reports Any Purpose and no-EKU templates with broad enrollment and no issuance gate' {
        $templates = @(
            [pscustomobject]@{
                Name = 'AnyPurpose'
                DisplayName = 'Any Purpose User'
                DistinguishedName = 'CN=AnyPurpose,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
                SchemaVersion = 2
                EnrolleeSuppliesSubject = $false
                ManagerApprovalRequired = $false
                RequiredRaSignatures = 0
                ExportablePrivateKey = $false
                ExtendedKeyUsage = @('2.5.29.37.0')
                EnrollmentPrincipals = @('Authenticated Users')
                AutoEnrollmentPrincipals = @()
                ControlPrincipals = @()
            },
            [pscustomobject]@{
                Name = 'NoEkuTemplate'
                DisplayName = 'No EKU Template'
                DistinguishedName = 'CN=NoEkuTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
                SchemaVersion = 2
                EnrolleeSuppliesSubject = $false
                ManagerApprovalRequired = $false
                RequiredRaSignatures = 0
                ExportablePrivateKey = $false
                ExtendedKeyUsage = @()
                EnrollmentPrincipals = @('Domain Users')
                AutoEnrollmentPrincipals = @()
                ControlPrincipals = @()
            }
        )

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates $templates

        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsAnyPurposeBroadEnrollment').Count | Should -Be 1
        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsNoEkuBroadEnrollment').Count | Should -Be 1
    }

    It 'reports broad control over Enrollment Services CA and NTAuth objects' {
        $ca = [pscustomobject]@{
            Name = 'CONTOSO-CA'
            DisplayName = 'CONTOSO-CA'
            DistinguishedName = 'CN=CONTOSO-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            CertificateTemplates = @()
            ControlPrincipals = @('Everyone')
        }
        $ntAuth = [pscustomobject]@{
            Name = 'NTAuthCertificates'
            DisplayName = 'NTAuthCertificates'
            DistinguishedName = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            CertificateCount = 1
            ControlPrincipals = @('Authenticated Users')
        }

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates @() -Cas @($ca) -NtAuth $ntAuth

        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsCaObjectControlDelegation').Count | Should -Be 1
        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsNtAuthControlDelegation').Count | Should -Be 1
    }

    It 'reports ESC6 CA SAN configuration and chains it to published authentication templates' {
        $template = [pscustomobject]@{
            Name = 'UserAuth'
            DisplayName = 'User Authentication'
            DistinguishedName = 'CN=UserAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            SchemaVersion = 2
            EnrolleeSuppliesSubject = $false
            ManagerApprovalRequired = $false
            RequiredRaSignatures = 0
            ExportablePrivateKey = $false
            ExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
            EnrollmentPrincipals = @('Domain Users')
            AutoEnrollmentPrincipals = @()
            ControlPrincipals = @()
        }
        $ca = [pscustomobject]@{
            Name = 'CONTOSO-CA'
            DisplayName = 'CONTOSO-CA'
            DistinguishedName = 'CN=CONTOSO-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            CertificateTemplates = @('UserAuth')
            ControlPrincipals = @()
            AcceptsRequestSubjectAltName = $true
            Configuration = [pscustomobject]@{ EditFlags = 0x00040000; Source = 'Synthetic'; AcceptsRequestSubjectAltName = $true }
        }

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates @($template) -Cas @($ca)
        $configFinding = @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsCaAcceptsRequestSan') | Select-Object -First 1
        $chainFinding = @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsEsc6RequestSanChain') | Select-Object -First 1

        $configFinding.EscTechnique | Should -Be 'ESC6'
        $chainFinding.EscTechnique | Should -Be 'ESC6'
        $chainFinding.CaName | Should -Be 'CONTOSO-CA'
        @($chainFinding.AttackPath).Count | Should -BeGreaterThan 2
    }

    It 'normalizes CA configuration fields without relying on ACL semantics' {
        $ca = ConvertTo-ADPostureAdcsCaObject -InputObject ([pscustomobject]@{
            Name = 'CONTOSO-CA'
            DisplayName = 'CONTOSO-CA'
            DistinguishedName = 'CN=CONTOSO-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            dNSHostName = 'ca01.contoso.local'
            certificateTemplates = @('UserAuth')
            Configuration = [pscustomobject]@{
                Source = 'Synthetic'
                EditFlags = 0x00040000
                AcceptsRequestSubjectAltName = $true
                RequestDisposition = 3
            }
        })

        $ca.AcceptsRequestSubjectAltName | Should -Be $true
        $ca.ConfigurationSource | Should -Be 'Synthetic'
        $ca.RequestDisposition | Should -Be 3
    }

    It 'keeps ADCS semantic checks out of the generic ACL posture module' {
        $aclSource = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'src\Private\ConvertTo-ADAclRiskModel.ps1')

        $aclSource | Should -Not -Match 'ESC[0-9]'
        $aclSource | Should -Not -Match 'CertificateTemplate'
        $aclSource | Should -Not -Match 'NTAuth'
    }

    It 'reports malicious template permissions with broad enroll, autoenroll, control, and supplied subject' {
        $template = [pscustomobject]@{
            Name = 'Malicious-Template'
            DisplayName = 'Malicious-Template'
            DistinguishedName = 'CN=Malicious-Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local'
            SchemaVersion = 2
            EnrolleeSuppliesSubject = $true
            ManagerApprovalRequired = $false
            RequiredRaSignatures = 0
            ExportablePrivateKey = $false
            ExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
            EnrollmentPrincipals = @('Authenticated Users', 'CONTOSO\Domain Users')
            AutoEnrollmentPrincipals = @('CONTOSO\Domain Users')
            ControlPrincipals = @('CONTOSO\Domain Users')
        }

        $model = ConvertTo-ADPostureAdcsRiskModel -Domain 'contoso.local' -Templates @($template)

        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsEsc1LikeTemplate').Count | Should -Be 2
        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsBroadAuthenticationEnrollment').Count | Should -Be 2
        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsBroadAuthenticationAutoEnrollment').Count | Should -Be 1
        @($model.AdcsFindings | Where-Object FindingType -eq 'AdcsTemplateControlDelegation').Count | Should -Be 1
        @($model.AdcsFindings | Where-Object { $_.Principal -eq 'CONTOSO\Domain Users' -and $_.FindingType -eq 'AdcsTemplateControlDelegation' }).Count | Should -Be 1
    }

    It 'extracts enroll, autoenroll, and control principals from template access rules' {
        $rules = @(
            [pscustomobject]@{
                IdentityReference = 'Authenticated Users'
                AccessControlType = 'Allow'
                ActiveDirectoryRights = 'ExtendedRight'
                ObjectType = '{0e10c968-78fb-11d2-90d4-00c04f79dc55}'
            },
            [pscustomobject]@{
                IdentityReference = 'WSG\Domain Users'
                AccessControlType = 'Allow'
                ActiveDirectoryRights = 'ExtendedRight'
                ObjectType = '{a05b8cc2-17bc-4802-a710-e7c15ab866a2}'
            },
            [pscustomobject]@{
                IdentityReference = 'WSG\Domain Users'
                AccessControlType = 'Allow'
                ActiveDirectoryRights = 'GenericAll'
                ObjectType = '00000000-0000-0000-0000-000000000000'
            }
        )

        $access = ConvertFrom-ADPostureAdcsTemplateAccessRules -AccessRules $rules

        $access.EnrollmentPrincipals -contains 'Authenticated Users' | Should -Be $true
        $access.AutoEnrollmentPrincipals -contains 'WSG\Domain Users' | Should -Be $true
        $access.ControlPrincipals -contains 'WSG\Domain Users' | Should -Be $true
    }
}
