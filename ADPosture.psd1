@{
    RootModule        = 'ADPosture.psm1'
    ModuleVersion     = '1.3.0'
    GUID              = 'a7f3c2e1-9b4d-4a6f-8e2c-1d5b7a9e0f3c'
    Author            = 'AD Posture'
    CompanyName       = 'Local'
    Copyright         = '(c) 2026 AD Posture. PolyForm Noncommercial License 1.0.0.'
    Description       = 'Local Active Directory posture and privilege audit module with Tier 0/1/2 classification (2012 R2-2025).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-ADPostureAudit'
        'Export-ADPostureReport'
        'Compare-ADPostureSnapshots'
        'New-ADPostureRemediationScript'
        'New-ADPostureRemediationPlaybook'
        'Invoke-ADPostureArtifactRetention'
        'Open-ADPostureDashboard'
        'Get-ADSensitiveGroupCatalog'
        'New-ADPostureTimelineHistory'
        'Sync-ADPostureDashboardData'
    )
    RequiredModules   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @(
                'ActiveDirectory',
                'ADSecurity',
                'IdentitySecurity',
                'Cybersecurity',
                'BlueTeam',
                'PowerShell',
                'Audit',
                'SecurityAssessment',
                'PostureManagement',
                'PrivilegeAudit',
                'Tier0',
                'Tiering',
                'Kerberos',
                'ADCS',
                'GPO',
                'ACL',
                'DNS',
                'Trusts',
                'MITREATTACK',
                'Pester'
            )
            LicenseUri   = 'https://polyformproject.org/licenses/noncommercial/1.0.0/'
            ProjectUri   = 'https://github.com/wgerade/AD-Posture'
            ReleaseNotes = 'See CHANGELOG.md'
        }
    }
}