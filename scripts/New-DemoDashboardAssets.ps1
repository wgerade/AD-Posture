[CmdletBinding()]
param(
    [string]$EdgePath = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    [int]$ScreenshotWidth = 1680,
    [int]$ScreenshotHeight = 1100,
    [int]$GifWidth = 1200,
    [int]$GifHeight = 760
)

$ErrorActionPreference = 'Stop'

Write-Host 'Demo asset generation only. Microsoft Edge is used only for headless documentation screenshots; normal audits and dashboard usage do not require Edge or Chrome.'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$dashboardRoot = Join-Path $repoRoot 'dashboard'
$assetRoot = Join-Path $repoRoot 'docs\assets'
$tempRoot = Join-Path $repoRoot '.tmp-demo-assets'
$demoTimestamp = (Get-Date).ToString('o')

. (Join-Path $repoRoot 'src\Private\ConvertTo-ADAclRiskModel.ps1')
. (Join-Path $repoRoot 'src\Private\ConvertTo-ADObjectRiskModel.ps1')

New-Item -ItemType Directory -Path $assetRoot -Force | Out-Null
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

if (-not (Test-Path -LiteralPath $EdgePath)) {
    $edgeCommand = Get-Command msedge.exe -ErrorAction SilentlyContinue
    if ($edgeCommand) {
        $EdgePath = $edgeCommand.Source
    }
    else {
        throw "Microsoft Edge was not found. This is required only for demo screenshot generation. Provide -EdgePath with the msedge.exe location, or skip this script for normal audit/dashboard operation."
    }
}

function New-DemoFinding {
    param(
        [string]$Group,
        [string]$Tier,
        [string]$GroupTier,
        [int]$Weight,
        [string]$Member,
        [string]$Display,
        [string]$Type,
        [double]$Score,
        [string]$Difficulty,
        [string]$Chain,
        [string]$Uac,
        [string]$Action,
        [string]$Risk,
        [string]$Technique,
        [bool]$Stale = $false,
        [bool]$Disabled = $false,
        [int]$Depth = 0
    )

    [ordered]@{
        Timestamp = $demoTimestamp
        Domain = 'corp.example'
        SensitiveGroup = $Group
        GroupTier = $GroupTier
        PrivilegeTier = $Tier
        PrivilegeTierReason = $Group
        GroupRiskWeight = $Weight
        MemberSam = $Member
        MemberDisplay = $Display
        MemberDn = "CN=$Display,OU=Demo Identities,DC=corp,DC=example"
        ObjectSid = "S-1-5-21-1000000000-2000000000-3000000000-$([Math]::Abs($Member.GetHashCode()))"
        AccountType = $Type
        IsDirect = ($Depth -eq 0)
        NestingDepth = $Depth
        MembershipChain = $Chain
        AccountStatus = $(if ($Disabled) { 'Disabled' } else { 'Active' })
        IsEnabled = -not $Disabled
        IsDisabled = $Disabled
        IsStale = $Stale
        DaysSinceLogon = $(if ($Stale) { 245 } else { 7 })
        LastLogonTimestamp = $(if ($Stale) { '2025-09-20T10:30:00-05:00' } else { '2026-05-16T11:30:00-05:00' })
        LastLogonUsDate = $(if ($Stale) { '09/20/2025' } else { '05/16/2026' })
        LastLogonDays = $(if ($Stale) { 245 } else { 7 })
        LastLogonDisplay = $(if ($Stale) { '09/20/2025 (245 days)' } else { '05/16/2026 (7 days)' })
        PasswordLastSet = '2025-04-18T08:15:00-05:00'
        PasswordLastSetUsDate = '04/18/2025'
        PasswordLastSetDays = 400
        PasswordLastSetDisplay = '04/18/2025 (400 days)'
        PasswordNeverExpires = ($Uac -like '*Password Never Expires*')
        WhenCreated = '2024-01-15T08:00:00-05:00'
        WhenCreatedUsDate = '01/15/2024'
        WhenCreatedDays = 859
        WhenCreatedDisplay = '01/15/2024 (859 days)'
        UserAccountControl = 512
        UserAccountControlCategory = 'Normal Account'
        UserAccountControlSummary = $Uac
        UserAccountControlNotes = ($Uac -replace '^Normal Account,?\s*', '')
        UacRiskBonus = $(if ($Uac -like '*Weak Kerberos*' -or $Uac -like '*Unconstrained*') { 1.5 } elseif ($Uac -like '*Password Never Expires*') { 0.8 } else { 0 })
        UacRemediationDifficulty = $(if ($Uac -like '*Unconstrained*') { 'High' } else { 'Medium' })
        UacPrivilegedConcernCount = $(if ($Uac -eq 'Normal Account') { 0 } else { 1 })
        UacActiveFlagNames = $(if ($Uac -like '*Weak Kerberos*') { 'USE_DES_KEY_ONLY' } elseif ($Uac -like '*Unconstrained*') { 'TRUSTED_FOR_DELEGATION' } else { '' })
        IsDomainController = $false
        IsExcluded = $false
        ExclusionReason = $null
        RiskScore = $Score
        RemediationDifficulty = $Difficulty
        CleanupActions = $Action
        SuggestedRemediation = $Action
        WhyThisMatters = $Risk
        TechnicalRisk = $Risk
        AttackTechniques = @(
            [ordered]@{
                Id = $Technique.Split(' ')[0]
                Name = ($Technique -replace '^[^ ]+\s*-\s*', '')
                Tactic = 'Privilege Escalation'
            }
        )
        ScoreModel = 'Demo cumulative exposure model'
        ScoreFormula = "Base $Weight + identity/UAC/nesting factors = $Score"
        ScoreComponents = [ordered]@{
            Base = $Weight
            AccountMultiplier = $(if ($Type -like 'Service*') { 1.2 } else { 1.0 })
            NestingBonus = $Depth
            UacBonus = $(if ($Uac -eq 'Normal Account') { 0 } else { 1 })
            Final = $Score
        }
        Notes = $Risk
    }
}

$findings = @(
    New-DemoFinding -Group 'Domain Admins' -Tier 'Tier 0' -GroupTier 'Domain' -Weight 5 -Member 'adm.breakglass01' -Display 'Admin Breakglass 01' -Type 'User (AdminCount)' -Score 8.4 -Difficulty 'High' -Depth 0 -Chain 'Domain Admins -> Admin Breakglass 01' -Uac 'Normal Account, Password Never Expires' -Action 'Replace standing membership with PIM/JIT approval; rotate break-glass password under vault control' -Risk 'Standing Tier 0 membership can become full domain compromise if the account is abused.' -Technique 'T1098 - Account Manipulation'
    New-DemoFinding -Group 'Domain Admins' -Tier 'Tier 0' -GroupTier 'Domain' -Weight 5 -Member 'svc.backup.archive' -Display 'Archive Backup Service' -Type 'ServiceAccount' -Score 9.8 -Difficulty 'High' -Depth 1 -Chain 'Domain Admins -> Backup Operators -> Archive Backup Service' -Uac 'Normal Account, Weak Kerberos (DES)' -Action 'Remove nested privilege path; redesign service access with least privilege and explicit ownership' -Risk 'A service account with weak Kerberos settings and Tier 0 reach increases credential theft impact.' -Technique 'T1558 - Steal or Forge Kerberos Tickets'
    New-DemoFinding -Group 'Administrators' -Tier 'Tier 0' -GroupTier 'Builtin' -Weight 5 -Member 'grp.workstation-admins' -Display 'Workstation Admins' -Type 'Group' -Score 6.6 -Difficulty 'Medium' -Depth 1 -Chain 'Administrators -> Workstation Admins -> Helpdesk Tier 2' -Uac 'N/A' -Action 'Replace broad nested group with tier-scoped administration groups' -Risk 'Nested groups make privileged access harder to govern and review.' -Technique 'T1078 - Valid Accounts'
    New-DemoFinding -Group 'Group Policy Creator Owners' -Tier 'Tier 0' -GroupTier 'Domain' -Weight 4 -Member 'jane.admin' -Display 'Jane Admin' -Type 'User (AdminCount)' -Score 5.9 -Difficulty 'Medium' -Depth 0 -Chain 'Group Policy Creator Owners -> Jane Admin' -Uac 'Normal Account, Cannot Be Delegated' -Action 'Move GPO creation through controlled change workflow' -Risk 'GPO creation rights can influence privileged computers and users.' -Technique 'T1484 - Domain Policy Modification'
    New-DemoFinding -Group 'Backup Operators' -Tier 'Tier 1' -GroupTier 'Domain' -Weight 4 -Member 'svc.file.backup' -Display 'File Backup gMSA' -Type 'ServiceAccount (gMSA)' -Score 4.2 -Difficulty 'Medium' -Depth 0 -Chain 'Backup Operators -> File Backup gMSA' -Uac 'Normal Account' -Action 'Validate backup scope and remove interactive logon where possible' -Risk 'Backup privileges may expose sensitive data and enable restore abuse.' -Technique 'T1006 - Direct Volume Access'
    New-DemoFinding -Group 'Remote Desktop Users' -Tier 'Tier 2' -GroupTier 'Builtin' -Weight 2 -Member 'contractor.ops' -Display 'Contractor Ops' -Type 'User' -Score 2.1 -Difficulty 'Low' -Depth 0 -Chain 'Remote Desktop Users -> Contractor Ops' -Uac 'Normal Account' -Action 'Validate business need and set expiration on access' -Risk 'Remote access should be time-bound and tied to an accountable owner.' -Technique 'T1021 - Remote Services' -Stale $true
    New-DemoFinding -Group 'Server Operators' -Tier 'Tier 1' -GroupTier 'Domain' -Weight 4 -Member 'old.ops.admin' -Display 'Old Ops Admin' -Type 'User' -Score 1.8 -Difficulty 'Low' -Depth 0 -Chain 'Server Operators -> Old Ops Admin' -Uac 'Normal Account' -Action 'Disable or remove stale privileged account after owner validation' -Risk 'Stale privileged identities often survive process changes and remain attack paths.' -Technique 'T1078 - Valid Accounts' -Stale $true -Disabled $true
)

$exceptions = @(
    [ordered]@{
        ApprovedExceptionStatus = 'Active'
        SensitiveGroup = 'Domain Admins'
        MemberSam = 'adm.breakglass02'
        MemberDisplay = 'Admin Breakglass 02'
        RiskScore = 7.4
        ApprovedExceptionOwner = 'Identity Operations'
        ApprovedExceptionApprovedBy = 'CISO'
        ApprovedExceptionTicket = 'CHG-2026-0042'
        ApprovedExceptionExpiresAt = '2026-12-31'
        ApprovedExceptionReason = 'Break-glass account with vault control and quarterly validation.'
    }
    [ordered]@{
        ApprovedExceptionStatus = 'Expired'
        SensitiveGroup = 'Backup Operators'
        MemberSam = 'svc.archive.backup'
        MemberDisplay = 'Archive Backup Service'
        RiskScore = 3.6
        ApprovedExceptionOwner = 'Infrastructure'
        ApprovedExceptionApprovedBy = 'Security Architecture'
        ApprovedExceptionTicket = 'CHG-2025-1199'
        ApprovedExceptionExpiresAt = '2026-04-30'
        ApprovedExceptionReason = 'Legacy backup migration window elapsed.'
    }
)

$monitoring = @(
    [ordered]@{
        ExclusionReason = 'Native AD architecture'
        SensitiveGroup = 'Domain Controllers'
        MemberSam = 'DC01$'
        MemberDisplay = 'DC01'
        NativeIdentityCategory = 'Domain controller computer'
        NativeIdentityReason = 'Domain controller membership is expected and monitored separately.'
        ObjectSid = 'S-1-5-21-demo-domain-516'
        AccountType = 'Computer (DomainController)'
        RiskScore = 0
    }
    [ordered]@{
        ExclusionReason = 'Well-known authority principal'
        SensitiveGroup = 'Denied RODC Password Replication Group'
        MemberSam = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
        MemberDisplay = 'Enterprise Domain Controllers'
        NativeIdentityCategory = 'Native AD authority'
        NativeIdentityReason = 'Well-known AD authority principal managed by platform architecture.'
        ObjectSid = 'S-1-5-9'
        AccountType = 'WellKnownSecurityPrincipal'
        RiskScore = 0
    }
)

$groups = @($findings |
    Group-Object { $_['SensitiveGroup'] } |
    ForEach-Object {
        $first = $_.Group[0]
        $scores = @($_.Group | ForEach-Object { [double]$_['RiskScore'] })
        $scoreSum = ($scores | Measure-Object -Sum).Sum
        $scoreAvg = ($scores | Measure-Object -Average).Average
        [ordered]@{
            SensitiveGroup = $_.Name
            Tier = $first['GroupTier']
            PrivilegeTier = $first['PrivilegeTier']
            MemberCount = $_.Count
            ExcludedCount = 0
            AverageRiskScore = [Math]::Round($scoreAvg, 2)
            AggregateRiskScore = [Math]::Round($scoreSum, 2)
            RiskWeight = $first['GroupRiskWeight']
        }
    })

$overallScore = [Math]::Round((($findings | ForEach-Object { [double]$_['RiskScore'] } | Measure-Object -Sum).Sum), 2)
$tierBreakdown = @{}
$findings | Group-Object { $_['PrivilegeTier'] } | ForEach-Object { $tierBreakdown[$_.Name] = $_.Count }
$remediation = @{}
$findings | Group-Object { $_['RemediationDifficulty'] } | ForEach-Object { $remediation[$_.Name] = $_.Count }

$aclModel = ConvertTo-ADAclRiskModel -Domain 'corp.example' -AccessRules @(
    [pscustomobject]@{
        TargetName = 'AdminSDHolder'
        TargetDistinguishedName = 'CN=AdminSDHolder,CN=System,DC=corp,DC=example'
        TargetObjectClass = 'container'
        TrusteeName = 'Delegated Admins'
        TrusteeObjectClass = 'group'
        ActiveDirectoryRights = 'WriteDacl'
        AccessControlType = 'Allow'
        ObjectType = '00000000-0000-0000-0000-000000000000'
        IsInherited = $false
    }
    [pscustomobject]@{
        TargetName = 'corp.example'
        TargetDistinguishedName = 'DC=corp,DC=example'
        TargetObjectClass = 'domainDNS'
        TrusteeName = 'Sync Operators'
        TrusteeObjectClass = 'group'
        ActiveDirectoryRights = 'ExtendedRight'
        AccessControlType = 'Allow'
        ObjectType = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        IsInherited = $false
    }
    [pscustomobject]@{
        TargetName = 'AXZ'
        TargetDistinguishedName = 'CN=AXZ,CN=Users,DC=corp,DC=example'
        TargetObjectClass = 'user'
        OwnerName = 'CORP\HelpdeskUser'
        OwnerObjectClass = 'user'
        ActiveDirectoryRights = 'Owner'
        AccessControlType = 'Owner'
    }
    [pscustomobject]@{
        TargetName = 'Workstation-042'
        TargetDistinguishedName = 'CN=Workstation-042,OU=Workstations,DC=corp,DC=example'
        TargetObjectClass = 'computer'
        TrusteeName = 'LAPS Readers'
        TrusteeObjectClass = 'group'
        ActiveDirectoryRights = 'ReadProperty'
        AccessControlType = 'Allow'
        ObjectType = 'f3531ec6-6330-4f8e-8d39-7a671fbac605'
        ObjectTypeName = 'ms-LAPS-Encrypted-Password-Attributes'
        IsInherited = $false
    }
    [pscustomobject]@{
        TargetName = 'Domain Admins'
        TargetDistinguishedName = 'CN=Domain Admins,CN=Users,DC=corp,DC=example'
        TargetObjectClass = 'group'
        TrusteeName = 'Group Operators'
        TrusteeObjectClass = 'group'
        ActiveDirectoryRights = 'WriteProperty'
        AccessControlType = 'Allow'
        ObjectType = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        IsInherited = $false
    }
)
$objectModel = ConvertTo-ADObjectRiskModel -Findings @($findings) -AclFindings @($aclModel.AclFindings) -Domain 'corp.example'

$demoGpoDn = 'CN={DEMO-GPO-0001},CN=Policies,CN=System,DC=corp,DC=example'
$demoGpos = @(
    [ordered]@{
        DisplayName = 'Tier 0 Workstation Control Policy'
        Name = '{DEMO-GPO-0001}'
        Guid = 'DEMO-GPO-0001'
        DistinguishedName = $demoGpoDn
        FileSysPath = '\\corp.example\SYSVOL\corp.example\Policies\{DEMO-GPO-0001}'
        Status = 'Enabled'
        WmiFilter = 'corp.example;{DEMO-WMI-0001};Privileged Workstations'
        HasScripts = $true
    }
)
$demoGpoLinks = @(
    [ordered]@{
        GpoDistinguishedName = $demoGpoDn
        LinkOptions = 0
        IsLinkDisabled = $false
        IsEnforced = $false
        ScopeName = 'Domain Controllers'
        ScopeDistinguishedName = 'OU=Domain Controllers,DC=corp,DC=example'
        ScopeObjectClass = 'organizationalUnit'
    }
)
$demoGpoFindings = @(
    [ordered]@{
        GpoFindingId = 'gpo-demo-000001'
        Domain = 'corp.example'
        FindingType = 'GpoDelegationControl'
        Severity = 'Critical'
        RiskScore = 11.88
        GpoName = 'Tier 0 Workstation Control Policy'
        GpoGuid = 'DEMO-GPO-0001'
        GpoDistinguishedName = $demoGpoDn
        GpoStatus = 'Enabled'
        GpoFileSysPath = '\\corp.example\SYSVOL\corp.example\Policies\{DEMO-GPO-0001}'
        GpoWmiFilter = 'corp.example;{DEMO-WMI-0001};Privileged Workstations'
        ScopeName = 'Domain Controllers'
        ScopeDistinguishedName = 'OU=Domain Controllers,DC=corp,DC=example'
        ScopeObjectClass = 'organizationalUnit'
        ScopeTier = 'Tier 0'
        ScopeRiskContext = 'Domain Controllers policy scope'
        ScopeRiskMultiplier = 1.65
        TrusteeName = 'Everyone'
        DelegatedRight = 'GenericAll'
        Reason = "Trustee 'Everyone' has GenericAll over a GPO linked to Domain Controllers, allowing broad policy control over Tier 0 systems."
        Remediation = 'Remove broad GPO delegation and restrict policy editing to an approved GPO administration group.'
        ScoreFormula = 'GPO delegation score = 7.2 * scope 1.65 * trustee 1.2'
        Tags = @('GpoDelegation', 'GpoControlPath', 'BroadTrustee', 'DomainControllerScope', 'Tier0Scope')
    }
    [ordered]@{
        GpoFindingId = 'gpo-demo-000002'
        Domain = 'corp.example'
        FindingType = 'GpoPreferenceCredential'
        Severity = 'Critical'
        RiskScore = 14.85
        GpoName = 'Tier 0 Workstation Control Policy'
        GpoGuid = 'DEMO-GPO-0001'
        GpoDistinguishedName = $demoGpoDn
        GpoStatus = 'Enabled'
        GpoFileSysPath = '\\corp.example\SYSVOL\corp.example\Policies\{DEMO-GPO-0001}'
        ScopeName = 'Domain Controllers'
        ScopeDistinguishedName = 'OU=Domain Controllers,DC=corp,DC=example'
        ScopeObjectClass = 'organizationalUnit'
        ScopeTier = 'Tier 0'
        ScopeRiskContext = 'Domain Controllers policy scope'
        ScopeRiskMultiplier = 1.65
        DelegatedRight = 'Properties'
        FileSystemPath = '\\corp.example\SYSVOL\corp.example\Policies\{DEMO-GPO-0001}\Machine\Preferences\Groups\Groups.xml'
        Reason = 'Group Policy Preference XML contains credential material or a cpassword-like field, exposing reusable credentials from SYSVOL to readers of the policy.'
        Remediation = 'Remove stored credentials from GPP items, rotate exposed passwords, and replace with a managed secret process.'
        ScoreFormula = 'GPO preference score = 9 * scope 1.65'
        Tags = @('GpoPreference', 'CredentialExposure', 'DomainControllerScope', 'Tier0Scope')
    }
    [ordered]@{
        GpoFindingId = 'gpo-demo-000003'
        Domain = 'corp.example'
        FindingType = 'GpoWmiFilterDependency'
        Severity = 'High'
        RiskScore = 9.24
        GpoName = 'Tier 0 Workstation Control Policy'
        GpoGuid = 'DEMO-GPO-0001'
        GpoDistinguishedName = $demoGpoDn
        GpoStatus = 'Enabled'
        GpoFileSysPath = '\\corp.example\SYSVOL\corp.example\Policies\{DEMO-GPO-0001}'
        GpoWmiFilter = 'corp.example;{DEMO-WMI-0001};Privileged Workstations'
        ScopeName = 'Domain Controllers'
        ScopeDistinguishedName = 'OU=Domain Controllers,DC=corp,DC=example'
        ScopeObjectClass = 'organizationalUnit'
        ScopeTier = 'Tier 0'
        ScopeRiskContext = 'Domain Controllers policy scope'
        ScopeRiskMultiplier = 1.65
        DelegatedRight = 'WmiFilter'
        Reason = 'Critical GPO depends on a WMI filter; if the filter is broken, too narrow, or changed, policy may not apply to the intended Tier 0 systems.'
        Remediation = 'Validate WMI filter query health, ownership, change control, and expected target count.'
        ScoreFormula = 'GPO WMI filter dependency score = 5.6 * scope 1.65'
        Tags = @('GpoWmiFilter', 'ManualReviewRequired', 'DomainControllerScope', 'Tier0Scope')
    }
)

$demoKerberosAuthPrincipals = @(
    [ordered]@{
        Domain = 'corp.example'
        Principal = 'svc.backup.archive'
        PrincipalSam = 'svc.backup.archive'
        PrincipalClass = 'user'
        PrincipalDn = 'CN=Archive Backup Service,OU=Service Accounts,DC=corp,DC=example'
        PrincipalSid = 'S-1-5-21-1000000000-2000000000-3000000000-4101'
        AccountType = 'ServiceAccount'
        PrivilegeTier = 'Tier 0'
        ServicePrincipalNames = @('MSSQLSvc/backup01.corp.example:1433', 'HOST/backup01.corp.example')
        DelegationType = 'Unconstrained'
        EncryptionSummary = 'DES enabled; AES not confirmed'
    }
    [ordered]@{
        Domain = 'corp.example'
        Principal = 'web.portal'
        PrincipalSam = 'web.portal'
        PrincipalClass = 'user'
        PrincipalDn = 'CN=Portal Web Service,OU=Service Accounts,DC=corp,DC=example'
        PrincipalSid = 'S-1-5-21-1000000000-2000000000-3000000000-4102'
        AccountType = 'ServiceAccount'
        PrivilegeTier = 'Tier 1'
        ServicePrincipalNames = @('HTTP/portal-web.corp.example')
        DelegationType = 'Constrained'
        EncryptionSummary = 'RC4 allowed; AES keys missing'
    }
)
$demoKerberosAuthFindings = @(
    [ordered]@{
        KerberosAuthFindingId = 'auth-demo-000001'
        Domain = 'corp.example'
        FindingType = 'KerberosRoastableServiceAccount'
        RiskPattern = 'Kerberoastable privileged service account'
        Severity = 'Critical'
        RiskScore = 9.4
        Principal = 'svc.backup.archive'
        PrincipalSam = 'svc.backup.archive'
        PrincipalClass = 'user'
        PrincipalDn = 'CN=Archive Backup Service,OU=Service Accounts,DC=corp,DC=example'
        PrincipalSid = 'S-1-5-21-1000000000-2000000000-3000000000-4101'
        PrivilegeTier = 'Tier 0'
        AccountType = 'ServiceAccount'
        DelegationType = 'Unconstrained'
        ServicePrincipalNames = @('MSSQLSvc/backup01.corp.example:1433', 'HOST/backup01.corp.example')
        DelegationTargets = @('Any service')
        EncryptionTypes = @('DES', 'RC4')
        EncryptionSummary = 'DES/RC4 exposure with privileged reach'
        Reason = 'Privileged service account has SPNs and weak Kerberos settings, making offline password attack impact high.'
        Remediation = 'Rotate the service account secret, remove weak encryption, and replace standing privileged membership with least-privilege delegation.'
        ScoreFormula = 'Kerberos score = privileged service account + roastable SPN + weak crypto + delegation'
        Tags = @('Kerberoast', 'WeakEncryption', 'Delegation', 'Tier0')
        AttackTechniques = @([ordered]@{ Id = 'T1558.003'; Name = 'Kerberoasting' })
        ScoreComponents = @(
            [ordered]@{ Name = 'Privilege tier'; Value = 'Tier 0'; Reason = 'Account reaches a sensitive group path.' }
            [ordered]@{ Name = 'SPN'; Value = 'Present'; Reason = 'SPNs enable Kerberos service ticket requests.' }
            [ordered]@{ Name = 'Crypto'; Value = 'Weak'; Reason = 'DES/RC4 increase cracking feasibility.' }
        )
    }
    [ordered]@{
        KerberosAuthFindingId = 'auth-demo-000002'
        Domain = 'corp.example'
        FindingType = 'KerberosDelegationRisk'
        RiskPattern = 'Delegation account with broad target path'
        Severity = 'High'
        RiskScore = 7.6
        Principal = 'web.portal'
        PrincipalSam = 'web.portal'
        PrincipalClass = 'user'
        PrincipalDn = 'CN=Portal Web Service,OU=Service Accounts,DC=corp,DC=example'
        PrincipalSid = 'S-1-5-21-1000000000-2000000000-3000000000-4102'
        PrivilegeTier = 'Tier 1'
        AccountType = 'ServiceAccount'
        DelegationType = 'Constrained'
        ServicePrincipalNames = @('HTTP/portal-web.corp.example')
        DelegationTargets = @('CIFS/files01.corp.example', 'HOST/app01.corp.example')
        EncryptionTypes = @('RC4', 'AES128')
        EncryptionSummary = 'RC4 still allowed'
        Reason = 'Delegation target list includes infrastructure services and should be reviewed for current business need.'
        Remediation = 'Constrain delegation to current service dependencies and remove RC4 support after key rollover.'
        ScoreFormula = 'Kerberos score = delegation + service exposure + weak crypto'
        Tags = @('Delegation', 'WeakEncryption')
        AttackTechniques = @([ordered]@{ Id = 'T1550.003'; Name = 'Pass the Ticket' })
        ScoreComponents = @(
            [ordered]@{ Name = 'Delegation'; Value = 'Constrained'; Reason = 'Delegation can extend token reach.' }
            [ordered]@{ Name = 'Crypto'; Value = 'RC4'; Reason = 'Legacy crypto remains enabled.' }
        )
    }
)

$demoAdcsTemplates = @(
    [ordered]@{
        TemplateName = 'Corp User Smartcard'
        TemplateShortName = 'CorpUserSmartcard'
        TemplateDistinguishedName = 'CN=CorpUserSmartcard,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example'
        PublishedCaNames = @('CORP-CA01')
        EnrolleeSuppliesSubject = $true
        ManagerApprovalRequired = $false
        RequiredRaSignatures = 0
        ExportablePrivateKey = $false
    }
)
$demoAdcsCas = @(
    [ordered]@{
        CaName = 'CORP-CA01'
        DistinguishedName = 'CN=CORP-CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example'
        DnsHostName = 'ca01.corp.example'
    }
)
$demoAdcsFindings = @(
    [ordered]@{
        AdcsFindingId = 'adcs-demo-000001'
        Domain = 'corp.example'
        FindingType = 'AdcsEsc1LikeTemplate'
        RiskPattern = 'ESC1-like'
        EscTechnique = 'ESC1'
        Severity = 'Critical'
        RiskScore = 9.2
        TemplateName = 'Corp User Smartcard'
        TemplateShortName = 'CorpUserSmartcard'
        TemplateDistinguishedName = 'CN=CorpUserSmartcard,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example'
        PublishedCaNames = @('CORP-CA01')
        Principal = 'Domain Users'
        EnrolleeSuppliesSubject = $true
        ManagerApprovalRequired = $false
        RequiredRaSignatures = 0
        ExportablePrivateKey = $false
        ExtendedKeyUsage = @('Client Authentication', 'Smart Card Logon')
        Reason = 'Template permits enrollee-supplied subject without approval, enabling identity impersonation if enrollment scope is broad.'
        Remediation = 'Require approval or remove enrollee-supplied subject, then restrict enrollment to a governed security group.'
        Tags = @('ESC1', 'Enrollment', 'IdentityImpersonation')
        AttackPath = @('Request certificate with alternate subject', 'Authenticate as targeted principal', 'Escalate access through mapped identity')
        ScoreComponents = @(
            [ordered]@{ Name = 'Subject supply'; Value = 'Enabled'; Weight = 3 }
            [ordered]@{ Name = 'Approval'; Value = 'Not required'; Weight = 3 }
            [ordered]@{ Name = 'Enrollment'; Value = 'Broad'; Weight = 3 }
        )
    }
    [ordered]@{
        AdcsFindingId = 'adcs-demo-000002'
        Domain = 'corp.example'
        FindingType = 'AdcsTemplateControlDelegation'
        RiskPattern = 'Template control delegation'
        Severity = 'High'
        RiskScore = 7.1
        TemplateName = 'Corp User Smartcard'
        TemplateShortName = 'CorpUserSmartcard'
        TemplateDistinguishedName = 'CN=CorpUserSmartcard,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example'
        PublishedCaNames = @('CORP-CA01')
        Principal = 'PKI Operators'
        TargetObjectName = 'Corp User Smartcard'
        DelegatedRight = 'WriteDacl'
        Reason = 'Delegated template control can alter issuance settings and turn a normal template into an escalation path.'
        Remediation = 'Restrict template control to dedicated PKI administrators and review change history.'
        Tags = @('ADCSControl', 'Delegation')
    }
)

$demoTrusts = @(
    [ordered]@{
        TrustName = 'partner.corp.example'
        TrustPartner = 'partner.corp.example'
        TrustDirection = 'Bidirectional'
        TrustType = 'External'
        TrustAttributes = 0
        SIDFilteringEnabled = $false
        SelectiveAuthentication = $false
        IsTransitive = $true
        ForestTransitive = $false
        TGTDelegation = $false
        DistinguishedName = 'CN=partner.corp.example,CN=System,DC=corp,DC=example'
        WhenChanged = $demoTimestamp
    }
)
$demoTrustFindings = @(
    [ordered]@{
        TrustFindingId = 'trust-demo-000001'
        Domain = 'corp.example'
        FindingType = 'TrustSidFilteringDisabled'
        RiskPattern = 'External trust without SID filtering'
        Severity = 'Critical'
        RiskScore = 8.8
        TrustName = 'partner.corp.example'
        TrustPartner = 'partner.corp.example'
        TrustDirection = 'Bidirectional'
        TrustType = 'External'
        TrustAttributes = 0
        SIDFilteringEnabled = $false
        SelectiveAuthentication = $false
        IsTransitive = $true
        ForestTransitive = $false
        TGTDelegation = $false
        DistinguishedName = 'CN=partner.corp.example,CN=System,DC=corp,DC=example'
        Reason = 'SID filtering is disabled on an external trust, increasing the risk of cross-boundary SID history abuse.'
        Remediation = 'Validate trust requirement, enable SID filtering, and document any exception with owner and expiry.'
        ScoreFormula = 'Trust score = external trust + SID filtering disabled + bidirectional path'
        Tags = @('TrustBoundary', 'SidFiltering', 'CrossForest')
        AttackTechniques = @([ordered]@{ Id = 'T1134.005'; Name = 'SID-History Injection' })
        ScoreComponents = @(
            [ordered]@{ Name = 'SID filtering'; Value = 'Disabled'; Reason = 'Boundary control is not active.' }
            [ordered]@{ Name = 'Direction'; Value = 'Bidirectional'; Reason = 'Trust path exists in both directions.' }
        )
    }
    [ordered]@{
        TrustFindingId = 'trust-demo-000002'
        Domain = 'corp.example'
        FindingType = 'TrustSelectiveAuthenticationDisabled'
        RiskPattern = 'Broad authentication across trust'
        Severity = 'High'
        RiskScore = 6.7
        TrustName = 'partner.corp.example'
        TrustPartner = 'partner.corp.example'
        TrustDirection = 'Bidirectional'
        TrustType = 'External'
        TrustAttributes = 0
        SIDFilteringEnabled = $false
        SelectiveAuthentication = $false
        IsTransitive = $true
        ForestTransitive = $false
        TGTDelegation = $false
        DistinguishedName = 'CN=partner.corp.example,CN=System,DC=corp,DC=example'
        Reason = 'Selective authentication is not enabled, so trusted principals may authenticate broadly unless constrained elsewhere.'
        Remediation = 'Enable selective authentication or document compensating controls and scoped access paths.'
        ScoreFormula = 'Trust score = external trust + broad authentication'
        Tags = @('TrustBoundary', 'SelectiveAuthentication')
    }
)

$demoDnsZones = @(
    [ordered]@{
        ZoneName = 'corp.example'
        DynamicUpdate = 'NonsecureAndSecure'
        AgingEnabled = $false
        DistinguishedName = 'DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example'
    }
)
$demoDnsRecords = @(
    [ordered]@{
        ZoneName = 'corp.example'
        RecordName = '*'
        RecordType = 'A'
        RecordData = '10.10.20.50'
        DistinguishedName = 'DC=*,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example'
    }
    [ordered]@{
        ZoneName = 'corp.example'
        RecordName = 'old-vpn'
        RecordType = 'CNAME'
        RecordData = 'retired-gateway.corp.example'
        DistinguishedName = 'DC=old-vpn,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example'
    }
)
$demoDnsFindings = @(
    [ordered]@{
        DnsFindingId = 'dns-demo-000001'
        Domain = 'corp.example'
        FindingType = 'DnsZoneInsecureDynamicUpdate'
        RiskPattern = 'Zone accepts nonsecure dynamic update'
        Severity = 'Critical'
        RiskScore = 8.1
        ZoneName = 'corp.example'
        RecordName = '@'
        RecordType = 'Zone'
        RecordData = 'NonsecureAndSecure'
        ParsedRecordType = 'Zone'
        ParsedRecordData = 'DynamicUpdate=NonsecureAndSecure'
        RecordParseStatus = 'Parsed'
        Principal = 'Authenticated Users'
        DistinguishedName = 'DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example'
        Reason = 'Zone allows nonsecure dynamic updates, which can permit unauthorized DNS record changes.'
        Remediation = 'Change dynamic updates to Secure only and review stale records before enforcement.'
        ScoreFormula = 'DNS score = insecure update + domain-integrated zone'
        Tags = @('DnsControl', 'DynamicUpdate')
    }
    [ordered]@{
        DnsFindingId = 'dns-demo-000002'
        Domain = 'corp.example'
        FindingType = 'DnsWildcardRecord'
        RiskPattern = 'Wildcard record in internal zone'
        Severity = 'High'
        RiskScore = 6.2
        ZoneName = 'corp.example'
        RecordName = '*'
        RecordType = 'A'
        RecordData = '10.10.20.50'
        ParsedRecordType = 'A'
        ParsedRecordData = '10.10.20.50'
        RecordParseStatus = 'Parsed'
        Principal = 'DNS Admins'
        DistinguishedName = 'DC=*,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example'
        Reason = 'Wildcard records can hide mistyped hostnames and redirect unexpected internal traffic.'
        Remediation = 'Validate business owner and remove wildcard records that are not explicitly approved.'
        ScoreFormula = 'DNS score = wildcard record + internal zone'
        Tags = @('DnsHygiene', 'Wildcard')
    }
)

$payload = [ordered]@{
    findings = $findings
    aclFindings = @($aclModel.AclFindings)
    gpos = $demoGpos
    gpoLinks = $demoGpoLinks
    gpoFindings = $demoGpoFindings
    kerberosAuthFindings = $demoKerberosAuthFindings
    kerberosAuthPrincipals = $demoKerberosAuthPrincipals
    adcsFindings = $demoAdcsFindings
    adcsTemplates = $demoAdcsTemplates
    adcsCas = $demoAdcsCas
    trusts = $demoTrusts
    trustFindings = $demoTrustFindings
    dnsZones = $demoDnsZones
    dnsRecords = $demoDnsRecords
    dnsFindings = $demoDnsFindings
    groups = $groups
    exceptions = $exceptions
    monitoring = $monitoring
    objects = @($objectModel.Objects)
    objectEvidence = @($objectModel.ObjectEvidence)
    objectRelationships = @($objectModel.ObjectRelationships)
    meta = [ordered]@{
        sensitivity = 'Synthetic demo data only. Safe for public screenshots.'
        domain = 'corp.example'
        forest = 'corp.example'
        timestamp = $demoTimestamp
        overallRiskScore = $overallScore
        targetScore = 0
        actionableCount = $findings.Count
        approvedExceptionCount = 1
        expiredExceptionCount = 1
        tierBreakdown = $tierBreakdown
        remediation = $remediation
        readiness = [ordered]@{
            Score = 68
            Controls = @(
                [ordered]@{ Name = 'Tier 0 standing access'; Status = 'Fail'; Count = 4; Target = 0; Detail = 'Reduce permanent Tier 0 memberships and route access through approval.' }
                [ordered]@{ Name = 'Service account privilege'; Status = 'Review'; Count = 2; Target = 0; Detail = 'Reduce standing service account privilege and require approved ownership.' }
                [ordered]@{ Name = 'Native identity handling'; Status = 'Pass'; Count = 2; Target = 0; Detail = 'Native AD principals are separated from normal remediation.' }
                [ordered]@{ Name = 'Approved exceptions'; Status = 'Review'; Count = 1; Target = 0; Detail = 'One exception needs renewal or removal.' }
            )
        }
    }
}

$timeline = [ordered]@{
    ScoreBefore = 42.6
    ScoreAfter = $overallScore
    ScoreDelta = [Math]::Round($overallScore - 42.6, 2)
    AddedCount = 2
    RemovedCount = 3
    ChangedCount = 2
    History = @(
        [ordered]@{ timestamp = '2026-03-01T09:00:00-05:00'; score = 58.4; actionable = 15 }
        [ordered]@{ timestamp = '2026-04-01T09:00:00-05:00'; score = 47.2; actionable = 12 }
        [ordered]@{ timestamp = '2026-05-01T09:00:00-05:00'; score = 42.6; actionable = 10 }
        [ordered]@{ timestamp = $demoTimestamp; score = $overallScore; actionable = $findings.Count }
    )
    Added = @($findings[1], $findings[3])
    Removed = @(
        New-DemoFinding -Group 'Domain Admins' -Tier 'Tier 0' -GroupTier 'Domain' -Weight 5 -Member 'retired.domain.admin' -Display 'Retired Domain Admin' -Type 'User' -Score 7.2 -Difficulty 'High' -Chain 'Domain Admins -> Retired Domain Admin' -Uac 'Normal Account, Password Never Expires' -Action 'Removed standing admin membership' -Risk 'Removed stale Tier 0 membership.' -Technique 'T1078 - Valid Accounts'
        New-DemoFinding -Group 'Backup Operators' -Tier 'Tier 1' -GroupTier 'Domain' -Weight 4 -Member 'old.backup.svc' -Display 'Old Backup Service' -Type 'ServiceAccount' -Score 4.1 -Difficulty 'Medium' -Chain 'Backup Operators -> Old Backup Service' -Uac 'Normal Account' -Action 'Removed old backup service account' -Risk 'Removed old privileged service account.' -Technique 'T1006 - Direct Volume Access'
    )
    Changed = @(
        [ordered]@{ Before = '9.80'; After = '4.20'; Finding = $findings[4] }
        [ordered]@{ Before = '6.60'; After = '2.10'; Finding = $findings[5] }
    )
}

$json = $payload | ConvertTo-Json -Depth 20
Set-Content -LiteralPath (Join-Path $dashboardRoot 'dashboard-data.js') -Value "/* Synthetic demo data generated by New-DemoDashboardAssets.ps1 */`nwindow.__AD_AUDIT_DATA__ = $json;" -Encoding UTF8
Set-Content -LiteralPath (Join-Path $dashboardRoot 'latest-dashboard.json') -Value $json -Encoding UTF8

$timelineJson = $timeline | ConvertTo-Json -Depth 20
Set-Content -LiteralPath (Join-Path $dashboardRoot 'timeline-data.js') -Value "/* Synthetic demo timeline generated by New-DemoDashboardAssets.ps1 */`nwindow.__AD_TIMELINE_DATA__ = $timelineJson;" -Encoding UTF8
Set-Content -LiteralPath (Join-Path $dashboardRoot 'timeline-comparison.json') -Value $timelineJson -Encoding UTF8

function ConvertTo-FileUrl {
    param([string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    return ([System.Uri]::new($full)).AbsoluteUri
}

function Invoke-EdgeScreenshot {
    param(
        [string]$Page,
        [string]$SourcePath,
        [string]$OutFile,
        [int]$Width,
        [int]$Height
    )

    $source = if ($SourcePath) { $SourcePath } else { Join-Path $dashboardRoot $Page }
    $url = ConvertTo-FileUrl -Path $source
    $profileName = if ($Page) { [System.IO.Path]::GetFileNameWithoutExtension($Page) } else { [System.IO.Path]::GetFileNameWithoutExtension($SourcePath) }
    $profile = Join-Path $tempRoot ('edge-' + $profileName)
    New-Item -ItemType Directory -Path $profile -Force | Out-Null
    Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue

    $args = @(
        '--headless=new',
        '--disable-gpu',
        '--hide-scrollbars',
        '--no-first-run',
        "--user-data-dir=$profile",
        "--window-size=$Width,$Height",
        "--screenshot=$OutFile",
        $url
    )

    $stderrPath = Join-Path $tempRoot ('edge-stderr-' + [guid]::NewGuid().ToString('N') + '.log')
    & $EdgePath @args 2> $stderrPath
    $edgeError = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "Edge screenshot failed for $source with exit code $LASTEXITCODE.`n$edgeError"
    }

    $deadline = (Get-Date).AddSeconds(15)
    while ((-not (Test-Path -LiteralPath $OutFile)) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }

    if (-not (Test-Path -LiteralPath $OutFile)) {
        throw "Screenshot was not created: $OutFile`n$edgeError"
    }

    Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
}

function ConvertTo-HtmlText {
    param([string]$Value)
    return [System.Net.WebUtility]::HtmlEncode($Value)
}

function New-TerminalDemoHtml {
    param(
        [string]$Title,
        [string[]]$Lines,
        [string]$OutFile
    )

    $body = ($Lines | ForEach-Object {
            $class = if ($_ -match '^(PS>|>)') { 'prompt' } elseif ($_ -match '^(\\[OK\\]|Audit export complete|Dashboard opened|Dry run complete)') { 'ok' } elseif ($_ -match '^(WARNING|Review)') { 'warn' } else { 'line' }
            "<div class=`"$class`">$(ConvertTo-HtmlText $_)</div>"
        }) -join "`n"

    $html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>$((ConvertTo-HtmlText $Title))</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; background: #07101f; font-family: Consolas, "Cascadia Mono", monospace; color: #d9e7ff; }
  .wrap { padding: 42px; }
  .terminal { border: 1px solid #2c4365; border-radius: 18px; background: linear-gradient(180deg, #111c31, #091224); box-shadow: 0 24px 70px rgba(0,0,0,.45); overflow: hidden; }
  .bar { height: 42px; background: #17243b; border-bottom: 1px solid #2c4365; display: flex; align-items: center; gap: 8px; padding: 0 16px; }
  .dot { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
  .red { background: #ff5f57; } .yellow { background: #ffbd2e; } .green { background: #28c840; }
  .title { margin-left: 12px; color: #9fb6d8; font: 600 13px "Segoe UI", sans-serif; letter-spacing: .02em; }
  .screen { padding: 26px 30px 32px; font-size: 22px; line-height: 1.55; min-height: 510px; }
  .prompt { color: #8be9fd; font-weight: 700; }
  .ok { color: #59f0b7; }
  .warn { color: #ffd166; }
  .line { color: #d9e7ff; }
</style>
</head>
<body>
<div class="wrap">
  <div class="terminal">
    <div class="bar"><span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span><span class="title">$((ConvertTo-HtmlText $Title))</span></div>
    <div class="screen">$body</div>
  </div>
</div>
</body>
</html>
"@

    Set-Content -LiteralPath $OutFile -Value $html -Encoding UTF8
}

$screenshots = @(
    @{ Page = 'index.html'; File = 'operations-dashboard.png' },
    @{ Page = 'objects.html'; File = 'objects-dashboard.png' },
    @{ Page = 'auth.html'; File = 'auth-dashboard.png' },
    @{ Page = 'acl.html'; File = 'acl-dashboard.png' },
    @{ Page = 'gpo.html'; File = 'gpo-dashboard.png' },
    @{ Page = 'adcs.html'; File = 'adcs-dashboard.png' },
    @{ Page = 'trusts.html'; File = 'trust-dashboard.png' },
    @{ Page = 'dns.html'; File = 'dns-dashboard.png' },
    @{ Page = 'exceptions.html'; File = 'exceptions-dashboard.png' },
    @{ Page = 'timeline.html'; File = 'timeline-dashboard.png' },
    @{ Page = 'executive.html'; File = 'executive-dashboard.png' }
)

foreach ($shot in $screenshots) {
    Invoke-EdgeScreenshot -Page $shot.Page -OutFile (Join-Path $assetRoot $shot.File) -Width $ScreenshotWidth -Height $ScreenshotHeight
}

$gifFrames = @(
    @{ Page = 'index.html'; File = 'demo-01-operations.png' },
    @{ Page = 'objects.html'; File = 'demo-02-objects.png' },
    @{ Page = 'auth.html'; File = 'demo-03-auth.png' },
    @{ Page = 'acl.html'; File = 'demo-04-acl.png' },
    @{ Page = 'gpo.html'; File = 'demo-05-gpo.png' },
    @{ Page = 'adcs.html'; File = 'demo-06-adcs.png' },
    @{ Page = 'trusts.html'; File = 'demo-07-trust.png' },
    @{ Page = 'dns.html'; File = 'demo-08-dns.png' },
    @{ Page = 'exceptions.html'; File = 'demo-09-exceptions.png' },
    @{ Page = 'timeline.html'; File = 'demo-10-timeline.png' },
    @{ Page = 'executive.html'; File = 'demo-11-executive.png' }
)

foreach ($frame in $gifFrames) {
    Invoke-EdgeScreenshot -Page $frame.Page -OutFile (Join-Path $tempRoot $frame.File) -Width $GifWidth -Height $GifHeight
}

Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$encoder = [System.Windows.Media.Imaging.GifBitmapEncoder]::new()
foreach ($frame in $gifFrames) {
    $stream = [System.IO.File]::OpenRead((Join-Path $tempRoot $frame.File))
    try {
        $bitmap = [System.Windows.Media.Imaging.BitmapFrame]::Create(
            $stream,
            [System.Windows.Media.Imaging.BitmapCreateOptions]::PreservePixelFormat,
            [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        )
        $encoder.Frames.Add($bitmap)
    }
    finally {
        $stream.Dispose()
    }
}

$gifPath = Join-Path $assetRoot 'demo.gif'
$gifStream = [System.IO.File]::Create($gifPath)
try {
    $encoder.Save($gifStream)
}
finally {
    $gifStream.Dispose()
}

$terminalShots = @(
    @{
        Title = 'PowerShell - Import module'
        File = 'powershell-import.png'
        Lines = @(
            'PS> Import-Module .\ADPosture.psd1 -Force',
            'PS> Get-Command -Module ADPosture',
            '',
            'CommandType     Name',
            '-----------     ----',
            'Function        Invoke-ADPostureAudit',
            'Function        Open-ADPostureDashboard',
            'Function        Invoke-ADPostureArtifactRetention',
            '[OK] Public v1 commands loaded from local module.'
        )
    },
    @{
        Title = 'PowerShell - Focused audit first'
        File = 'powershell-focused-audit.png'
        Lines = @(
            'PS> Invoke-ADPostureAudit -IncludeOptionalGroups -IncludeKerberosAuthPosture -IncludeTrustPosture -IncludeDnsPosture -LogPath .\reports\audit.log',
            'Collecting sensitive group membership...',
            'Collecting Kerberos/Auth posture...',
            'Collecting Trust posture...',
            'Collecting DNS posture...',
            'Audit export complete: .\reports\audit-20260607-1015',
            '[OK] Focused read-only posture completed with synthetic demo data.'
        )
    },
    @{
        Title = 'PowerShell - Planned broad audit'
        File = 'powershell-planned-full.png'
        Lines = @(
            'PS> Invoke-ADPostureAudit -IncludeAclPosture -IncludeAclAllObjects -IncludeGpoPosture -IncludeGpoSysvolAcl -IncludeAdcsPosture -AclReadDelayMilliseconds 100 -LogPath .\reports\audit-full.log',
            'WARNING: Broad ACL collection is planned. Validate maintenance window and management host capacity.',
            'ACL target discovery: staged and paced.',
            'GPO/SYSVOL posture: read-only metadata and policy file review.',
            'ADCS posture: read-only Configuration naming context metadata.',
            '[OK] Broad audit command uses pacing and explicit collector selection.'
        )
    },
    @{
        Title = 'PowerShell - Open static dashboard'
        File = 'powershell-open-dashboard.png'
        Lines = @(
            'PS> Open-ADPostureDashboard',
            'Dashboard opened: dashboard\index.html',
            'PS> Open-ADPostureDashboard -View ObjectRisk',
            'Dashboard opened: dashboard\objects.html',
            'PS> Open-ADPostureDashboard -View Executive',
            'Dashboard opened: dashboard\executive.html',
            '[OK] No localhost service or backend process started.'
        )
    },
    @{
        Title = 'PowerShell - Retention dry run'
        File = 'powershell-retention-dry-run.png'
        Lines = @(
            'PS> Invoke-ADPostureArtifactRetention -RootPath . -RetentionDays 180',
            'Review: reports\audit-20251101-0900-findings.csv would be expired.',
            'Review: data\snapshot-20251101.json would be expired.',
            'Dry run complete. No files were removed.',
            '[OK] Destructive cleanup requires -Remove and explicit approval.'
        )
    }
)

foreach ($shot in $terminalShots) {
    $htmlPath = Join-Path $tempRoot ([System.IO.Path]::ChangeExtension($shot.File, '.html'))
    New-TerminalDemoHtml -Title $shot.Title -Lines $shot.Lines -OutFile $htmlPath
    Invoke-EdgeScreenshot -SourcePath $htmlPath -OutFile (Join-Path $assetRoot $shot.File) -Width 1320 -Height 760
}

Get-Item -LiteralPath (Join-Path $assetRoot '*') |
    Where-Object { $_.Name -in @(
            'operations-dashboard.png',
            'objects-dashboard.png',
            'auth-dashboard.png',
            'acl-dashboard.png',
            'gpo-dashboard.png',
            'adcs-dashboard.png',
            'trust-dashboard.png',
            'dns-dashboard.png',
            'exceptions-dashboard.png',
            'timeline-dashboard.png',
            'executive-dashboard.png',
            'powershell-import.png',
            'powershell-focused-audit.png',
            'powershell-planned-full.png',
            'powershell-open-dashboard.png',
            'powershell-retention-dry-run.png',
            'demo.gif'
        ) } |
    Select-Object Name, Length, LastWriteTime

