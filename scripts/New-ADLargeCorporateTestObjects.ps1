#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a large Active Directory lab corpus with mixed users, groups, computers, service accounts, gMSA/sMSA-style accounts, GPOs, and risky identity scenarios.
.DESCRIPTION
    This script provisions real AD objects for lab/testing purposes. It creates an isolated OU tree under TargetPath and populates it with a large-company style mix of identities and relationships.

    By default, privileged memberships are assigned to lab-created groups only. To add generated accounts to real privileged groups such as Domain Admins, use -AllowBuiltInPrivilegedGroupMembership explicitly.
    Use -CreateAllRiskScenarios to enable the broad risk corpus: gMSA, weak PSO, modern/legacy LAPS read ACLs, DCSync rights, AdminSDHolder ACLs, RBCD, shadow-credential markers, ADCS ACL exposure, GPO delegation, orphaned SID ACLs, and sensitive object ACLs.
    OU accidental deletion protection is optional with -ProtectOUsFromAccidentalDeletion because some delegated lab accounts can create OUs but cannot write the protection ACL.
    If AD returns RID pool exhaustion, the script stops with DC/RID diagnostics because users, groups, computers, and gMSA all require new RIDs.
    Use -Server to force Active Directory cmdlets to use a specific healthy DC.
    Use -Force to run without per-object confirmation prompts.

    The script supports -WhatIf. Use it before creating objects in any environment.
.EXAMPLE
    $pwd = Read-Host 'Default lab password' -AsSecureString
    .\scripts\New-ADLargeCorporateTestObjects.ps1 -TargetPath 'DC=corp,DC=example' -DefaultPassword $pwd -WhatIf
.EXAMPLE
    $pwd = Read-Host 'Default lab password' -AsSecureString
    .\scripts\New-ADLargeCorporateTestObjects.ps1 -TargetPath 'DC=corp,DC=example' -DefaultPassword $pwd -UserCount 5000 -ServiceAccountCount 500 -ComputerCount 1500
.EXAMPLE
    $pwd = Read-Host 'Default lab password' -AsSecureString
    .\scripts\New-ADLargeCorporateTestObjects.ps1 -TargetPath 'DC=corp,DC=example' -DefaultPassword $pwd -CreateAllRiskScenarios -Force
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string]$TargetPath,

    [string]$LabName = 'ADPosture-LargeCorp-Lab',

    [string]$Prefix = 'ADPosture',

    [string]$Server,

    [ValidateRange(10, 200000)]
    [int]$UserCount = 5000,

    [ValidateRange(0, 50000)]
    [int]$ServiceAccountCount = 500,

    [ValidateRange(0, 20000)]
    [int]$GmsaCount = 100,

    [ValidateRange(0, 50000)]
    [int]$ComputerCount = 1500,

    [ValidateRange(10, 20000)]
    [int]$GroupCount = 400,

    [ValidateRange(0, 500)]
    [int]$GpoCount = 30,

    [Parameter(Mandatory)]
    [securestring]$DefaultPassword,

    [int]$Seed = 424242,

    [switch]$Force,

    [switch]$ProtectOUsFromAccidentalDeletion,

    [switch]$ContinueOnPrincipalCreateFailure,

    [switch]$AllowBuiltInPrivilegedGroupMembership,

    [switch]$CreateAllRiskScenarios,

    [switch]$CreateGpos,

    [switch]$CreateGmsaObjects,

    [switch]$CreatePsoScenarios,

    [switch]$CreateLapsScenarios,

    [switch]$CreateDcsyncScenario,

    [switch]$CreateAdminSdHolderScenario,

    [switch]$CreateRbcdScenario,

    [switch]$CreateShadowCredentialScenario,

    [switch]$CreateAdcsAclScenario,

    [switch]$CreateOrphanedSidAclScenario
)

$ErrorActionPreference = 'Stop'

$effectiveCreateGpos = $CreateGpos -or $CreateAllRiskScenarios
$effectiveCreateGmsaObjects = $CreateGmsaObjects -or $CreateAllRiskScenarios
$effectiveCreatePsoScenarios = $CreatePsoScenarios -or $CreateAllRiskScenarios
$effectiveCreateLapsScenarios = $CreateLapsScenarios -or $CreateAllRiskScenarios
$effectiveCreateDcsyncScenario = $CreateDcsyncScenario -or $CreateAllRiskScenarios
$effectiveCreateAdminSdHolderScenario = $CreateAdminSdHolderScenario -or $CreateAllRiskScenarios
$effectiveCreateRbcdScenario = $CreateRbcdScenario -or $CreateAllRiskScenarios
$effectiveCreateShadowCredentialScenario = $CreateShadowCredentialScenario -or $CreateAllRiskScenarios
$effectiveCreateAdcsAclScenario = $CreateAdcsAclScenario -or $CreateAllRiskScenarios
$effectiveCreateOrphanedSidAclScenario = $CreateOrphanedSidAclScenario -or $CreateAllRiskScenarios

if ($Force) {
    $ConfirmPreference = 'None'
}

Import-Module ActiveDirectory -ErrorAction Stop
if ($Server) {
    $PSDefaultParameterValues['*-AD*:Server'] = $Server
}
if ($effectiveCreateGpos) {
    Import-Module GroupPolicy -ErrorAction Stop
}

$random = [System.Random]::new($Seed)
$created = [System.Collections.Generic.List[object]]::new()
$skipped = [System.Collections.Generic.List[object]]::new()
$updated = [System.Collections.Generic.List[object]]::new()
$domain = Get-ADDomain
$rootDse = Get-ADRootDSE
$domainDnsRoot = $domain.DNSRoot
$domainDn = $domain.DistinguishedName
$schemaDn = $rootDse.schemaNamingContext
$configurationDn = $rootDse.configurationNamingContext

$targetContainer = Get-ADObject -Identity $TargetPath -ErrorAction SilentlyContinue
if (-not $targetContainer) {
    throw "TargetPath '$TargetPath' was not found in the current AD context. Use the real domain DN, for example '$domainDn', or an existing OU/container DN."
}

foreach ($namingContext in @($domainDn, $configurationDn, $schemaDn)) {
    $contextObject = Get-ADObject -Identity $namingContext -ErrorAction SilentlyContinue
    if (-not $contextObject) {
        throw "Active Directory naming context '$namingContext' is not accessible from this session. Check DNS/DC selection, schema access, and the -Server parameter before running the lab provisioner."
    }
}

$labRootDn = "OU=$LabName,$TargetPath"
$ouMap = [ordered]@{
    Root = $labRootDn
    Tier0 = "OU=Tier0,$labRootDn"
    Tier1 = "OU=Tier1,$labRootDn"
    Tier2 = "OU=Tier2,$labRootDn"
    Users = "OU=Users,$labRootDn"
    ServiceAccounts = "OU=Service Accounts,$labRootDn"
    Computers = "OU=Computers,$labRootDn"
    Groups = "OU=Groups,$labRootDn"
    Gpos = "OU=GPO Scope,$labRootDn"
    Disabled = "OU=Disabled Objects,$labRootDn"
}

$departments = @('Identity Operations','Cybersecurity','Infrastructure','Finance','Legal','Human Resources','Sales','Manufacturing','Research','Cloud Platform','Data Engineering','Helpdesk','Endpoint Services','Network Operations')
$locations = @('Sao Paulo','Rio de Janeiro','Curitiba','Recife','Austin','Chicago','New York','London','Madrid','Lisbon','Toronto','Mexico City','Bogota','Buenos Aires')
$firstNames = @('Alex','Ana','Andre','Bianca','Bruno','Camila','Carla','Carlos','Daniel','Diego','Eduardo','Fernanda','Gabriel','Helena','Igor','Isabela','Joao','Julia','Laura','Leonardo','Lucas','Marina','Mateus','Natalia','Paula','Rafael','Renata','Rodrigo','Sofia','Thiago','Vanessa','Victor')
$lastNames = @('Almeida','Araujo','Barbosa','Cardoso','Costa','Fernandes','Gomes','Lima','Martins','Mendes','Moreira','Oliveira','Pereira','Ribeiro','Rocha','Santos','Silva','Souza','Teixeira','Vieira')

$labPrivilegedGroups = @(
    @{ Name = "$Prefix LAB Domain Admins"; Tier = 'Tier0'; Weight = 5 },
    @{ Name = "$Prefix LAB Enterprise Admins"; Tier = 'Tier0'; Weight = 5 },
    @{ Name = "$Prefix LAB Schema Admins"; Tier = 'Tier0'; Weight = 5 },
    @{ Name = "$Prefix LAB Account Operators"; Tier = 'Tier0'; Weight = 4 },
    @{ Name = "$Prefix LAB GPO Owners"; Tier = 'Tier0'; Weight = 4 },
    @{ Name = "$Prefix LAB DNS Admins"; Tier = 'Tier0'; Weight = 4 },
    @{ Name = "$Prefix LAB Backup Operators"; Tier = 'Tier1'; Weight = 4 },
    @{ Name = "$Prefix LAB Server Operators"; Tier = 'Tier1'; Weight = 4 },
    @{ Name = "$Prefix LAB Hyper-V Admins"; Tier = 'Tier1'; Weight = 3 },
    @{ Name = "$Prefix LAB Helpdesk Password Reset"; Tier = 'Tier2'; Weight = 2 },
    @{ Name = "$Prefix LAB Remote Desktop Users"; Tier = 'Tier2'; Weight = 2 }
)

$builtInPrivilegedGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Account Operators',
    'Group Policy Creator Owners',
    'DnsAdmins',
    'Backup Operators',
    'Server Operators',
    'Remote Desktop Users'
)

function Add-Result {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Type,
        [string]$Name,
        [string]$Action
    )

    $List.Add([pscustomobject]@{
        Type = $Type
        Name = $Name
        Action = $Action
    })
}

function Get-RandomItem {
    param([object[]]$Items)
    $Items[$random.Next(0, $Items.Count)]
}

function Test-IsRidPoolException {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $text = @(
        $ErrorRecord.Exception.Message
        $ErrorRecord.FullyQualifiedErrorId
        $ErrorRecord.CategoryInfo.Reason
    ) -join ' '

    $text -match '8209|exhausted the pool of relative identifiers|pool of relative identifiers|RID'
}

function Register-PrincipalCreateFailure {
    param(
        [string]$Type,
        [string]$Name,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    if (Test-IsRidPoolException -ErrorRecord $ErrorRecord) {
        $message = @(
            "AD refused to create '$Type' '$Name' because the current domain controller cannot allocate a new RID."
            'This is a domain/DC RID allocation problem, not a volume/tuning problem in this script.'
            'Fix or change the DC/RID Master path first, then rerun the script; existing objects will be skipped.'
            'Useful checks on a domain controller: dcdiag /test:ridmanager /v, netdom query fsmo, repadmin /replsummary.'
            "Original AD error: $($ErrorRecord.Exception.Message)"
        ) -join ' '

        if ($ContinueOnPrincipalCreateFailure) {
            Add-Result -List $skipped -Type $Type -Name $Name -Action $message
            Write-Warning $message
            return
        }

        throw $message
    }

    $genericMessage = "Failed to create '$Type' '$Name'. AD returned: $($ErrorRecord.Exception.Message)"
    if ($ContinueOnPrincipalCreateFailure) {
        Add-Result -List $skipped -Type $Type -Name $Name -Action $genericMessage
        Write-Warning $genericMessage
        return
    }

    throw $genericMessage
}

function Ensure-OrganizationalUnit {
    param(
        [string]$DistinguishedName,
        [string]$Name,
        [string]$Path
    )

    $existing = $null
    try {
        $existing = Get-ADOrganizationalUnit -Identity $DistinguishedName -ErrorAction Stop
    }
    catch {
        $existing = $null
    }
    if ($existing) {
        Add-Result -List $skipped -Type 'OU' -Name $DistinguishedName -Action 'Exists'
        if ($ProtectOUsFromAccidentalDeletion -and -not $existing.ProtectedFromAccidentalDeletion) {
            if ($PSCmdlet.ShouldProcess($DistinguishedName, 'Enable OU accidental deletion protection')) {
                try {
                    Set-ADOrganizationalUnit -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
                    Add-Result -List $updated -Type 'OU' -Name $DistinguishedName -Action 'ProtectedFromAccidentalDeletion enabled'
                }
                catch {
                    Add-Result -List $skipped -Type 'OU' -Name $DistinguishedName -Action "Protection not applied: $($_.Exception.Message)"
                }
            }
        }
        return
    }

    if ($PSCmdlet.ShouldProcess($DistinguishedName, 'Create OU')) {
        try {
            New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
            Add-Result -List $created -Type 'OU' -Name $DistinguishedName -Action 'Created'
        }
        catch {
            throw "Failed to create OU '$DistinguishedName'. Confirm that Path '$Path' exists and that the account can create OUs there. AD returned: $($_.Exception.Message)"
        }

        if ($ProtectOUsFromAccidentalDeletion) {
            try {
                Set-ADOrganizationalUnit -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
                Add-Result -List $updated -Type 'OU' -Name $DistinguishedName -Action 'ProtectedFromAccidentalDeletion enabled'
            }
            catch {
                Add-Result -List $skipped -Type 'OU' -Name $DistinguishedName -Action "Protection not applied: $($_.Exception.Message)"
            }
        }
    }
}

function Ensure-Group {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Description = 'ADPosture generated lab group'
    )

    $existing = Get-ADGroup -LDAPFilter "(sAMAccountName=$Name)" -ErrorAction SilentlyContinue
    if ($existing) {
        Add-Result -List $skipped -Type 'Group' -Name $Name -Action 'Exists'
        return $existing
    }

    if ($PSCmdlet.ShouldProcess($Name, 'Create AD group')) {
        try {
            New-ADGroup -Name $Name -SamAccountName $Name -GroupCategory Security -GroupScope Global -Path $Path -Description $Description -ErrorAction Stop
            Add-Result -List $created -Type 'Group' -Name $Name -Action 'Created'
        }
        catch {
            Register-PrincipalCreateFailure -Type 'Group' -Name $Name -ErrorRecord $_
            return $null
        }
    }

    Get-ADGroup -LDAPFilter "(sAMAccountName=$Name)" -ErrorAction SilentlyContinue
}

function Ensure-User {
    param(
        [string]$SamAccountName,
        [string]$DisplayName,
        [string]$Path,
        [string]$Department,
        [string]$Title,
        [string]$Description,
        [bool]$Enabled,
        [bool]$PasswordNeverExpires,
        [bool]$PasswordNotRequired,
        [bool]$DoesNotRequirePreAuth,
        [bool]$TrustedForDelegation,
        [bool]$TrustedToAuthForDelegation,
        [bool]$CannotBeDelegated,
        [bool]$UseDesKeyOnly,
        [string[]]$ServicePrincipalNames = @(),
        [string]$LogonWorkstations = ''
    )

    $existing = Get-ADUser -LDAPFilter "(sAMAccountName=$SamAccountName)" -Properties servicePrincipalName -ErrorAction SilentlyContinue
    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($SamAccountName, 'Create AD user')) {
            try {
                New-ADUser -Name $DisplayName `
                    -SamAccountName $SamAccountName `
                    -UserPrincipalName "$SamAccountName@$domainDnsRoot" `
                    -DisplayName $DisplayName `
                    -Path $Path `
                    -Department $Department `
                    -Title $Title `
                    -Description $Description `
                    -AccountPassword $DefaultPassword `
                    -Enabled $Enabled `
                    -PasswordNeverExpires $PasswordNeverExpires `
                    -PasswordNotRequired $PasswordNotRequired `
                    -ErrorAction Stop
                Add-Result -List $created -Type 'User' -Name $SamAccountName -Action 'Created'
            }
            catch {
                Register-PrincipalCreateFailure -Type 'User' -Name $SamAccountName -ErrorRecord $_
                return $null
            }
        }
        $existing = Get-ADUser -LDAPFilter "(sAMAccountName=$SamAccountName)" -Properties servicePrincipalName -ErrorAction SilentlyContinue
    }
    else {
        Add-Result -List $skipped -Type 'User' -Name $SamAccountName -Action 'Exists'
    }

    if ($existing -and ($ServicePrincipalNames.Count -gt 0 -or $LogonWorkstations)) {
        $replace = @{}
        if ($ServicePrincipalNames.Count -gt 0) { $replace['servicePrincipalName'] = $ServicePrincipalNames }
        if ($LogonWorkstations) { $replace['userWorkstations'] = $LogonWorkstations }
        if ($replace.Count -gt 0 -and $PSCmdlet.ShouldProcess($SamAccountName, 'Set user SPN/workstation restrictions')) {
            Set-ADUser -Identity $existing.DistinguishedName -Replace $replace -ErrorAction Stop
            Add-Result -List $updated -Type 'User' -Name $SamAccountName -Action 'Updated attributes'
        }
    }

    if ($existing -and ($DoesNotRequirePreAuth -or $TrustedForDelegation -or $TrustedToAuthForDelegation -or $CannotBeDelegated -or $UseDesKeyOnly)) {
        if ($PSCmdlet.ShouldProcess($SamAccountName, 'Set advanced account-control flags')) {
            if ($DoesNotRequirePreAuth) {
                Set-ADAccountControl -Identity $existing.DistinguishedName -DoesNotRequirePreAuth $true -ErrorAction Stop
                Add-Result -List $updated -Type 'User' -Name $SamAccountName -Action 'DoesNotRequirePreAuth enabled'
            }
            if ($TrustedForDelegation) {
                Set-ADAccountControl -Identity $existing.DistinguishedName -TrustedForDelegation $true -ErrorAction Stop
                Add-Result -List $updated -Type 'User' -Name $SamAccountName -Action 'TrustedForDelegation enabled'
            }
            if ($TrustedToAuthForDelegation) {
                Set-ADAccountControl -Identity $existing.DistinguishedName -TrustedToAuthForDelegation $true -ErrorAction Stop
                Add-Result -List $updated -Type 'User' -Name $SamAccountName -Action 'TrustedToAuthForDelegation enabled'
            }
            if ($CannotBeDelegated) {
                Set-ADAccountControl -Identity $existing.DistinguishedName -AccountNotDelegated $true -ErrorAction Stop
                Add-Result -List $updated -Type 'User' -Name $SamAccountName -Action 'AccountNotDelegated enabled'
            }
            if ($UseDesKeyOnly) {
                Set-ADAccountControl -Identity $existing.DistinguishedName -UseDESKeyOnly $true -ErrorAction Stop
                Add-Result -List $updated -Type 'User' -Name $SamAccountName -Action 'UseDESKeyOnly enabled'
            }
        }
    }

    $existing
}

function Ensure-Computer {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Description,
        [bool]$Enabled,
        [bool]$TrustedForDelegation
    )

    $sam = if ($Name.EndsWith('$')) { $Name } else { "$Name`$" }
    $existing = Get-ADComputer -LDAPFilter "(sAMAccountName=$sam)" -ErrorAction SilentlyContinue
    if ($existing) {
        Add-Result -List $skipped -Type 'Computer' -Name $sam -Action 'Exists'
        return $existing
    }

    if ($PSCmdlet.ShouldProcess($sam, 'Create AD computer')) {
        try {
            New-ADComputer -Name $Name -SamAccountName $sam -Path $Path -Description $Description -Enabled $Enabled -ErrorAction Stop
            if ($TrustedForDelegation) {
                Set-ADAccountControl -Identity $sam -TrustedForDelegation $true -ErrorAction Stop
            }
            Add-Result -List $created -Type 'Computer' -Name $sam -Action 'Created'
        }
        catch {
            Register-PrincipalCreateFailure -Type 'Computer' -Name $sam -ErrorRecord $_
            return $null
        }
    }

    Get-ADComputer -LDAPFilter "(sAMAccountName=$sam)" -ErrorAction SilentlyContinue
}

function Ensure-Gmsa {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Description
    )

    $existing = Get-ADServiceAccount -LDAPFilter "(sAMAccountName=$Name`$)" -ErrorAction SilentlyContinue
    if ($existing) {
        Add-Result -List $skipped -Type 'gMSA' -Name "$Name`$" -Action 'Exists'
        return $existing
    }

    if ($PSCmdlet.ShouldProcess("$Name`$", 'Create gMSA')) {
        try {
            New-ADServiceAccount -Name $Name -Path $Path -DNSHostName "$Name.$domainDnsRoot" -Description $Description -ErrorAction Stop
            Add-Result -List $created -Type 'gMSA' -Name "$Name`$" -Action 'Created'
        }
        catch {
            Register-PrincipalCreateFailure -Type 'gMSA' -Name "$Name`$" -ErrorRecord $_
            return $null
        }
    }

    Get-ADServiceAccount -LDAPFilter "(sAMAccountName=$Name`$)" -ErrorAction SilentlyContinue
}

function Ensure-FineGrainedPasswordPolicy {
    param(
        [string]$Name,
        [string]$SubjectDn,
        [int]$Precedence
    )

    $existing = Get-ADFineGrainedPasswordPolicy -Identity $Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($Name, 'Create fine-grained password policy')) {
            New-ADFineGrainedPasswordPolicy -Name $Name `
                -Precedence $Precedence `
                -ComplexityEnabled $false `
                -ReversibleEncryptionEnabled $true `
                -MinPasswordLength 4 `
                -PasswordHistoryCount 0 `
                -LockoutThreshold 0 `
                -MinPasswordAge (New-TimeSpan -Days 0) `
                -MaxPasswordAge (New-TimeSpan -Days 3650) `
                -Description 'ADPosture generated weak PSO test scenario' `
                -ErrorAction Stop
            Add-Result -List $created -Type 'PSO' -Name $Name -Action 'Created'
        }
        $existing = Get-ADFineGrainedPasswordPolicy -Identity $Name -ErrorAction SilentlyContinue
    }
    else {
        Add-Result -List $skipped -Type 'PSO' -Name $Name -Action 'Exists'
    }

    if ($existing -and $SubjectDn -and $PSCmdlet.ShouldProcess("$SubjectDn -> $Name", 'Apply fine-grained password policy')) {
        Add-ADFineGrainedPasswordPolicySubject -Identity $existing.Name -Subjects $SubjectDn -ErrorAction SilentlyContinue
        Add-Result -List $created -Type 'PSOAssignment' -Name "$SubjectDn -> $Name" -Action 'Created'
    }
}

function Add-MemberToGroupSafe {
    param(
        [string]$GroupName,
        [string]$MemberDn,
        [string]$Reason
    )

    if (-not $MemberDn) { return }
    $group = Get-ADGroup -LDAPFilter "(sAMAccountName=$GroupName)" -ErrorAction SilentlyContinue
    if (-not $group) {
        Add-Result -List $skipped -Type 'Membership' -Name "$MemberDn -> $GroupName" -Action 'Group not found'
        return
    }

    $alreadyMember = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive:$false -ErrorAction SilentlyContinue |
        Where-Object { $_.DistinguishedName -eq $MemberDn } |
        Select-Object -First 1

    if ($alreadyMember) {
        Add-Result -List $skipped -Type 'Membership' -Name "$MemberDn -> $GroupName" -Action 'Exists'
        return
    }

    if ($PSCmdlet.ShouldProcess("$MemberDn -> $GroupName", "Add AD group member ($Reason)")) {
        Add-ADGroupMember -Identity $group.DistinguishedName -Members $MemberDn -ErrorAction Stop
        Add-Result -List $created -Type 'Membership' -Name "$MemberDn -> $GroupName" -Action 'Created'
    }
}

function Set-LabObjectAcl {
    param(
        [string]$TargetDn,
        [string]$TrusteeSam,
        [string]$RightName,
        [Nullable[guid]]$ObjectTypeGuid = $null
    )

    $trustee = Get-ADGroup -LDAPFilter "(sAMAccountName=$TrusteeSam)" -ErrorAction SilentlyContinue
    if (-not $trustee) { return }

    if ($PSCmdlet.ShouldProcess($TargetDn, "Add lab ACL $RightName for $TrusteeSam")) {
        $adPath = "AD:\$TargetDn"
        $acl = Get-Acl -Path $adPath
        $sid = [System.Security.Principal.SecurityIdentifier]$trustee.SID
        $rights = [System.DirectoryServices.ActiveDirectoryRights]::$RightName
        $rule = if ($ObjectTypeGuid) {
            New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, 'Allow', $ObjectTypeGuid.Value)
        }
        else {
            New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, 'Allow')
        }
        $acl.AddAccessRule($rule)
        Set-Acl -Path $adPath -AclObject $acl
        Add-Result -List $created -Type 'ACL' -Name "$TrusteeSam $RightName $TargetDn" -Action 'Created'
    }
}

function Get-SchemaAttributeGuid {
    param([string]$LdapDisplayName)

    $attribute = Get-ADObject -SearchBase $schemaDn -LDAPFilter "(lDAPDisplayName=$LdapDisplayName)" -Properties schemaIDGUID -ErrorAction SilentlyContinue
    if (-not $attribute -or -not $attribute.schemaIDGUID) {
        Add-Result -List $skipped -Type 'SchemaAttribute' -Name $LdapDisplayName -Action 'Not found'
        return $null
    }

    [guid]::new([byte[]]$attribute.schemaIDGUID)
}

function Set-LapsReadScenario {
    param(
        [string]$TargetDn,
        [string]$TrusteeSam,
        [string[]]$AttributeNames
    )

    foreach ($attributeName in $AttributeNames) {
        $attributeGuid = Get-SchemaAttributeGuid -LdapDisplayName $attributeName
        if ($attributeGuid) {
            Set-LabObjectAcl -TargetDn $TargetDn -TrusteeSam $TrusteeSam -RightName 'ReadProperty' -ObjectTypeGuid $attributeGuid
        }
    }
}

function Set-ExtendedRightScenario {
    param(
        [string]$TargetDn,
        [string]$TrusteeSam,
        [guid[]]$RightGuids,
        [string]$ScenarioName
    )

    foreach ($rightGuid in $RightGuids) {
        Set-LabObjectAcl -TargetDn $TargetDn -TrusteeSam $TrusteeSam -RightName 'ExtendedRight' -ObjectTypeGuid $rightGuid
        Add-Result -List $created -Type $ScenarioName -Name "$TrusteeSam $rightGuid $TargetDn" -Action 'Configured'
    }
}

function Set-RbcdScenario {
    param(
        [Microsoft.ActiveDirectory.Management.ADComputer]$ActorComputer,
        [Microsoft.ActiveDirectory.Management.ADComputer]$TargetComputer
    )

    if (-not $ActorComputer -or -not $TargetComputer) { return }
    if ($PSCmdlet.ShouldProcess($TargetComputer.SamAccountName, "Allow RBCD from $($ActorComputer.SamAccountName)")) {
        Set-ADComputer -Identity $TargetComputer.DistinguishedName -PrincipalsAllowedToDelegateToAccount $ActorComputer -ErrorAction Stop
        Add-Result -List $created -Type 'RBCD' -Name "$($ActorComputer.SamAccountName) -> $($TargetComputer.SamAccountName)" -Action 'Configured'
    }
}

function Set-ShadowCredentialMarker {
    param([object]$TargetObject)

    if (-not $TargetObject) { return }
    $bytes = New-Object byte[] 32
    $random.NextBytes($bytes)
    $hex = -join ($bytes | ForEach-Object { $_.ToString('X2') })
    $value = "B:$($hex.Length):${hex}:$($TargetObject.DistinguishedName)"

    if ($PSCmdlet.ShouldProcess($TargetObject.DistinguishedName, 'Add msDS-KeyCredentialLink marker')) {
        try {
            Set-ADObject -Identity $TargetObject.DistinguishedName -Add @{ 'msDS-KeyCredentialLink' = $value } -ErrorAction Stop
            Add-Result -List $created -Type 'ShadowCredential' -Name $TargetObject.DistinguishedName -Action 'Marker added'
        }
        catch {
            Add-Result -List $skipped -Type 'ShadowCredential' -Name $TargetObject.DistinguishedName -Action $_.Exception.Message
        }
    }
}

function Set-AdcsAclScenario {
    param([string]$TrusteeSam)

    $templateContainerDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationDn"
    $container = Get-ADObject -Identity $templateContainerDn -ErrorAction SilentlyContinue
    if (-not $container) {
        Add-Result -List $skipped -Type 'ADCS' -Name $templateContainerDn -Action 'Certificate Templates container not found'
        return
    }

    Set-LabObjectAcl -TargetDn $templateContainerDn -TrusteeSam $TrusteeSam -RightName 'GenericAll'

    $templates = Get-ADObject -SearchBase $templateContainerDn -LDAPFilter '(objectClass=pKICertificateTemplate)' -SearchScope OneLevel -ErrorAction SilentlyContinue |
        Select-Object -First 5
    foreach ($template in $templates) {
        Set-LabObjectAcl -TargetDn $template.DistinguishedName -TrusteeSam $TrusteeSam -RightName 'WriteDacl'
    }
}

function Set-OrphanedSidAclScenario {
    param(
        [string]$TargetDn,
        [string]$RightName
    )

    $sidText = 'S-1-5-21-{0}-{1}-{2}-{3}' -f $random.Next(100000000, 999999999), $random.Next(100000000, 999999999), $random.Next(100000000, 999999999), $random.Next(1000, 9999)
    $sid = [System.Security.Principal.SecurityIdentifier]$sidText
    if ($PSCmdlet.ShouldProcess($TargetDn, "Add orphaned SID ACL $RightName")) {
        $adPath = "AD:\$TargetDn"
        $acl = Get-Acl -Path $adPath
        $rights = [System.DirectoryServices.ActiveDirectoryRights]::$RightName
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $adPath -AclObject $acl
        Add-Result -List $created -Type 'OrphanedSidACL' -Name "$sidText $RightName $TargetDn" -Action 'Created'
    }
}

Ensure-OrganizationalUnit -DistinguishedName $labRootDn -Name $LabName -Path $TargetPath
Ensure-OrganizationalUnit -DistinguishedName $ouMap.Tier0 -Name 'Tier0' -Path $labRootDn
Ensure-OrganizationalUnit -DistinguishedName $ouMap.Tier1 -Name 'Tier1' -Path $labRootDn
Ensure-OrganizationalUnit -DistinguishedName $ouMap.Tier2 -Name 'Tier2' -Path $labRootDn
Ensure-OrganizationalUnit -DistinguishedName $ouMap.Users -Name 'Users' -Path $labRootDn
Ensure-OrganizationalUnit -DistinguishedName $ouMap.ServiceAccounts -Name 'Service Accounts' -Path $labRootDn
Ensure-OrganizationalUnit -DistinguishedName $ouMap.Computers -Name 'Computers' -Path $labRootDn
Ensure-OrganizationalUnit -DistinguishedName $ouMap.Groups -Name 'Groups' -Path $labRootDn
Ensure-OrganizationalUnit -DistinguishedName $ouMap.Gpos -Name 'GPO Scope' -Path $labRootDn
Ensure-OrganizationalUnit -DistinguishedName $ouMap.Disabled -Name 'Disabled Objects' -Path $labRootDn

$allLabGroups = [System.Collections.Generic.List[object]]::new()
foreach ($groupSpec in $labPrivilegedGroups) {
    $path = switch ($groupSpec.Tier) {
        'Tier0' { $ouMap.Tier0 }
        'Tier1' { $ouMap.Tier1 }
        default { $ouMap.Tier2 }
    }
    $group = Ensure-Group -Name $groupSpec.Name -Path $path -Description "ADPosture generated $($groupSpec.Tier) privileged group"
    if ($group) { $allLabGroups.Add($group) }
}

for ($i = 1; $i -le $GroupCount; $i++) {
    $dept = (Get-RandomItem $departments).Replace(' ', '-')
    $tier = if ($i % 8 -eq 0) { 'Tier0' } elseif ($i % 3 -eq 0) { 'Tier1' } else { 'Tier2' }
    $groupName = "$Prefix LAB $tier $dept Access {0:00000}" -f $i
    $path = if ($tier -eq 'Tier0') { $ouMap.Tier0 } elseif ($tier -eq 'Tier1') { $ouMap.Tier1 } else { $ouMap.Groups }
    $group = Ensure-Group -Name $groupName -Path $path -Description "ADPosture generated nested $tier access group"
    if ($group) { $allLabGroups.Add($group) }
}

$createdPrincipals = [System.Collections.Generic.List[object]]::new()

for ($i = 1; $i -le $UserCount; $i++) {
    $first = Get-RandomItem $firstNames
    $last = Get-RandomItem $lastNames
    $sam = "$Prefix.u.$($first.ToLowerInvariant()).$($last.ToLowerInvariant()).{0:00000}" -f $i
    if ($sam.Length -gt 20) { $sam = "$Prefix.u.{0:000000000000}" -f $i }
    $display = "$first $last ADPosture {0:00000}" -f $i
    $dept = Get-RandomItem $departments
    $enabled = ($i % 37 -ne 0)
    $path = if ($enabled) { $ouMap.Users } else { $ouMap.Disabled }
    $user = Ensure-User -SamAccountName $sam `
        -DisplayName $display `
        -Path $path `
        -Department $dept `
        -Title (Get-RandomItem @('Analyst','Administrator','Engineer','Manager','Operator','Contractor')) `
        -Description "ADPosture generated user; location $(Get-RandomItem $locations); synthetic lab object" `
        -Enabled $enabled `
        -PasswordNeverExpires:($i % 5 -eq 0) `
        -PasswordNotRequired:($i % 23 -eq 0) `
        -DoesNotRequirePreAuth:($i % 11 -eq 0) `
        -TrustedForDelegation:($i % 101 -eq 0) `
        -TrustedToAuthForDelegation:($i % 149 -eq 0) `
        -CannotBeDelegated:($i % 29 -eq 0) `
        -UseDesKeyOnly:($i % 71 -eq 0) `
        -LogonWorkstations $(if ($i % 8 -eq 0) { 'PAW001,PAW002' } else { '' })
    if ($user) { $createdPrincipals.Add($user) }
}

for ($i = 1; $i -le $ServiceAccountCount; $i++) {
    $dept = (Get-RandomItem $departments).ToLowerInvariant().Replace(' ', '-')
    $sam = "$Prefix.svc.$dept.{0:00000}" -f $i
    if ($sam.Length -gt 20) { $sam = "$Prefix.svc.{0:0000000000}" -f $i }
    $display = "$Prefix Service $dept {0:00000}" -f $i
    $spns = @("HTTP/$sam.$domainDnsRoot", "MSSQLSvc/$sam.$domainDnsRoot:1433")
    $svc = Ensure-User -SamAccountName $sam `
        -DisplayName $display `
        -Path $ouMap.ServiceAccounts `
        -Department 'Application Services' `
        -Title 'Service Account' `
        -Description 'ADPosture generated service account with SPNs and mixed UAC posture' `
        -Enabled $true `
        -PasswordNeverExpires:$true `
        -PasswordNotRequired:($i % 17 -eq 0) `
        -DoesNotRequirePreAuth:($i % 9 -eq 0) `
        -TrustedForDelegation:($i % 13 -eq 0) `
        -TrustedToAuthForDelegation:($i % 11 -eq 0) `
        -CannotBeDelegated:($i % 7 -eq 0) `
        -UseDesKeyOnly:($i % 19 -eq 0) `
        -ServicePrincipalNames $spns
    if ($svc) { $createdPrincipals.Add($svc) }
}

if ($effectiveCreateGmsaObjects) {
    for ($i = 1; $i -le $GmsaCount; $i++) {
        $shortPrefix = ($Prefix -replace '[^A-Za-z0-9]', '')
        if ($shortPrefix.Length -gt 5) { $shortPrefix = $shortPrefix.Substring(0, 5) }
        if (-not $shortPrefix) { $shortPrefix = 'ADPosture' }
        $name = "$shortPrefix-g{0:0000}" -f $i
        $gmsa = Ensure-Gmsa -Name $name -Path $ouMap.ServiceAccounts -Description 'ADPosture generated gMSA lab object'
        if ($gmsa) { $createdPrincipals.Add($gmsa) }
    }
}

for ($i = 1; $i -le $ComputerCount; $i++) {
    $name = "$Prefix-SRV-{0:00000}" -f $i
    $computer = Ensure-Computer -Name $name -Path $ouMap.Computers -Description "ADPosture generated server; Windows LAPS posture test candidate" -Enabled:($i % 41 -ne 0) -TrustedForDelegation:($i % 97 -eq 0)
    if ($computer) { $createdPrincipals.Add($computer) }
}

if ($createdPrincipals.Count -gt 0 -and $allLabGroups.Count -gt 0) {
    for ($i = 0; $i -lt $createdPrincipals.Count; $i++) {
        $principal = $createdPrincipals[$i]
        $targetGroup = $allLabGroups[$random.Next(0, $allLabGroups.Count)]
        Add-MemberToGroupSafe -GroupName $targetGroup.SamAccountName -MemberDn $principal.DistinguishedName -Reason 'lab privileged membership'

        if ($i % 4 -eq 0) {
            $nestedGroup = $allLabGroups[$random.Next(0, $allLabGroups.Count)]
            Add-MemberToGroupSafe -GroupName $targetGroup.SamAccountName -MemberDn $nestedGroup.DistinguishedName -Reason 'lab nested group path'
        }

        if ($AllowBuiltInPrivilegedGroupMembership -and $i % 250 -eq 0) {
            $builtIn = Get-RandomItem $builtInPrivilegedGroups
            Add-MemberToGroupSafe -GroupName $builtIn -MemberDn $principal.DistinguishedName -Reason 'explicit built-in privileged group test'
        }
    }
}

foreach ($group in @($allLabGroups | Select-Object -First 12)) {
    Set-LabObjectAcl -TargetDn $ouMap.Users -TrusteeSam $group.SamAccountName -RightName 'GenericWrite'
    Set-LabObjectAcl -TargetDn $ouMap.ServiceAccounts -TrusteeSam $group.SamAccountName -RightName 'WriteDacl'
}

foreach ($group in @($allLabGroups | Select-Object -Skip 12 -First 8)) {
    Set-LabObjectAcl -TargetDn $ouMap.Computers -TrusteeSam $group.SamAccountName -RightName 'GenericAll'
    Set-LabObjectAcl -TargetDn $ouMap.Groups -TrusteeSam $group.SamAccountName -RightName 'WriteOwner'
    Set-ExtendedRightScenario -TargetDn $ouMap.Users -TrusteeSam $group.SamAccountName -ScenarioName 'ResetPasswordACL' -RightGuids @(
        [guid]'00299570-246d-11d0-a768-00aa006e0529'
    )
}

if ($effectiveCreatePsoScenarios -and $allLabGroups.Count -gt 0) {
    $psoTargets = @($allLabGroups | Select-Object -First 5)
    for ($i = 0; $i -lt $psoTargets.Count; $i++) {
        Ensure-FineGrainedPasswordPolicy -Name ("$Prefix LAB Weak PSO {0:000}" -f ($i + 1)) -SubjectDn $psoTargets[$i].DistinguishedName -Precedence ($i + 10)
    }
}

if ($effectiveCreateLapsScenarios -and $allLabGroups.Count -gt 0) {
    $lapsReaders = @($allLabGroups | Select-Object -First 6)
    $lapsAttributes = @(
        'msLAPS-Password',
        'msLAPS-EncryptedPassword',
        'msLAPS-EncryptedPasswordHistory',
        'msLAPS-PasswordExpirationTime',
        'ms-Mcs-AdmPwd',
        'ms-Mcs-AdmPwdExpirationTime'
    )
    foreach ($group in $lapsReaders) {
        Set-LapsReadScenario -TargetDn $ouMap.Computers -TrusteeSam $group.SamAccountName -AttributeNames $lapsAttributes
    }
}

if ($effectiveCreateDcsyncScenario -and $allLabGroups.Count -gt 0) {
    $dcsyncGroup = $allLabGroups[0]
    Set-ExtendedRightScenario -TargetDn $domainDn -TrusteeSam $dcsyncGroup.SamAccountName -ScenarioName 'DCSyncACL' -RightGuids @(
        [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
        [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
        [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
    )
}

if ($effectiveCreateAdminSdHolderScenario -and $allLabGroups.Count -gt 1) {
    $adminSdHolderDn = "CN=AdminSDHolder,CN=System,$domainDn"
    $adminSdHolder = Get-ADObject -Identity $adminSdHolderDn -ErrorAction SilentlyContinue
    if ($adminSdHolder) {
        Set-LabObjectAcl -TargetDn $adminSdHolderDn -TrusteeSam $allLabGroups[1].SamAccountName -RightName 'WriteDacl'
        Set-LabObjectAcl -TargetDn $adminSdHolderDn -TrusteeSam $allLabGroups[1].SamAccountName -RightName 'GenericWrite'
    }
    else {
        Add-Result -List $skipped -Type 'AdminSDHolder' -Name $adminSdHolderDn -Action 'Not found'
    }
}

if ($effectiveCreateRbcdScenario) {
    $actorComputers = @(Get-ADComputer -SearchBase $ouMap.Computers -LDAPFilter "(sAMAccountName=$Prefix-SRV-00001`$)" -ErrorAction SilentlyContinue)
    $targetComputers = @(Get-ADComputer -SearchBase $ouMap.Computers -LDAPFilter "(sAMAccountName=$Prefix-SRV-00002`$)" -ErrorAction SilentlyContinue)
    if ($actorComputers.Count -gt 0 -and $targetComputers.Count -gt 0) {
        Set-RbcdScenario -ActorComputer $actorComputers[0] -TargetComputer $targetComputers[0]
    }
}

if ($effectiveCreateShadowCredentialScenario) {
    $shadowTargets = @(Get-ADUser -SearchBase $ouMap.ServiceAccounts -LDAPFilter '(servicePrincipalName=*)' -Properties msDS-KeyCredentialLink -ErrorAction SilentlyContinue | Select-Object -First 5)
    foreach ($target in $shadowTargets) {
        Set-ShadowCredentialMarker -TargetObject $target
    }
}

if ($effectiveCreateAdcsAclScenario -and $allLabGroups.Count -gt 2) {
    Set-AdcsAclScenario -TrusteeSam $allLabGroups[2].SamAccountName
}

if ($effectiveCreateOrphanedSidAclScenario) {
    Set-OrphanedSidAclScenario -TargetDn $ouMap.Users -RightName 'GenericWrite'
    Set-OrphanedSidAclScenario -TargetDn $ouMap.ServiceAccounts -RightName 'WriteDacl'
}

if ($effectiveCreateGpos) {
    for ($i = 1; $i -le $GpoCount; $i++) {
        $gpoName = "$Prefix LAB GPO {0:00000}" -f $i
        $existing = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $existing -and $PSCmdlet.ShouldProcess($gpoName, 'Create and link GPO')) {
            $gpo = New-GPO -Name $gpoName -Comment 'ADPosture generated lab GPO' -ErrorAction Stop
            New-GPLink -Name $gpo.DisplayName -Target $ouMap.Gpos -LinkEnabled Yes -ErrorAction Stop | Out-Null
            if ($allLabGroups.Count -gt 0) {
                Set-GPPermission -Name $gpo.DisplayName -TargetName $allLabGroups[0].SamAccountName -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction SilentlyContinue | Out-Null
            }
            Add-Result -List $created -Type 'GPO' -Name $gpoName -Action 'Created'
        }
        elseif ($existing) {
            Add-Result -List $skipped -Type 'GPO' -Name $gpoName -Action 'Exists'
        }
    }
}

[pscustomobject]@{
    LabRoot = $labRootDn
    Created = $created.Count
    Skipped = $skipped.Count
    Updated = $updated.Count
    UsersRequested = $UserCount
    ServiceAccountsRequested = $ServiceAccountCount
    GmsaRequested = if ($effectiveCreateGmsaObjects) { $GmsaCount } else { 0 }
    ComputersRequested = $ComputerCount
    GroupsRequested = $GroupCount + $labPrivilegedGroups.Count
    BuiltInPrivilegedMembershipsEnabled = [bool]$AllowBuiltInPrivilegedGroupMembership
    GposEnabled = [bool]$effectiveCreateGpos
    AllRiskScenariosEnabled = [bool]$CreateAllRiskScenarios
    PsoScenariosEnabled = [bool]$effectiveCreatePsoScenarios
    LapsScenariosEnabled = [bool]$effectiveCreateLapsScenarios
    DcsyncScenarioEnabled = [bool]$effectiveCreateDcsyncScenario
    AdminSdHolderScenarioEnabled = [bool]$effectiveCreateAdminSdHolderScenario
    RbcdScenarioEnabled = [bool]$effectiveCreateRbcdScenario
    ShadowCredentialScenarioEnabled = [bool]$effectiveCreateShadowCredentialScenario
    AdcsAclScenarioEnabled = [bool]$effectiveCreateAdcsAclScenario
    OrphanedSidAclScenarioEnabled = [bool]$effectiveCreateOrphanedSidAclScenario
    Seed = $Seed
    CreatedSample = @($created | Select-Object -First 20)
    SkippedSample = @($skipped | Select-Object -First 20)
    UpdatedSample = @($updated | Select-Object -First 20)
}
