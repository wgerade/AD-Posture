function Get-ADPostureKerberosEncryptionSummary {
    [CmdletBinding()]
    param([object]$Value)

    $raw = if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { $null } else { [int]$Value }
    $types = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $raw -or $raw -eq 0) {
        $types.Add('NotSet')
    }
    else {
        if (($raw -band 0x1) -ne 0) { $types.Add('DES-CBC-CRC') }
        if (($raw -band 0x2) -ne 0) { $types.Add('DES-CBC-MD5') }
        if (($raw -band 0x4) -ne 0) { $types.Add('RC4-HMAC') }
        if (($raw -band 0x8) -ne 0) { $types.Add('AES128-CTS-HMAC-SHA1-96') }
        if (($raw -band 0x10) -ne 0) { $types.Add('AES256-CTS-HMAC-SHA1-96') }
        if (($raw -band 0x20) -ne 0) { $types.Add('FAST') }
    }

    $hasDes = @($types | Where-Object { $_ -like 'DES-*' }).Count -gt 0
    $hasRc4 = @($types | Where-Object { $_ -eq 'RC4-HMAC' }).Count -gt 0
    $hasAes = @($types | Where-Object { $_ -like 'AES*' }).Count -gt 0

    [pscustomobject]@{
        Raw = $raw
        Types = @($types)
        Summary = (@($types) -join ', ')
        HasDes = $hasDes
        HasRc4 = $hasRc4
        HasAes = $hasAes
        IsNotSet = ($null -eq $raw -or $raw -eq 0)
        IsDesOnly = ($hasDes -and -not $hasRc4 -and -not $hasAes)
        IsRc4OnlyOrNoAes = (($hasRc4 -and -not $hasAes) -or ($null -eq $raw -or $raw -eq 0))
    }
}

function Test-ADPostureKerberosUacFlag {
    param(
        [object]$Principal,
        [int]$Flag
    )

    if (-not $Principal.PSObject.Properties['UserAccountControl'] -and -not $Principal.PSObject.Properties['userAccountControl']) { return $false }
    $uac = if ($Principal.PSObject.Properties['UserAccountControl']) { [int]$Principal.UserAccountControl } else { [int]$Principal.userAccountControl }
    ($uac -band $Flag) -ne 0
}

function Get-ADPostureKerberosPrincipalName {
    param($Principal)

    foreach ($property in @('SamAccountName', 'sAMAccountName', 'Name', 'DisplayName', 'DNSHostName')) {
        if ($Principal.PSObject.Properties[$property] -and -not [string]::IsNullOrWhiteSpace([string]$Principal.$property)) {
            return [string]$Principal.$property
        }
    }
    'Unknown principal'
}

function Get-ADPostureKerberosPrincipalClass {
    param($Principal)

    $classes = @($Principal.objectClass | Where-Object { $_ })
    if ($Principal.PSObject.Properties['ObjectClass'] -and $Principal.ObjectClass) { $classes += @($Principal.ObjectClass) }
    $blob = (@($classes) -join ';').ToLowerInvariant()
    $sam = Get-ADPostureKerberosPrincipalName -Principal $Principal
    if ($blob -match 'msds-groupmanagedserviceaccount') { return 'serviceAccount' }
    if ($blob -match 'computer' -or $sam -match '\$$') { return 'computer' }
    if ($blob -match 'user') { return 'user' }
    'unknown'
}

function Get-ADPostureKerberosPropertyValues {
    param(
        [Parameter(Mandatory)]$Principal,
        [Parameter(Mandatory)][string[]]$PropertyNames
    )

    $values = [System.Collections.Generic.List[object]]::new()
    foreach ($propertyName in $PropertyNames) {
        if (-not $Principal.PSObject.Properties[$propertyName]) { continue }
        $value = $Principal.$propertyName
        if ($null -eq $value) { continue }

        if ($value -is [byte[]] -or $value -is [System.DirectoryServices.ActiveDirectorySecurity]) {
            $values.Add($value)
            continue
        }

        if ($value -is [array]) {
            foreach ($item in $value) {
                if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
                    $values.Add($item)
                }
            }
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            $values.Add($value)
        }
    }

    @($values)
}

function Get-ADPostureKerberosDateValue {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return [datetime]$Value }
    if ($Value -is [int64] -or $Value -is [long] -or $Value -is [int]) {
        if ([int64]$Value -le 0) { return $null }
        try { return [DateTime]::FromFileTimeUtc([int64]$Value) } catch { return $null }
    }
    try { return [datetime]$Value } catch { return $null }
}

function Get-ADPostureKerberosPasswordLastSet {
    param($Principal)

    foreach ($property in @('PasswordLastSet', 'pwdLastSet')) {
        if ($Principal.PSObject.Properties[$property]) {
            $date = Get-ADPostureKerberosDateValue -Value $Principal.$property
            if ($date) { return $date }
        }
    }
    $null
}

function Test-ADPostureKerberosPasswordNeverExpires {
    param($Principal)

    Test-ADPostureKerberosUacFlag -Principal $Principal -Flag 0x10000
}

function Get-ADPostureKerberosRiskContext {
    param(
        [Parameter(Mandatory)]$Principal,
        [Parameter(Mandatory)][string]$AccountType,
        [Parameter(Mandatory)][bool]$IsPrivileged,
        [object[]]$ServicePrincipalNames = @(),
        [object[]]$DelegationTargets = @(),
        [object[]]$ResourceBasedDelegation = @(),
        [datetime]$AsOf = (Get-Date),
        [int]$PasswordAgeDays = 365
    )

    $signals = [System.Collections.Generic.List[string]]::new()
    if ($IsPrivileged) { $signals.Add('privileged identity') }
    if ($AccountType -eq 'ServiceAccount') { $signals.Add('service account') }
    if (@($ServicePrincipalNames).Count -gt 0) { $signals.Add('service principal') }
    if (@($DelegationTargets).Count -gt 0 -or @($ResourceBasedDelegation).Count -gt 0 -or (Test-ADPostureKerberosUacFlag -Principal $Principal -Flag 0x80000) -or (Test-ADPostureKerberosUacFlag -Principal $Principal -Flag 0x1000000)) { $signals.Add('delegation configured') }
    if (Test-ADPostureKerberosPasswordNeverExpires -Principal $Principal) { $signals.Add('password never expires') }

    $passwordLastSet = Get-ADPostureKerberosPasswordLastSet -Principal $Principal
    $passwordAge = $null
    if ($passwordLastSet) {
        $passwordAge = [int](New-TimeSpan -Start $passwordLastSet -End $AsOf).TotalDays
        if ($passwordAge -ge $PasswordAgeDays) { $signals.Add("password age ${passwordAge}d") }
    }

    [pscustomobject]@{
        Signals = @($signals | Sort-Object -Unique)
        IsReportable = (@($signals).Count -gt 0)
        PasswordLastSet = $passwordLastSet
        PasswordAgeDays = $passwordAge
    }
}

function ConvertTo-ADPostureKerberosPrincipalSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Principal
    )

    $name = Get-ADPostureKerberosPrincipalName -Principal $Principal
    $dn = if ($Principal.PSObject.Properties['DistinguishedName']) { [string]$Principal.DistinguishedName } else { $null }
    $sid = if ($Principal.PSObject.Properties['ObjectSid']) { [string]$Principal.ObjectSid } elseif ($Principal.PSObject.Properties['SID']) { [string]$Principal.SID } else { $null }
    $spns = @($Principal.servicePrincipalName | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $delegationTargets = @(Get-ADPostureKerberosPropertyValues -Principal $Principal -PropertyNames @('msDS-AllowedToDelegateTo', 'AllowedToDelegateTo') | ForEach-Object { [string]$_ })
    $rbcdValues = @(Get-ADPostureKerberosPropertyValues -Principal $Principal -PropertyNames @('msDS-AllowedToActOnBehalfOfOtherIdentity', 'ResourceBasedConstrainedDelegation'))
    $encValue = if ($Principal.PSObject.Properties['msDS-SupportedEncryptionTypes']) { $Principal.'msDS-SupportedEncryptionTypes' } elseif ($Principal.PSObject.Properties['SupportedEncryptionTypes']) { $Principal.SupportedEncryptionTypes } else { $null }
    $enc = Get-ADPostureKerberosEncryptionSummary -Value $encValue
    $uac = if ($Principal.PSObject.Properties['UserAccountControl']) { [int]$Principal.UserAccountControl } elseif ($Principal.PSObject.Properties['userAccountControl']) { [int]$Principal.userAccountControl } else { $null }
    $memberOf = @($Principal.MemberOf + $Principal.memberOf | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $rbcdValueTypes = @($rbcdValues | ForEach-Object { $_.GetType().FullName } | Sort-Object -Unique)

    [pscustomobject]@{
        SamAccountName = $name
        DistinguishedName = $dn
        ObjectSid = $sid
        PrincipalClass = Get-ADPostureKerberosPrincipalClass -Principal $Principal
        AccountType = Get-ADPostureKerberosAccountType -Principal $Principal
        DnsHostName = if ($Principal.PSObject.Properties['dnsHostName']) { [string]$Principal.dnsHostName } elseif ($Principal.PSObject.Properties['DNSHostName']) { [string]$Principal.DNSHostName } else { $null }
        UserAccountControl = $uac
        AdminCount = if ($Principal.PSObject.Properties['adminCount']) { [int]$Principal.adminCount } elseif ($Principal.PSObject.Properties['AdminCount']) { [int]$Principal.AdminCount } else { $null }
        ServicePrincipalNames = @($spns)
        ServicePrincipalNameCount = @($spns).Count
        AllowedToDelegateTo = @($delegationTargets)
        AllowedToDelegateToCount = @($delegationTargets).Count
        HasResourceBasedConstrainedDelegation = (@($rbcdValues).Count -gt 0)
        ResourceBasedConstrainedDelegationValueTypes = @($rbcdValueTypes)
        SupportedEncryptionTypesRaw = $enc.Raw
        EncryptionTypes = @($enc.Types)
        EncryptionSummary = $enc.Summary
        PasswordLastSet = $(Get-ADPostureKerberosPasswordLastSet -Principal $Principal)
        PasswordNeverExpires = Test-ADPostureKerberosPasswordNeverExpires -Principal $Principal
        MemberOfCount = @($memberOf).Count
        IsPrivileged = Test-ADPostureKerberosPrivilegedPrincipal -Principal $Principal
        IsProtectedUsersMember = Test-ADPostureKerberosProtectedUsersMember -Principal $Principal
        IsDelegationProtected = Test-ADPostureKerberosUacFlag -Principal $Principal -Flag 0x100000
        DelegationProtectionMethod = Get-ADPostureKerberosDelegationProtectionMethod -Principal $Principal
    }
}

function Get-ADPostureKerberosAccountType {
    param($Principal)

    $class = Get-ADPostureKerberosPrincipalClass -Principal $Principal
    $spns = @($Principal.servicePrincipalName | Where-Object { $_ })
    if ($class -eq 'computer') { return 'Computer' }
    if ($class -eq 'serviceAccount' -or $spns.Count -gt 0 -or (Get-ADPostureKerberosPrincipalName -Principal $Principal) -match '^(?i:svc|sa_|app|sql|iis)') { return 'ServiceAccount' }
    if ($class -eq 'user') { return 'User' }
    'Unknown'
}

function Test-ADPostureKerberosPrivilegedPrincipal {
    param($Principal)

    if ($Principal.PSObject.Properties['AdminCount'] -and [int]$Principal.AdminCount -eq 1) { return $true }
    if ($Principal.PSObject.Properties['adminCount'] -and [int]$Principal.adminCount -eq 1) { return $true }
    $memberOf = @($Principal.MemberOf + $Principal.memberOf | Where-Object { $_ })
    ($memberOf -join ';') -match '(?i)CN=(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Server Operators|Backup Operators|Print Operators|DnsAdmins|Group Policy Creator Owners|Key Admins|Enterprise Key Admins|Cert Publishers),'
}

function Test-ADPostureKerberosProtectedUsersMember {
    param($Principal)

    $memberOf = @($Principal.MemberOf + $Principal.memberOf | Where-Object { $_ })
    ($memberOf -join ';') -match '(?i)CN=Protected Users,'
}

function Get-ADPostureKerberosDelegationProtectionMethod {
    param($Principal)

    $methods = [System.Collections.Generic.List[string]]::new()
    if (Test-ADPostureKerberosUacFlag -Principal $Principal -Flag 0x100000) { $methods.Add('NOT_DELEGATED') }
    if (Test-ADPostureKerberosProtectedUsersMember -Principal $Principal) { $methods.Add('ProtectedUsers') }

    if ($methods.Count -eq 0) { return 'None' }
    @($methods) -join ', '
}

function New-ADPostureKerberosAuthFinding {
    param(
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$FindingType,
        [Parameter(Mandatory)][string]$RiskPattern,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][double]$RiskScore,
        [Parameter(Mandatory)]$Principal,
        [string]$DelegationType,
        [object[]]$DelegationTargets = @(),
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$Remediation,
        [Parameter(Mandatory)][string]$ScoreFormula,
        [object[]]$ScoreComponents = @(),
        [object[]]$AttackTechniques = @(),
        [string[]]$Tags = @()
    )

    $name = Get-ADPostureKerberosPrincipalName -Principal $Principal
    $sid = if ($Principal.PSObject.Properties['ObjectSid']) { [string]$Principal.ObjectSid } elseif ($Principal.PSObject.Properties['SID']) { [string]$Principal.SID } else { $null }
    $dn = if ($Principal.PSObject.Properties['DistinguishedName']) { [string]$Principal.DistinguishedName } else { $null }
    $spns = @($Principal.servicePrincipalName | Where-Object { $_ })
    $enc = Get-ADPostureKerberosEncryptionSummary -Value $(if ($Principal.PSObject.Properties['msDS-SupportedEncryptionTypes']) { $Principal.'msDS-SupportedEncryptionTypes' } elseif ($Principal.PSObject.Properties['SupportedEncryptionTypes']) { $Principal.SupportedEncryptionTypes } else { $null })
    $accountType = Get-ADPostureKerberosAccountType -Principal $Principal
    $tier = if (Test-ADPostureKerberosPrivilegedPrincipal -Principal $Principal) { 'Tier 0' } elseif ($accountType -eq 'ServiceAccount' -or $accountType -eq 'Computer') { 'Tier 1' } else { 'Tier 2' }

    [pscustomobject]@{
        KerberosAuthFindingId = 'auth-{0:000000}' -f $Index
        Domain = $Domain
        FindingType = $FindingType
        RiskPattern = $RiskPattern
        Severity = $Severity
        RiskScore = [Math]::Round($RiskScore, 2)
        Principal = $name
        PrincipalSam = $name
        PrincipalDn = $dn
        PrincipalSid = $sid
        PrincipalClass = Get-ADPostureKerberosPrincipalClass -Principal $Principal
        PrivilegeTier = $tier
        AccountType = $accountType
        ServicePrincipalNames = @($spns)
        DelegationType = $DelegationType
        DelegationTargets = @($DelegationTargets)
        EncryptionTypes = @($enc.Types)
        EncryptionSummary = $enc.Summary
        Reason = $Reason
        Remediation = $Remediation
        ScoreFormula = $ScoreFormula
        ScoreComponents = @($ScoreComponents)
        AttackTechniques = @($AttackTechniques)
        Tags = @($Tags + 'KerberosAuth' | Sort-Object -Unique)
    }
}

function ConvertTo-ADPostureKerberosAuthRiskModel {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [object[]]$Principals = @(),
        $AuthPolicy = $null,
        [datetime]$AsOf = (Get-Date),
        [int]$PasswordAgeDays = 365,
        [int]$KrbtgtPasswordAgeDays = 180
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = 0

    foreach ($principal in @($Principals)) {
        if (-not $principal) { continue }
        $name = Get-ADPostureKerberosPrincipalName -Principal $principal
        $spns = @($principal.servicePrincipalName | Where-Object { $_ })
        $encValue = if ($principal.PSObject.Properties['msDS-SupportedEncryptionTypes']) { $principal.'msDS-SupportedEncryptionTypes' } elseif ($principal.PSObject.Properties['SupportedEncryptionTypes']) { $principal.SupportedEncryptionTypes } else { $null }
        $enc = Get-ADPostureKerberosEncryptionSummary -Value $encValue
        $isPrivileged = Test-ADPostureKerberosPrivilegedPrincipal -Principal $principal
        $isProtectedUsers = Test-ADPostureKerberosProtectedUsersMember -Principal $principal
        $notDelegated = Test-ADPostureKerberosUacFlag -Principal $principal -Flag 0x100000
        $accountType = Get-ADPostureKerberosAccountType -Principal $principal
        $allowedToDelegateTo = @(Get-ADPostureKerberosPropertyValues -Principal $principal -PropertyNames @('msDS-AllowedToDelegateTo', 'AllowedToDelegateTo'))
        $rbcd = @(Get-ADPostureKerberosPropertyValues -Principal $principal -PropertyNames @('msDS-AllowedToActOnBehalfOfOtherIdentity', 'ResourceBasedConstrainedDelegation'))
        $context = Get-ADPostureKerberosRiskContext -Principal $principal -AccountType $accountType -IsPrivileged ([bool]$isPrivileged) -ServicePrincipalNames $spns -DelegationTargets $allowedToDelegateTo -ResourceBasedDelegation $rbcd -AsOf $AsOf -PasswordAgeDays $PasswordAgeDays
        $contextReason = if (@($context.Signals).Count) { " Context: $(@($context.Signals) -join ', ')." } else { '' }

        if ($name -match '^(?i:krbtgt)$') {
            $krbtgtDate = $context.PasswordLastSet
            if (-not $krbtgtDate) {
                $index++
                $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosKrbtgtRotationEvidenceMissing' -RiskPattern 'krbtgt rotation evidence gap' -Severity 'Informational' -RiskScore 0 -Principal $principal -Reason 'krbtgt password age could not be confirmed from local directory evidence.' -Remediation 'Collect krbtgt password-last-set evidence and validate the dual-rotation process is documented and current.' -ScoreFormula 'krbtgt review = missing local password-last-set evidence' -ScoreComponents @([pscustomobject]@{ Name = 'krbtgt pwdLastSet'; Value = 'Missing'; Reason = 'Local directory evidence is required before rotation age can be assessed' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558.001'; Name = 'Golden Ticket'; Tactic = 'Credential Access' }) -Tags @('Krbtgt', 'TicketForgery', 'EvidenceReview')))
            }
            else {
                $ageDays = [int](New-TimeSpan -Start $krbtgtDate -End $AsOf).TotalDays
                if ($ageDays -gt $KrbtgtPasswordAgeDays) {
                    $index++
                    $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosKrbtgtPasswordStale' -RiskPattern 'krbtgt password age' -Severity 'High' -RiskScore 8.4 -Principal $principal -Reason "krbtgt password was last set $ageDays days ago, exceeding the $KrbtgtPasswordAgeDays day review threshold." -Remediation 'Plan and execute the approved dual krbtgt rotation procedure, then record the rotation evidence.' -ScoreFormula 'krbtgt score = stale Tier 0 ticket-signing secret' -ScoreComponents @([pscustomobject]@{ Name = 'krbtgt password age'; Value = $ageDays; Reason = 'Stale krbtgt key material increases ticket-forgery persistence impact' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558.001'; Name = 'Golden Ticket'; Tactic = 'Credential Access' }) -Tags @('Krbtgt', 'TicketForgery', 'Tier0Exposure')))
                }
            }
            continue
        }

        if ((Test-ADPostureKerberosUacFlag -Principal $principal -Flag 0x400000) -and $context.IsReportable) {
            $index++
            $score = if ($isPrivileged) { 9.2 } elseif ($accountType -eq 'ServiceAccount') { 8.4 } else { 7.2 }
            $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosAsRepRoastableAccount' -RiskPattern 'AS-REP Roast' -Severity 'High' -RiskScore $score -Principal $principal -Reason "Account '$name' does not require Kerberos pre-authentication.$contextReason" -Remediation 'Require Kerberos pre-authentication and document any exception with owner, ticket, and expiration.' -ScoreFormula 'AS-REP score = pre-auth disabled + account risk context' -ScoreComponents @([pscustomobject]@{ Name = 'DONT_REQ_PREAUTH'; Value = $true; Reason = 'Kerberos pre-authentication is disabled' }, [pscustomobject]@{ Name = 'Context'; Value = (@($context.Signals) -join ', '); Reason = 'Finding is reportable because the account has exposure context' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558.004'; Name = 'AS-REP Roasting'; Tactic = 'Credential Access' }) -Tags @('ASREP', 'Roastable', 'CredentialExposure')))
        }

        if ($spns.Count -gt 0 -and $name -notmatch '^(?i:krbtgt)$') {
            $index++
            $score = if ($isPrivileged) { 8.8 } elseif ($accountType -eq 'ServiceAccount') { 7.0 } else { 5.8 }
            $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosRoastableServiceAccount' -RiskPattern 'Kerberoast' -Severity $(if ($score -ge 8) { 'High' } else { 'Medium' }) -RiskScore $score -Principal $principal -Reason "Account '$name' has $($spns.Count) SPN(s), making it a Kerberos service principal that should be reviewed for password strength, rotation, and privilege.$contextReason" -Remediation 'Use gMSA where possible, remove unused SPNs, reduce privilege, and enforce strong AES-capable service account hygiene.' -ScoreFormula 'Kerberoast score = SPN exposure + account sensitivity' -ScoreComponents @([pscustomobject]@{ Name = 'SPN count'; Value = $spns.Count; Reason = 'Service principal can receive service tickets' }, [pscustomobject]@{ Name = 'Context'; Value = (@($context.Signals) -join ', '); Reason = 'Service principal exposure is actionable when paired with account context' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558.003'; Name = 'Kerberoasting'; Tactic = 'Credential Access' }) -Tags @('Kerberoast', 'ServicePrincipal')))
        }

        if (($enc.IsDesOnly -or (Test-ADPostureKerberosUacFlag -Principal $principal -Flag 0x200000)) -and $context.IsReportable) {
            $index++
            $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosDesOnlyAccount' -RiskPattern 'Weak Kerberos Encryption' -Severity 'High' -RiskScore 8.0 -Principal $principal -Reason "Account '$name' allows DES-only or DES-focused Kerberos encryption.$contextReason" -Remediation 'Remove DES, enable AES-capable Kerberos encryption, and rotate the account password/key material.' -ScoreFormula 'Weak encryption score = DES enabled + account risk context' -ScoreComponents @([pscustomobject]@{ Name = 'Encryption'; Value = $enc.Summary; Reason = 'DES is obsolete for Kerberos authentication' }, [pscustomobject]@{ Name = 'Context'; Value = (@($context.Signals) -join ', '); Reason = 'Finding is reportable because the account has exposure context' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558'; Name = 'Steal or Forge Kerberos Tickets'; Tactic = 'Credential Access' }) -Tags @('WeakEncryption', 'DES')))
        }
        elseif ($enc.IsRc4OnlyOrNoAes -and $spns.Count -gt 0 -and $context.IsReportable) {
            $index++
            $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosRc4OnlyOrNoAes' -RiskPattern 'Weak Kerberos Encryption' -Severity 'Medium' -RiskScore 5.8 -Principal $principal -Reason "Account '$name' has no explicit AES Kerberos encryption posture recorded for a service principal.$contextReason" -Remediation 'Set AES-capable supported encryption types where compatible and rotate the password/key so AES keys exist.' -ScoreFormula 'Weak encryption score = service principal + no AES evidence + account risk context' -ScoreComponents @([pscustomobject]@{ Name = 'Encryption'; Value = $enc.Summary; Reason = 'No AES evidence was found for this service principal' }, [pscustomobject]@{ Name = 'Context'; Value = (@($context.Signals) -join ', '); Reason = 'Finding is reportable because the service principal has exposure context' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558.003'; Name = 'Kerberoasting'; Tactic = 'Credential Access' }) -Tags @('WeakEncryption', 'RC4', 'NoAES')))
        }

        if (Test-ADPostureKerberosUacFlag -Principal $principal -Flag 0x80000) {
            $index++
            $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosUnconstrainedDelegation' -RiskPattern 'Unconstrained Delegation' -Severity 'Critical' -RiskScore 15.0 -Principal $principal -DelegationType 'Unconstrained' -Reason "Account '$name' is trusted for unconstrained delegation." -Remediation 'Remove unconstrained delegation; replace with least-privilege constrained delegation or RBCD only where formally approved.' -ScoreFormula 'Delegation score = unconstrained delegation control path' -ScoreComponents @([pscustomobject]@{ Name = 'TRUSTED_FOR_DELEGATION'; Value = $true; Reason = 'Account can receive delegated tickets broadly' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558'; Name = 'Steal or Forge Kerberos Tickets'; Tactic = 'Credential Access' }) -Tags @('Delegation', 'UnconstrainedDelegation', 'Tier0Exposure')))
        }

        if ((Test-ADPostureKerberosUacFlag -Principal $principal -Flag 0x1000000) -or $allowedToDelegateTo.Count -gt 0) {
            $index++
            $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosConstrainedDelegation' -RiskPattern 'Constrained Delegation' -Severity 'High' -RiskScore 8.2 -Principal $principal -DelegationType 'Constrained' -DelegationTargets $allowedToDelegateTo -Reason "Account '$name' has Kerberos constrained delegation targets." -Remediation 'Validate every delegated SPN target, remove stale entries, and keep protocol transition disabled unless explicitly required.' -ScoreFormula 'Delegation score = constrained delegation target count + account sensitivity' -ScoreComponents @([pscustomobject]@{ Name = 'Delegation targets'; Value = $allowedToDelegateTo.Count; Reason = 'Account can delegate to configured services' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558'; Name = 'Steal or Forge Kerberos Tickets'; Tactic = 'Credential Access' }) -Tags @('Delegation', 'ConstrainedDelegation')))
        }

        if ($rbcd.Count -gt 0) {
            $index++
            $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosResourceBasedConstrainedDelegation' -RiskPattern 'RBCD' -Severity 'High' -RiskScore 8.5 -Principal $principal -DelegationType 'ResourceBasedConstrained' -Reason "Account '$name' has resource-based constrained delegation security descriptor data." -Remediation 'Review and remove unauthorized RBCD trustees; require explicit owner and change-control for any remaining RBCD path.' -ScoreFormula 'RBCD score = resource-based delegation descriptor present' -ScoreComponents @([pscustomobject]@{ Name = 'RBCD descriptor'; Value = $true; Reason = 'msDS-AllowedToActOnBehalfOfOtherIdentity is populated' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1134.001'; Name = 'Token Impersonation/Theft'; Tactic = 'Privilege Escalation, Defense Evasion' }) -Tags @('Delegation', 'RBCD')))
        }

        if ($isPrivileged -and -not $notDelegated -and -not $isProtectedUsers) {
            $index++
            $findings.Add((New-ADPostureKerberosAuthFinding -Index $index -Domain $Domain -FindingType 'KerberosSensitiveAccountDelegable' -RiskPattern 'Sensitive Account Delegable' -Severity 'High' -RiskScore 7.8 -Principal $principal -Reason "Privileged account '$name' is not marked as non-delegable and was not identified as a Protected Users member." -Remediation 'Mark privileged accounts as sensitive/cannot be delegated and place appropriate Tier 0 users in Protected Users after compatibility review.' -ScoreFormula 'Sensitive account delegation score = privileged identity without delegation protection' -ScoreComponents @([pscustomobject]@{ Name = 'Delegation protection'; Value = $false; Reason = 'Privileged identity lacks NOT_DELEGATED/Protected Users evidence' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1558'; Name = 'Steal or Forge Kerberos Tickets'; Tactic = 'Credential Access' }) -Tags @('Delegation', 'ProtectedUsersGap', 'Tier0Exposure')))
        }
    }

    [pscustomobject]@{
        KerberosAuthPrincipals = @($Principals | ForEach-Object { ConvertTo-ADPostureKerberosPrincipalSnapshot -Principal $_ })
        KerberosAuthPolicy = $AuthPolicy
        KerberosAuthFindings = @($findings)
    }
}

function Get-ADPostureKerberosAuthPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Domain,
        [hashtable]$DomainParams = @{},
        [string]$LogPath
    )

    Write-Host 'Kerberos/Auth posture collection: reading authentication-sensitive principals.'
    if ($LogPath) {
        Write-ADPostureLog -Message 'Kerberos/Auth posture collection: reading authentication-sensitive principals.' -Path $LogPath
    }

    $properties = @(
        'servicePrincipalName',
        'userAccountControl',
        'msDS-SupportedEncryptionTypes',
        'msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity',
        'adminCount',
        'memberOf',
        'objectSid',
        'distinguishedName',
        'sAMAccountName',
        'displayName',
        'objectClass',
        'dnsHostName',
        'pwdLastSet'
    )

    try {
        $principals = @(Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))' -Properties $properties @DomainParams -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not enumerate Kerberos/Auth principals: $($_.Exception.Message)"
        if ($LogPath) {
            Write-ADPostureLog -Message "Could not enumerate Kerberos/Auth principals: $($_.Exception.Message)" -Level Warning -Path $LogPath
        }
        $principals = @()
    }

    $domainName = if ($Domain.DNSRoot) { $Domain.DNSRoot } else { [string]$Domain }
    $model = ConvertTo-ADPostureKerberosAuthRiskModel -Domain $domainName -Principals @($principals)
    $message = "Kerberos/Auth posture collection complete: $(@($principals).Count) principals, $(@($model.KerberosAuthFindings).Count) findings."
    Write-Host $message
    if ($LogPath) {
        Write-ADPostureLog -Message $message -Path $LogPath
    }

    $model
}
