function Get-AccountEnrichment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADPrincipal]$Principal,
        [string[]]$DomainControllerDnsNames = @(),
        [ValidateRange(1, 3650)]
        [int]$StaleDays = 90,
        [ValidateRange(0, 3650)]
        [int]$PasswordAgeDays = 365
    )

    $sam = $Principal.SamAccountName
    $type = 'Unknown'
    $isService = $false
    $isComputer = $false
    $isUser = $false
    $isGroup = $false
    $isExcluded = $false
    $exclusionReason = $null
    $enabled = $true
    $accountStatus = 'Active'
    $lastLogon = $null
    $lastLogonTimestamp = $null
    $pwdLastSet = $null
    $passwordNeverExpires = $false
    $whenCreated = $null
    $userAccountControl = $null
    $userAccountControlCategory = $null
    $userAccountControlSummary = 'N/A'
    $userAccountControlNotes = @()
    $uacRiskBonus = 0.0
    $uacRemediationDifficulty = 'Low'
    $uacPrivilegedConcernCount = 0
    $uacActiveFlagNames = ''
    $daysSinceLogon = $null
    $isStale = $false
    $isPasswordStale = $false
    $isDisabled = $false
    $isDomainController = $false
    $description = $null
    $spnCount = 0

    $userProps = @(
        'Enabled', 'LastLogonDate', 'lastLogonTimestamp', 'PasswordLastSet',
        'PasswordNeverExpires', 'whenCreated', 'userAccountControl',
        'Description', 'servicePrincipalName', 'AdminCount'
    )
    $computerProps = @(
        'Enabled', 'LastLogonDate', 'lastLogonTimestamp', 'PasswordLastSet',
        'PasswordNeverExpires', 'whenCreated', 'userAccountControl',
        'Description', 'operatingSystem', 'DNSHostName'
    )
    $serviceAccountProps = @(
        'Enabled', 'LastLogonDate', 'lastLogonTimestamp', 'PasswordLastSet',
        'PasswordNeverExpires', 'whenCreated', 'userAccountControl',
        'Description', 'servicePrincipalName', 'AdminCount', 'objectCategory'
    )

    $principalType = Resolve-ADPrincipalAccountType -Principal $Principal
    $type = $principalType.AccountType
    $nativeIdentity = Resolve-ADNativeIdentity -Principal $Principal -AccountType $type

    switch ($principalType.Kind) {
        'Group' { $isGroup = $true; $type = 'Group' }
        'User' {
            if ($Principal.SamAccountName -match '\$$') {
                $isComputer = $true
                $type = 'Computer'
                $detail = Get-ADComputer -Identity $Principal.DistinguishedName -Properties $computerProps -ErrorAction SilentlyContinue
            }
            else {
                $isUser = $true
                $type = 'User'
                $detail = Get-ADUser -Identity $Principal.DistinguishedName -Properties $userProps -ErrorAction SilentlyContinue
            }

            if ($detail) {
                $enabled = $detail.Enabled
                $isDisabled = -not $detail.Enabled
                $accountStatus = if ($enabled) { 'Active' } else { 'Disabled' }

                $lastLogon = $detail.LastLogonDate
                $lastLogonTimestamp = Convert-ADFileTime -FileTime $detail.lastLogonTimestamp
                if ($lastLogonTimestamp) { $lastLogon = $lastLogonTimestamp }
                elseif (-not $lastLogon -or $lastLogon -eq [DateTime]::MinValue) {
                    $lastLogon = $null
                }

                $pwdLastSet = $detail.PasswordLastSet
                if ($pwdLastSet -eq [DateTime]::MinValue) { $pwdLastSet = $null }

                $passwordNeverExpires = [bool]$detail.PasswordNeverExpires
                if (-not $passwordNeverExpires -and $detail.userAccountControl) {
                    $passwordNeverExpires = ($detail.userAccountControl -band 0x10000) -ne 0
                }

                $whenCreated = $detail.whenCreated
                $userAccountControl = [int]$detail.userAccountControl
                $description = $detail.Description
                $spnCount = @($detail.servicePrincipalName | Where-Object { $_ }).Count

                if ($isUser -and ($spnCount -gt 0 -or ($description -match 'service|svc|app|sql|iis|exchange'))) {
                    $isService = $true
                    $type = 'ServiceAccount'
                }
                if ($detail.AdminCount -eq 1) { $type = "$type (AdminCount)" }

                if ($isComputer) {
                    $dns = ($detail.DNSHostName -as [string])
                    if ($dns -and $DomainControllerDnsNames -contains $dns.ToLower()) {
                        $isDomainController = $true
                        $isExcluded = $true
                        $exclusionReason = 'Domain Controller (expected in Domain Controllers group)'
                    }
                }
            }
        }
        'Computer' {
            $isComputer = $true
            $type = 'Computer'
            $comp = Get-ADComputer -Identity $Principal.DistinguishedName -Properties $computerProps -ErrorAction SilentlyContinue
            if ($comp) {
                $enabled = $comp.Enabled
                $isDisabled = -not $comp.Enabled
                $accountStatus = if ($enabled) { 'Active' } else { 'Disabled' }

                $lastLogon = $comp.LastLogonDate
                $lastLogonTimestamp = Convert-ADFileTime -FileTime $comp.lastLogonTimestamp
                if ($lastLogonTimestamp) { $lastLogon = $lastLogonTimestamp }

                $pwdLastSet = $comp.PasswordLastSet
                if ($pwdLastSet -eq [DateTime]::MinValue) { $pwdLastSet = $null }

                $passwordNeverExpires = [bool]$comp.PasswordNeverExpires
                if (-not $passwordNeverExpires -and $comp.userAccountControl) {
                    $passwordNeverExpires = ($comp.userAccountControl -band 0x10000) -ne 0
                }

                $whenCreated = $comp.whenCreated
                $userAccountControl = [int]$comp.userAccountControl
                $description = $comp.Description

                $dns = ($comp.DNSHostName -as [string])
                if ($dns -and $DomainControllerDnsNames -contains $dns.ToLower()) {
                    $isDomainController = $true
                    $isExcluded = $true
                    $exclusionReason = 'Domain Controller (expected in Domain Controllers group)'
                }
            }
        }
        { $_ -in @('GroupManagedServiceAccount', 'ManagedServiceAccount') } {
            $isService = $true
            $type = $principalType.AccountType
            $detail = Get-ADServiceAccount -Identity $Principal.DistinguishedName -Properties $serviceAccountProps -ErrorAction SilentlyContinue

            if ($detail) {
                $enabled = $detail.Enabled
                $isDisabled = -not $detail.Enabled
                $accountStatus = if ($enabled) { 'Active' } else { 'Disabled' }

                $lastLogon = $detail.LastLogonDate
                $lastLogonTimestamp = Convert-ADFileTime -FileTime $detail.lastLogonTimestamp
                if ($lastLogonTimestamp) { $lastLogon = $lastLogonTimestamp }
                elseif (-not $lastLogon -or $lastLogon -eq [DateTime]::MinValue) {
                    $lastLogon = $null
                }

                $pwdLastSet = $detail.PasswordLastSet
                if ($pwdLastSet -eq [DateTime]::MinValue) { $pwdLastSet = $null }

                $passwordNeverExpires = [bool]$detail.PasswordNeverExpires
                if (-not $passwordNeverExpires -and $detail.userAccountControl) {
                    $passwordNeverExpires = ($detail.userAccountControl -band 0x10000) -ne 0
                }

                $whenCreated = $detail.whenCreated
                $userAccountControl = [int]$detail.userAccountControl
                $description = $detail.Description
                $spnCount = @($detail.servicePrincipalName | Where-Object { $_ }).Count

                if ($detail.AdminCount -eq 1) { $type = "$type (AdminCount)" }
            }
        }
    }

    if ($lastLogon) {
        $daysSinceLogon = Get-DaysSinceDate -Date $lastLogon
        if ($null -ne $daysSinceLogon -and $daysSinceLogon -ge $StaleDays) { $isStale = $true }
    }
    elseif ($isUser -or $isService) {
        $isStale = $true
        $daysSinceLogon = 9999
    }

    $lastLogonInfo = New-ADAccountDateField -Date $lastLogon
    $pwdInfo = New-ADAccountDateField -Date $pwdLastSet
    $createdInfo = New-ADAccountDateField -Date $whenCreated
    if ($PasswordAgeDays -gt 0 -and $null -ne $pwdInfo.Days -and $pwdInfo.Days -ge $PasswordAgeDays) {
        $isPasswordStale = $true
    }

    if ($null -ne $userAccountControl) {
        $uacFriendly = Get-UserAccountControlFriendly -Uac $userAccountControl `
            -IsDisabled:$isDisabled -PasswordNeverExpires:$passwordNeverExpires -IsStale:$isStale
        $userAccountControlCategory = $uacFriendly.Category
        $userAccountControlSummary = $uacFriendly.Summary
        $userAccountControlNotes = $uacFriendly.Notes
        $uacRiskBonus = $uacFriendly.UacRiskBonus
        $uacRemediationDifficulty = $uacFriendly.UacRemediationDifficulty
        $uacPrivilegedConcernCount = $uacFriendly.PrivilegedConcernCount
        $uacActiveFlagNames = ($uacFriendly.ActiveFlags | ForEach-Object { $_.Name }) -join '; '
    }

    if ($nativeIdentity.IsNativeIdentity -and $nativeIdentity.IsRemediableIdentity -eq $false) {
        $isExcluded = $true
        if (-not $exclusionReason) { $exclusionReason = $nativeIdentity.NativeIdentityReason }
    }

    [PSCustomObject]@{
        SamAccountName              = $sam
        DisplayName                 = $Principal.Name
        DistinguishedName           = $Principal.DistinguishedName
        ObjectSid                   = $Principal.SID.Value
        AccountType                 = $type
        IsUser                      = $isUser
        IsServiceAccount            = $isService
        IsComputer                  = $isComputer
        IsGroup                     = $isGroup
        IsEnabled                   = $enabled
        AccountStatus               = $accountStatus
        IsDisabled                  = $isDisabled
        IsStale                     = $isStale
        IsPasswordStale             = $isPasswordStale
        StaleDaysThreshold          = $StaleDays
        DaysSinceLogon              = $daysSinceLogon
        LastLogonDate               = $lastLogon
        LastLogonTimestamp          = $lastLogonTimestamp
        LastLogonUsDate             = $lastLogonInfo.UsDate
        LastLogonDays               = $lastLogonInfo.Days
        LastLogonDisplay            = $lastLogonInfo.Display
        PasswordLastSet             = $pwdLastSet
        PasswordLastSetUsDate       = $pwdInfo.UsDate
        PasswordLastSetDays         = $pwdInfo.Days
        PasswordLastSetDisplay      = $pwdInfo.Display
        PasswordAgeDaysThreshold    = $PasswordAgeDays
        PasswordNeverExpires        = $passwordNeverExpires
        WhenCreated                 = $whenCreated
        WhenCreatedUsDate           = $createdInfo.UsDate
        WhenCreatedDays             = $createdInfo.Days
        WhenCreatedDisplay          = $createdInfo.Display
        UserAccountControl              = $userAccountControl
        UserAccountControlCategory      = $userAccountControlCategory
        UserAccountControlSummary       = $userAccountControlSummary
        UserAccountControlNotes         = ($userAccountControlNotes -join '; ')
        UacRiskBonus                    = $uacRiskBonus
        UacRemediationDifficulty        = $uacRemediationDifficulty
        UacPrivilegedConcernCount       = $uacPrivilegedConcernCount
        UacActiveFlagNames              = $uacActiveFlagNames
        IsDomainController          = $isDomainController
        IsExcluded                  = $isExcluded
        ExclusionReason             = $exclusionReason
        Description                 = $description
        SpnCount                    = $spnCount
        IsNativeIdentity            = $nativeIdentity.IsNativeIdentity
        NativeIdentityCategory      = $nativeIdentity.NativeIdentityCategory
        NativeIdentityReason        = $nativeIdentity.NativeIdentityReason
        IsRemediableIdentity        = $nativeIdentity.IsRemediableIdentity
    }
}
