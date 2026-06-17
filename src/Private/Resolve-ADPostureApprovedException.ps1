function Get-ADPostureApprovedExceptionCatalog {
    [CmdletBinding()]
    param(
        [string]$Path = (Get-ModuleConfig).ApprovedExceptionsPath
    )

    if (-not (Test-Path $Path)) {
        return [PSCustomObject]@{
            SchemaVersion = '1.0'
            Exceptions    = @()
        }
    }

    $raw = Import-ADPostureJsonFile -Path $Path -RequiredProperties @('exceptions')
    [PSCustomObject]@{
        SchemaVersion = $raw.schemaVersion
        Exceptions    = @($raw.exceptions)
    }
}

function Test-ADPostureExceptionValueMatch {
    param(
        [string]$Pattern,
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) { return $true }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return $Value -like $Pattern
}

function Test-ADPostureExceptionHasMembershipScope {
    param([object]$Entry)

    foreach ($property in @('sensitiveGroup', 'memberSam', 'memberSid', 'memberDn', 'accountType')) {
        if ($Entry.PSObject.Properties[$property] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.$property)) {
            return $true
        }
    }

    $false
}

function Resolve-ADPostureApprovedException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SensitiveGroup,

        [Parameter(Mandatory)]
        $Enrichment,

        $Catalog = (Get-ADPostureApprovedExceptionCatalog),

        [datetime]$AsOf = (Get-Date)
    )

    if (-not $script:ADPostureWarnedUnscopedExceptionIds) {
        $script:ADPostureWarnedUnscopedExceptionIds = @{}
    }

    foreach ($entry in @($Catalog.Exceptions)) {
        if ($entry.enabled -eq $false) { continue }
        # An entry with no membership scope fields would otherwise match every member of every group
        # and silently remove the whole membership queue from the actionable score.
        if (-not (Test-ADPostureExceptionHasMembershipScope -Entry $entry)) {
            $entryId = if ($entry.id) { [string]$entry.id } else { '<no id>' }
            if (-not $script:ADPostureWarnedUnscopedExceptionIds.ContainsKey($entryId)) {
                $script:ADPostureWarnedUnscopedExceptionIds[$entryId] = $true
                Write-Warning "Approved exception '$entryId' has no membership scope field (sensitiveGroup, memberSam, memberSid, memberDn, accountType) and was ignored for membership findings."
            }
            continue
        }
        if (-not (Test-ADPostureExceptionValueMatch -Pattern $entry.sensitiveGroup -Value $SensitiveGroup)) { continue }
        if (-not (Test-ADPostureExceptionValueMatch -Pattern $entry.memberSam -Value $Enrichment.SamAccountName)) { continue }
        if (-not (Test-ADPostureExceptionValueMatch -Pattern $entry.memberSid -Value $Enrichment.ObjectSid)) { continue }
        if (-not (Test-ADPostureExceptionValueMatch -Pattern $entry.memberDn -Value $Enrichment.DistinguishedName)) { continue }
        if (-not (Test-ADPostureExceptionValueMatch -Pattern $entry.accountType -Value $Enrichment.AccountType)) { continue }

        $expiresAt = $null
        $status = 'Active'
        if ($entry.expiresAt) {
            $expiresAt = [datetime]$entry.expiresAt
            if ($expiresAt.Date -lt $AsOf.Date) { $status = 'Expired' }
        }

        return [PSCustomObject]@{
            Id         = $entry.id
            Status     = $status
            Reason     = $entry.reason
            Owner      = $entry.owner
            ApprovedBy = $entry.approvedBy
            Ticket     = $entry.ticket
            ExpiresAt  = if ($expiresAt) { $expiresAt.ToString('yyyy-MM-dd') } else { $null }
        }
    }

    return $null
}

function New-ADPostureApprovedExceptionResult {
    param(
        [Parameter(Mandatory)]
        $Entry,

        [datetime]$AsOf = (Get-Date)
    )

    $expiresAt = $null
    $status = 'Active'
    if ($Entry.expiresAt) {
        $expiresAt = [datetime]$Entry.expiresAt
        if ($expiresAt.Date -lt $AsOf.Date) { $status = 'Expired' }
    }

    [PSCustomObject]@{
        Id         = $Entry.id
        Status     = $status
        Reason     = $Entry.reason
        Owner      = $Entry.owner
        ApprovedBy = $Entry.approvedBy
        Ticket     = $Entry.ticket
        ExpiresAt  = if ($expiresAt) { $expiresAt.ToString('yyyy-MM-dd') } else { $null }
    }
}

function Test-ADPostureExceptionFieldMatch {
    param(
        [object]$Entry,
        [string]$EntryProperty,
        [object]$Finding,
        [string[]]$FindingProperties
    )

    if (-not $Entry.PSObject.Properties[$EntryProperty]) { return $true }
    $pattern = [string]$Entry.$EntryProperty
    if ([string]::IsNullOrWhiteSpace($pattern)) { return $true }

    foreach ($property in $FindingProperties) {
        if (-not $Finding.PSObject.Properties[$property]) { continue }
        if (Test-ADPostureExceptionValueMatch -Pattern $pattern -Value ([string]$Finding.$property)) { return $true }
    }

    $false
}

function Test-ADPostureExceptionHasFindingScope {
    param([object]$Entry)

    foreach ($property in @(
        'findingDomain',
        'sourceDomain',
        'findingType',
        'aclRight',
        'normalizedRight',
        'delegatedRight',
        'right',
        'trusteeName',
        'trusteeSid',
        'trusteeDn',
        'targetName',
        'targetDn',
        'targetSid',
        'gpoName',
        'gpoGuid',
        'gpoDn',
        'scopeName',
        'scopeDn',
        'fileSystemPath',
        'templateName',
        'templateDn',
        'principal',
        'principalSam',
        'principalSid',
        'principalDn',
        'delegationType',
        'encryption',
        'trustName',
        'trustPartner',
        'trustDirection',
        'trustType',
        'zoneName',
        'recordName',
        'recordType',
        'computerName',
        'setting',
        'observedValue',
        'mitreId',
        'severity'
    )) {
        if ($Entry.PSObject.Properties[$property] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.$property)) {
            return $true
        }
    }

    $false
}

function Resolve-ADPostureApprovedFindingException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Finding,

        $Catalog = (Get-ADPostureApprovedExceptionCatalog),

        [datetime]$AsOf = (Get-Date)
    )

    $findingDomain = if ($Finding.PSObject.Properties['IdentityRiskFindingId']) { 'IdentityRisk' } elseif ($Finding.PSObject.Properties['DnsFindingId']) { 'DNS' } elseif ($Finding.PSObject.Properties['TrustFindingId']) { 'Trust' } elseif ($Finding.PSObject.Properties['KerberosAuthFindingId']) { 'KerberosAuth' } elseif ($Finding.PSObject.Properties['AdcsFindingId']) { 'ADCS' } elseif ($Finding.PSObject.Properties['GpoFindingId']) { 'GPO' } elseif ($Finding.PSObject.Properties['AclFindingId']) { 'ACL' } else { $null }
    if (-not $findingDomain) { return $null }

    foreach ($entry in @($Catalog.Exceptions)) {
        if ($entry.enabled -eq $false) { continue }
        if (-not (Test-ADPostureExceptionHasFindingScope -Entry $entry)) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'findingDomain' -Finding ([pscustomobject]@{ FindingDomain = $findingDomain }) -FindingProperties @('FindingDomain'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'sourceDomain' -Finding ([pscustomobject]@{ FindingDomain = $findingDomain }) -FindingProperties @('FindingDomain'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'findingType' -Finding $Finding -FindingProperties @('FindingType', 'EvidenceType'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'aclRight' -Finding $Finding -FindingProperties @('NormalizedRight', 'DelegatedRight'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'normalizedRight' -Finding $Finding -FindingProperties @('NormalizedRight'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'delegatedRight' -Finding $Finding -FindingProperties @('DelegatedRight', 'NormalizedRight'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'right' -Finding $Finding -FindingProperties @('NormalizedRight', 'DelegatedRight'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'trusteeName' -Finding $Finding -FindingProperties @('TrusteeName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'trusteeSid' -Finding $Finding -FindingProperties @('TrusteeSid'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'trusteeDn' -Finding $Finding -FindingProperties @('TrusteeDistinguishedName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'targetName' -Finding $Finding -FindingProperties @('TargetName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'targetDn' -Finding $Finding -FindingProperties @('TargetDistinguishedName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'targetSid' -Finding $Finding -FindingProperties @('TargetObjectSid'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'gpoName' -Finding $Finding -FindingProperties @('GpoName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'gpoGuid' -Finding $Finding -FindingProperties @('GpoGuid'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'gpoDn' -Finding $Finding -FindingProperties @('GpoDistinguishedName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'scopeName' -Finding $Finding -FindingProperties @('ScopeName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'scopeDn' -Finding $Finding -FindingProperties @('ScopeDistinguishedName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'fileSystemPath' -Finding $Finding -FindingProperties @('FileSystemPath'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'templateName' -Finding $Finding -FindingProperties @('TemplateName', 'TemplateShortName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'templateDn' -Finding $Finding -FindingProperties @('TemplateDistinguishedName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'principal' -Finding $Finding -FindingProperties @('Principal', 'PrincipalSam', 'TrusteeName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'principalSam' -Finding $Finding -FindingProperties @('PrincipalSam', 'Principal'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'principalSid' -Finding $Finding -FindingProperties @('PrincipalSid'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'principalDn' -Finding $Finding -FindingProperties @('PrincipalDn'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'delegationType' -Finding $Finding -FindingProperties @('DelegationType'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'encryption' -Finding $Finding -FindingProperties @('EncryptionSummary'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'trustName' -Finding $Finding -FindingProperties @('TrustName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'trustPartner' -Finding $Finding -FindingProperties @('TrustPartner'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'trustDirection' -Finding $Finding -FindingProperties @('TrustDirection'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'trustType' -Finding $Finding -FindingProperties @('TrustType'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'zoneName' -Finding $Finding -FindingProperties @('ZoneName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'recordName' -Finding $Finding -FindingProperties @('RecordName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'recordType' -Finding $Finding -FindingProperties @('RecordType'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'computerName' -Finding $Finding -FindingProperties @('ComputerName'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'setting' -Finding $Finding -FindingProperties @('Setting'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'observedValue' -Finding $Finding -FindingProperties @('ObservedValue'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'mitreId' -Finding $Finding -FindingProperties @('MitreId'))) { continue }
        if (-not (Test-ADPostureExceptionFieldMatch -Entry $entry -EntryProperty 'severity' -Finding $Finding -FindingProperties @('Severity'))) { continue }

        return New-ADPostureApprovedExceptionResult -Entry $entry -AsOf $AsOf
    }

    $null
}

function Add-ADPostureApprovedExceptionMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Finding,

        $ApprovedException
    )

    $Finding | Add-Member -NotePropertyName IsApprovedException -NotePropertyValue ($null -ne $ApprovedException) -Force
    $Finding | Add-Member -NotePropertyName ApprovedExceptionStatus -NotePropertyValue $ApprovedException.Status -Force
    $Finding | Add-Member -NotePropertyName ApprovedExceptionId -NotePropertyValue $ApprovedException.Id -Force
    $Finding | Add-Member -NotePropertyName ApprovedExceptionReason -NotePropertyValue $ApprovedException.Reason -Force
    $Finding | Add-Member -NotePropertyName ApprovedExceptionOwner -NotePropertyValue $ApprovedException.Owner -Force
    $Finding | Add-Member -NotePropertyName ApprovedExceptionApprovedBy -NotePropertyValue $ApprovedException.ApprovedBy -Force
    $Finding | Add-Member -NotePropertyName ApprovedExceptionTicket -NotePropertyValue $ApprovedException.Ticket -Force
    $Finding | Add-Member -NotePropertyName ApprovedExceptionExpiresAt -NotePropertyValue $ApprovedException.ExpiresAt -Force

    if ($ApprovedException -and $ApprovedException.Status -eq 'Active') {
        $Finding | Add-Member -NotePropertyName IsExcluded -NotePropertyValue $true -Force
        $Finding | Add-Member -NotePropertyName ExclusionReason -NotePropertyValue "Approved exception: $($ApprovedException.Reason)" -Force
    }

    $Finding
}

function Add-ADPostureApprovedFindingExceptions {
    [CmdletBinding()]
    param(
        [object[]]$Findings = @(),

        $Catalog = (Get-ADPostureApprovedExceptionCatalog),

        [datetime]$AsOf = (Get-Date)
    )

    @($Findings | ForEach-Object {
        $approvedException = Resolve-ADPostureApprovedFindingException -Finding $_ -Catalog $Catalog -AsOf $AsOf
        Add-ADPostureApprovedExceptionMetadata -Finding $_ -ApprovedException $approvedException
    })
}
