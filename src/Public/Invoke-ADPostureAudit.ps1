function Invoke-ADPostureAudit {
    <#
    .SYNOPSIS
    Runs a full audit of members in sensitive AD groups.
    .PARAMETER InputObject
    Optional pipeline input. Accepts a server/domain string or an object with Server, DNSHostName, HostName, Domain, or Name.
    .PARAMETER Server
    Target DC or domain. Default: current context domain.
    .PARAMETER IncludeOptionalGroups
    Includes groups marked optional (Exchange, etc.).
    .PARAMETER IncludeAclPosture
    Reads ACLs from the domain root, AdminSDHolder, and scanned sensitive groups and adds dangerous ACE evidence to the object risk model.
    .PARAMETER IncludeAclOrganizationalUnits
    When used with IncludeAclPosture, also reads ACLs from Organizational Units.
    .PARAMETER IncludeAclGpoContainers
    When used with IncludeAclPosture, also reads ACLs from Group Policy container objects under CN=Policies,CN=System.
    .PARAMETER IncludeAclPrivilegedUsers
    When used with IncludeAclPosture, also reads ACLs from users protected by AdminSDHolder/adminCount.
    .PARAMETER IncludeAclPrivilegedComputers
    When used with IncludeAclPosture, also reads ACLs from computers protected by AdminSDHolder/adminCount.
    .PARAMETER IncludeAclPrivilegedGroups
    When used with IncludeAclPosture, also reads ACLs from groups protected by AdminSDHolder/adminCount beyond the catalog targets.
    .PARAMETER IncludeAclAllObjects
    When used with IncludeAclPosture, also reads ACLs from users, groups, computers, OUs, and GPO containers under the domain naming context.
    .PARAMETER AclSearchBase
    When used with IncludeAclPosture, also reads ACLs from users, groups, computers, OUs, and GPO containers under one or more distinguished names.
    .PARAMETER AclReadDelayMilliseconds
    Optional pause between ACL target reads. Defaults to a conservative 25 ms to reduce sustained DC/jump-server pressure during broad ACL scans.
    .PARAMETER AclEffectiveTrusteeLimit
    Maximum recursive group members to retain per direct ACL group trustee when modeling effective ACL exposure.
    .PARAMETER IncludeGpoPosture
    Reads GPO containers and linked domain/OU scopes, then reports risky GPO posture signals such as dangerous GPO delegation and unusual SYSVOL paths.
    .PARAMETER IncludeGpoSysvolAcl
    When used with IncludeGpoPosture, validates GPO SYSVOL folder ACLs and external script paths that can be discovered from policy metadata files.
    .PARAMETER GpoSearchBase
    Optional distinguished names used to limit OU link discovery for GPO posture. Domain-root links are always checked when IncludeGpoPosture is used.
    .PARAMETER IncludeAdcsPosture
    Reads ADCS certificate templates, Enrollment Services CA objects, NTAuth, template publication state, and best-effort CA policy configuration; reports ESC-style enrollment, template, CA, and NTAuth posture signals.
    .PARAMETER IncludeKerberosAuthPosture
    Reads Kerberos/authentication-sensitive account attributes and reports roastable accounts, weak encryption, delegation exposure, RBCD, and privileged-account delegation protection gaps.
    .PARAMETER IncludeTrustPosture
    Reads domain trust configuration and reports trust blast-radius signals such as SID filtering gaps, selective authentication gaps, transitivity, TGT delegation, and stale trust governance.
    .PARAMETER IncludeDnsPosture
    Reads AD-integrated DNS zones, records, DnsAdmins membership, and DNS-related ACL evidence; reports insecure dynamic updates, stale/wildcard/dangling records, DNS ACL delegation, and DNS admin exposure.
    .PARAMETER StaleDays
    Days without logon to classify an account as unused.
    .PARAMETER PasswordAgeDays
    Days since password last set to classify a privileged account password as stale. Use 0 to disable password-age findings.
    .PARAMETER OutputDirectory
    Directory for CSV/JSON reports.
    .PARAMETER LogPath
    Optional log file path. Verbose output is always available with -Verbose.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ValueFromPipeline)]
        [object]$InputObject,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('Domain', 'DNSHostName', 'HostName', 'Name')]
        [string]$Server,

        [Parameter(ParameterSetName = 'Full')]
        [switch]$Full,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeOptionalGroups,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeAclPosture,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeAclOrganizationalUnits,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeAclGpoContainers,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeAclPrivilegedUsers,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeAclPrivilegedComputers,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeAclPrivilegedGroups,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeAclAllObjects,
        [Parameter(ParameterSetName = 'Default')]
        [string[]]$AclSearchBase,
        [ValidateRange(0, 10000)]
        [int]$AclReadDelayMilliseconds = 25,
        [ValidateRange(0, 10000)]
        [int]$AclEffectiveTrusteeLimit = 100,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeGpoPosture,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeGpoSysvolAcl,
        [Parameter(ParameterSetName = 'Default')]
        [string[]]$GpoSearchBase,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeAdcsPosture,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeKerberosAuthPosture,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeTrustPosture,
        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeDnsPosture,
        [ValidateRange(1, 3650)]
        [int]$StaleDays = 90,
        [ValidateRange(0, 3650)]
        [int]$PasswordAgeDays = 365,
        [string]$OutputDirectory,
        [string]$LogPath,
        [switch]$SkipTimelineRefresh
    )

    begin {
        Test-ADModuleAvailable
        $cfg = Get-ModuleConfig
        $catalog = Get-ADSensitiveGroupCatalog
        $approvedExceptionCatalog = Get-ADPostureApprovedExceptionCatalog

        if (-not $OutputDirectory) {
            $OutputDirectory = $cfg.ReportPath
        }
        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop | Out-Null
        }
    }

    process {
        $script:ADPostureRequestedPosture = @{
            Acl      = [bool]($Full -or $IncludeAclPosture)
            Gpo      = [bool]($Full -or $IncludeGpoPosture)
            Adcs     = [bool]($Full -or $IncludeAdcsPosture)
            Kerberos = [bool]($Full -or $IncludeKerberosAuthPosture)
            Trust    = [bool]($Full -or $IncludeTrustPosture)
            Dns      = [bool]($Full -or $IncludeDnsPosture)
        }
        $script:ADPostureSkipTimelineRefresh = [bool]$SkipTimelineRefresh

        if ($Full) {
            $IncludeOptionalGroups = $true
            $IncludeAclPosture = $true
            $IncludeAclOrganizationalUnits = $true
            $IncludeAclGpoContainers = $true
            $IncludeAclPrivilegedUsers = $true
            $IncludeAclPrivilegedComputers = $true
            $IncludeAclPrivilegedGroups = $true
            $IncludeAclAllObjects = $true
            $IncludeGpoPosture = $true
            $IncludeGpoSysvolAcl = $true
            $IncludeAdcsPosture = $true
            $IncludeKerberosAuthPosture = $true
            $IncludeTrustPosture = $true
            $IncludeDnsPosture = $true
        }
        $targetServer = Resolve-ADPosturePipelineServer -InputObject $InputObject -Server $Server
        Invoke-ADPostureAuditTarget -Server $targetServer `
            -IncludeOptionalGroups:$IncludeOptionalGroups `
            -IncludeAclPosture:$IncludeAclPosture `
            -IncludeAclOrganizationalUnits:$IncludeAclOrganizationalUnits `
            -IncludeAclGpoContainers:$IncludeAclGpoContainers `
            -IncludeAclPrivilegedUsers:$IncludeAclPrivilegedUsers `
            -IncludeAclPrivilegedComputers:$IncludeAclPrivilegedComputers `
            -IncludeAclPrivilegedGroups:$IncludeAclPrivilegedGroups `
            -IncludeAclAllObjects:$IncludeAclAllObjects `
            -AclSearchBase $AclSearchBase `
            -AclReadDelayMilliseconds $AclReadDelayMilliseconds `
            -AclEffectiveTrusteeLimit $AclEffectiveTrusteeLimit `
            -IncludeGpoPosture:$IncludeGpoPosture `
            -IncludeGpoSysvolAcl:$IncludeGpoSysvolAcl `
            -GpoSearchBase $GpoSearchBase `
            -IncludeAdcsPosture:$IncludeAdcsPosture `
            -IncludeKerberosAuthPosture:$IncludeKerberosAuthPosture `
            -IncludeTrustPosture:$IncludeTrustPosture `
            -IncludeDnsPosture:$IncludeDnsPosture `
            -StaleDays $StaleDays `
            -PasswordAgeDays $PasswordAgeDays `
            -OutputDirectory $OutputDirectory `
            -LogPath $LogPath `
            -Config $cfg `
            -Catalog $catalog `
            -ApprovedExceptionCatalog $approvedExceptionCatalog
    }
}

function Invoke-ADPostureAuditTarget {
    [CmdletBinding()]
    param(
        [string]$Server,
        [switch]$IncludeOptionalGroups,
        [switch]$IncludeAclPosture,
        [switch]$IncludeAclOrganizationalUnits,
        [switch]$IncludeAclGpoContainers,
        [switch]$IncludeAclPrivilegedUsers,
        [switch]$IncludeAclPrivilegedComputers,
        [switch]$IncludeAclPrivilegedGroups,
        [switch]$IncludeAclAllObjects,
        [string[]]$AclSearchBase,
        [ValidateRange(0, 10000)]
        [int]$AclReadDelayMilliseconds = 25,
        [ValidateRange(0, 10000)]
        [int]$AclEffectiveTrusteeLimit = 100,
        [switch]$IncludeGpoPosture,
        [switch]$IncludeGpoSysvolAcl,
        [string[]]$GpoSearchBase,
        [switch]$IncludeAdcsPosture,
        [switch]$IncludeKerberosAuthPosture,
        [switch]$IncludeTrustPosture,
        [switch]$IncludeDnsPosture,
        [int]$StaleDays,
        [int]$PasswordAgeDays,
        [Parameter(Mandatory)]
        [string]$OutputDirectory,
        [string]$LogPath,
        [Parameter(Mandatory)]
        $Config,
        [Parameter(Mandatory)]
        $Catalog,
        [Parameter(Mandatory)]
        $ApprovedExceptionCatalog
    )

    $targetName = if ($Server) { $Server } else { 'current domain context' }
    Write-ADPostureLog -Message "Starting AD Posture audit for $targetName." -Path $LogPath

    $domainParams = @{}
    if ($Server) { $domainParams['Server'] = $Server }

    try {
        $domain = Get-ADDomain @domainParams -ErrorAction Stop
        $forest = Get-ADForest @domainParams -ErrorAction Stop
    }
    catch {
        Write-ADPostureLog -Message "Failed to read AD domain/forest for $targetName. $($_.Exception.Message)" -Level Error -Path $LogPath
        throw "Could not read AD domain/forest for '$targetName'. $($_.Exception.Message)"
    }

    try {
        $dcComputers = Get-ADDomainController -Filter * @domainParams -ErrorAction Stop | ForEach-Object {
            $_.HostName.ToLower()
        }
        Write-ADPostureLog -Message "Resolved $(@($dcComputers).Count) domain controllers for $($domain.DNSRoot)." -Path $LogPath
    }
    catch {
        Write-ADPostureLog -Message "Could not enumerate domain controllers. Domain controller exclusion will be skipped. $($_.Exception.Message)" -Level Warning -Path $LogPath
        Write-Warning "Could not enumerate domain controllers; expected DC exclusions may be incomplete. $($_.Exception.Message)"
        $dcComputers = @()
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $findings = [System.Collections.Generic.List[object]]::new()
    $groupSummaries = [System.Collections.Generic.List[object]]::new()
    $aclTargets = [System.Collections.Generic.List[object]]::new()
    $groupsScanned = 0
    $groupsMissing = [System.Collections.Generic.List[string]]::new()

    if ($IncludeAclPosture) {
        $aclTargets.Add([pscustomobject]@{
            Name = $domain.DNSRoot
            DistinguishedName = $domain.DistinguishedName
            ObjectSid = $domain.DomainSID.Value
            ObjectGuid = $null
            ObjectClass = 'domainDNS'
        })
        $aclTargets.Add([pscustomobject]@{
            Name = 'AdminSDHolder'
            DistinguishedName = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
            ObjectSid = $null
            ObjectGuid = $null
            ObjectClass = 'container'
        })
    }

    foreach ($g in $Catalog.Groups) {
        if ($g.Optional -and -not $IncludeOptionalGroups) { continue }

        $identity = $null
        try {
            $groupFilterName = ConvertTo-ADPostureADFilterLiteral -Value $g.Name
            if ($g.Tier -eq 'Builtin') {
                $identity = Get-ADGroup -Filter "Name -eq '$groupFilterName'" -SearchBase ("CN=Builtin," + $domain.DistinguishedName) @domainParams -ErrorAction Stop
            }
            elseif ($g.Tier -eq 'Forest') {
                $identity = Get-ADGroup -Filter "Name -eq '$groupFilterName'" -SearchBase $forest.PartitionsContainer @domainParams -ErrorAction SilentlyContinue
                if (-not $identity) {
                    $identity = Get-ADGroup -Filter "Name -eq '$groupFilterName'" @domainParams -ErrorAction SilentlyContinue
                }
            }
            else {
                $identity = Get-ADGroup -Filter "Name -eq '$groupFilterName'" @domainParams -ErrorAction SilentlyContinue
            }
        }
        catch {
            $groupsMissing.Add($g.Name)
            Write-ADPostureLog -Message "Sensitive group lookup failed: $($g.Name). $($_.Exception.Message)" -Level Warning -Path $LogPath
            continue
        }

        if (-not $identity) {
            $groupsMissing.Add($g.Name)
            Write-ADPostureLog -Message "Sensitive group not found: $($g.Name)." -Level Warning -Path $LogPath
            continue
        }

        Write-ADPostureLog -Message "Scanning sensitive group: $($g.Name)." -Path $LogPath
        $groupsScanned++

        if ($IncludeAclPosture) {
            $aclTargets.Add([pscustomobject]@{
                Name = $g.Name
                DistinguishedName = $identity.DistinguishedName
                ObjectSid = if ($identity.SID) { $identity.SID.Value } else { $null }
                ObjectGuid = $identity.ObjectGUID
                ObjectClass = 'group'
            })
        }

        try {
            $memberships = Resolve-ADGroupMembershipChain -GroupIdentity $identity.DistinguishedName
        }
        catch {
            $groupsMissing.Add($g.Name)
            Write-ADPostureLog -Message "Could not resolve membership chain for $($g.Name). $($_.Exception.Message)" -Level Warning -Path $LogPath
            Write-Warning "Could not resolve membership chain for '$($g.Name)': $($_.Exception.Message)"
            continue
        }

        $uniqueMemberRisk = @{}
        $uniqueExcludedMembers = @{}
        $uniqueApprovedExceptions = @{}
        $uniqueExpiredExceptions = @{}

        foreach ($row in $memberships) {
            try {
                $enrich = Get-AccountEnrichment -Principal $row.Member -DomainControllerDnsNames $dcComputers -StaleDays $StaleDays -PasswordAgeDays $PasswordAgeDays
            }
            catch {
                $memberName = if ($row.Member -and $row.Member.SamAccountName) { $row.Member.SamAccountName } else { '<unknown>' }
                Write-ADPostureLog -Message "Skipping member $memberName in $($g.Name): enrichment failed. $($_.Exception.Message)" -Level Warning -Path $LogPath
                Write-Warning "Skipping member '$memberName' in '$($g.Name)': $($_.Exception.Message)"
                continue
            }

            if ($Catalog.ExcludedAccounts -contains $enrich.SamAccountName) {
                $enrich.IsExcluded = $true
                $enrich.ExclusionReason = 'Built-in account excluded by policy'
            }
            elseif ($Catalog.ExcludedAccounts -contains $enrich.DisplayName) {
                $enrich.IsExcluded = $true
                $enrich.ExclusionReason = 'Built-in account excluded by policy'
            }
            elseif ($Catalog.ExcludedSids -contains $enrich.ObjectSid) {
                $enrich.IsExcluded = $true
                $enrich.ExclusionReason = 'Well-known AD authority principal excluded by policy'
            }
            foreach ($pat in $Catalog.ExcludedSamPatterns) {
                if ($enrich.SamAccountName -and $enrich.SamAccountName -match $pat) {
                    $enrich.IsExcluded = $true
                    $enrich.ExclusionReason = "Excluded pattern: $pat"
                    break
                }
            }
            $memberKey = if ($enrich.ObjectSid) { "sid:$($enrich.ObjectSid)" } elseif ($enrich.DistinguishedName) { "dn:$($enrich.DistinguishedName.ToLowerInvariant())" } elseif ($enrich.SamAccountName) { "sam:$($enrich.SamAccountName.ToLowerInvariant())" } else { "display:$($enrich.DisplayName)" }

            $approvedException = $null
            if (-not $enrich.IsExcluded) {
                $approvedException = Resolve-ADPostureApprovedException `
                    -SensitiveGroup $g.Name `
                    -Enrichment $enrich `
                    -Catalog $ApprovedExceptionCatalog
            }

            $enrich | Add-Member -NotePropertyName IsApprovedException -NotePropertyValue ($null -ne $approvedException) -Force
            $enrich | Add-Member -NotePropertyName ApprovedExceptionStatus -NotePropertyValue $approvedException.Status -Force
            $enrich | Add-Member -NotePropertyName ApprovedExceptionId -NotePropertyValue $approvedException.Id -Force
            $enrich | Add-Member -NotePropertyName ApprovedExceptionReason -NotePropertyValue $approvedException.Reason -Force
            $enrich | Add-Member -NotePropertyName ApprovedExceptionOwner -NotePropertyValue $approvedException.Owner -Force
            $enrich | Add-Member -NotePropertyName ApprovedExceptionApprovedBy -NotePropertyValue $approvedException.ApprovedBy -Force
            $enrich | Add-Member -NotePropertyName ApprovedExceptionTicket -NotePropertyValue $approvedException.Ticket -Force
            $enrich | Add-Member -NotePropertyName ApprovedExceptionExpiresAt -NotePropertyValue $approvedException.ExpiresAt -Force

            if ($approvedException) {
                if ($approvedException.Status -eq 'Active') {
                    $enrich.IsExcluded = $true
                    $enrich.ExclusionReason = "Approved exception: $($approvedException.Reason)"
                    $uniqueApprovedExceptions[$memberKey] = $true
                }
                elseif ($approvedException.Status -eq 'Expired') {
                    $uniqueExpiredExceptions[$memberKey] = $true
                }
            }

            $riskAssessment = Get-MembershipRiskAssessment -GroupCatalogEntry $g -Enrichment $enrich -NestingDepth $row.NestingDepth -IsDirect:$row.IsDirectMembership
            $risk = $riskAssessment.Score
            $difficulty = Get-RemediationDifficulty -GroupCatalogEntry $g -Enrichment $enrich -RiskScore $risk
            $cleanup = Get-CleanupRecommendation -Enrichment $enrich -GroupName $g.Name -RiskScore $risk
            $privilegeTier = Resolve-ADPostureTier -GroupName $g.Name -AccountType $enrich.AccountType -IsDomainController:$enrich.IsDomainController

            if ($enrich.IsExcluded) {
                $uniqueExcludedMembers[$memberKey] = $true
            }
            else {
                if (-not $uniqueMemberRisk.ContainsKey($memberKey) -or $risk -gt [double]$uniqueMemberRisk[$memberKey]) {
                    $uniqueMemberRisk[$memberKey] = $risk
                }
            }

            $findings.Add([PSCustomObject]@{
                Timestamp                     = (Get-Date).ToString('o')
                Domain                        = $domain.DNSRoot
                SensitiveGroup                = $g.Name
                GroupTier                     = $g.Tier
                PrivilegeTier                 = $privilegeTier.Tier
                PrivilegeTierReason           = $privilegeTier.Reason
                GroupRiskWeight               = $g.RiskWeight
                MemberSam                     = $enrich.SamAccountName
                MemberDisplay                 = $enrich.DisplayName
                MemberDn                      = $enrich.DistinguishedName
                ObjectSid                     = $enrich.ObjectSid
                AccountType                   = $enrich.AccountType
                IsDirect                      = $row.IsDirectMembership
                NestingDepth                  = $row.NestingDepth
                TruncatedNesting              = [bool]$row.TruncatedNesting
                MembershipChain               = $row.ChainDisplay
                AccountStatus                 = $enrich.AccountStatus
                IsEnabled                     = $enrich.IsEnabled
                IsDisabled                    = $enrich.IsDisabled
                IsStale                       = $enrich.IsStale
                IsPasswordStale               = $enrich.IsPasswordStale
                StaleDaysThreshold            = $enrich.StaleDaysThreshold
                DaysSinceLogon                = $enrich.DaysSinceLogon
                LastLogonTimestamp            = if ($enrich.LastLogonDate) { $enrich.LastLogonDate.ToString('o') } else { $null }
                LastLogonUsDate               = $enrich.LastLogonUsDate
                LastLogonDays                 = $enrich.LastLogonDays
                LastLogonDisplay              = $enrich.LastLogonDisplay
                PasswordLastSet               = if ($enrich.PasswordLastSet) { $enrich.PasswordLastSet.ToString('o') } else { $null }
                PasswordLastSetUsDate         = $enrich.PasswordLastSetUsDate
                PasswordLastSetDays           = $enrich.PasswordLastSetDays
                PasswordLastSetDisplay        = $enrich.PasswordLastSetDisplay
                PasswordAgeDaysThreshold      = $enrich.PasswordAgeDaysThreshold
                PasswordNeverExpires          = $enrich.PasswordNeverExpires
                WhenCreated                   = if ($enrich.WhenCreated) { $enrich.WhenCreated.ToString('o') } else { $null }
                WhenCreatedUsDate             = $enrich.WhenCreatedUsDate
                WhenCreatedDays               = $enrich.WhenCreatedDays
                WhenCreatedDisplay            = $enrich.WhenCreatedDisplay
                UserAccountControl            = $enrich.UserAccountControl
                UserAccountControlCategory    = $enrich.UserAccountControlCategory
                UserAccountControlSummary     = $enrich.UserAccountControlSummary
                UserAccountControlNotes       = $enrich.UserAccountControlNotes
                UacRiskBonus                  = $enrich.UacRiskBonus
                UacRemediationDifficulty      = $enrich.UacRemediationDifficulty
                UacPrivilegedConcernCount     = $enrich.UacPrivilegedConcernCount
                UacActiveFlagNames            = $enrich.UacActiveFlagNames
                IsDomainController            = $enrich.IsDomainController
                IsNativeIdentity              = $enrich.IsNativeIdentity
                NativeIdentityCategory        = $enrich.NativeIdentityCategory
                NativeIdentityReason          = $enrich.NativeIdentityReason
                IsRemediableIdentity          = $enrich.IsRemediableIdentity
                IsExcluded                    = $enrich.IsExcluded
                ExclusionReason               = $enrich.ExclusionReason
                IsApprovedException           = $enrich.IsApprovedException
                ApprovedExceptionStatus       = $enrich.ApprovedExceptionStatus
                ApprovedExceptionId           = $enrich.ApprovedExceptionId
                ApprovedExceptionReason       = $enrich.ApprovedExceptionReason
                ApprovedExceptionOwner        = $enrich.ApprovedExceptionOwner
                ApprovedExceptionApprovedBy   = $enrich.ApprovedExceptionApprovedBy
                ApprovedExceptionTicket       = $enrich.ApprovedExceptionTicket
                ApprovedExceptionExpiresAt    = $enrich.ApprovedExceptionExpiresAt
                RiskScore                     = $risk
                ScoreFormula                  = $riskAssessment.Formula
                ScoreModel                    = $riskAssessment.RiskModel
                ScoreComponents               = @($riskAssessment.Components)
                TechnicalRisk                 = $riskAssessment.TechnicalRisk
                AttackTechniques              = @($riskAssessment.AttackTechniques)
                RemediationDifficulty         = $difficulty
                CleanupActions                = ($cleanup -join '; ')
                Notes                         = $g.Notes
            })
        }

        $countedMembers = $uniqueMemberRisk.Count
        $excludedCount = $uniqueExcludedMembers.Count
        $approvedExceptionCount = $uniqueApprovedExceptions.Count
        $expiredExceptionCount = $uniqueExpiredExceptions.Count
        $groupRiskSum = if ($countedMembers -gt 0) { ($uniqueMemberRisk.Values | Measure-Object -Sum).Sum } else { 0 }
        $avgGroupScore = if ($countedMembers -gt 0) { [Math]::Round($groupRiskSum / $countedMembers, 2) } else { 0 }
        $groupAggregate = [Math]::Round($groupRiskSum, 2)
        $groupPrivilegeTier = Resolve-ADPostureTier -GroupName $g.Name -AccountType 'Group'

        $groupSummaries.Add([PSCustomObject]@{
            SensitiveGroup     = $g.Name
            Tier               = $g.Tier
            PrivilegeTier      = $groupPrivilegeTier.Tier
            MemberCount        = $countedMembers
            ExcludedCount      = $excludedCount
            ApprovedExceptionCount = $approvedExceptionCount
            ExpiredExceptionCount = $expiredExceptionCount
            AverageRiskScore   = $avgGroupScore
            AggregateRiskScore = $groupAggregate
            RiskWeight         = $g.RiskWeight
        })
    }

    $activeFindings = $findings | Where-Object { -not $_.IsExcluded -and $_.RiskScore -gt 0 }
    $overall = 0.0
    if ($activeFindings) {
        $overall = [Math]::Round(($activeFindings | Measure-Object -Property RiskScore -Sum).Sum, 2)
    }

    $byDifficulty = @{
        Low    = ($findings | Where-Object { $_.RemediationDifficulty -eq 'Low' -and -not $_.IsExcluded }).Count
        Medium = ($findings | Where-Object { $_.RemediationDifficulty -eq 'Medium' -and -not $_.IsExcluded }).Count
        High   = ($findings | Where-Object { $_.RemediationDifficulty -eq 'High' -and -not $_.IsExcluded }).Count
    }

    $byPrivilegeTier = @{
        'Tier 0' = ($findings | Where-Object { $_.PrivilegeTier -eq 'Tier 0' -and -not $_.IsExcluded }).Count
        'Tier 1' = ($findings | Where-Object { $_.PrivilegeTier -eq 'Tier 1' -and -not $_.IsExcluded }).Count
        'Tier 2' = ($findings | Where-Object { $_.PrivilegeTier -eq 'Tier 2' -and -not $_.IsExcluded }).Count
    }

    $approvedExceptions = @($findings | Where-Object { $_.IsApprovedException -and $_.ApprovedExceptionStatus -eq 'Active' })
    $expiredExceptions = @($findings | Where-Object { $_.IsApprovedException -and $_.ApprovedExceptionStatus -eq 'Expired' })
    $readiness = Get-ADPostureReadinessScorecard -Findings @($findings) -OverallRiskScore $overall -ExpiredExceptionCount @($expiredExceptions).Count
    $aclRiskModel = [pscustomobject]@{ AclFindings = @() }
    if ($IncludeAclPosture) {
        if ($IncludeAclAllObjects -and $AclReadDelayMilliseconds -eq 0) {
            Write-Warning "Broad ACL scan is running without read delay. This can sustain high CPU/I/O pressure on a DC, VM, or jump server; use -AclReadDelayMilliseconds 25 or higher outside disposable labs."
        }

        $aclDiscoveryMessage = "ACL target discovery: expanding requested ACL scopes."
        Write-Host $aclDiscoveryMessage
        Write-ADPostureLog -Message $aclDiscoveryMessage -Path $LogPath
        $aclDiscoveryStarted = Get-Date
        $aclTargets = @(Get-ADPostureAclTargets `
            -BaseTargets @($aclTargets) `
            -Domain $domain `
            -DomainParams $domainParams `
            -IncludeOrganizationalUnits:$IncludeAclOrganizationalUnits `
            -IncludeGpoContainers:$IncludeAclGpoContainers `
            -IncludePrivilegedUsers:$IncludeAclPrivilegedUsers `
            -IncludePrivilegedComputers:$IncludeAclPrivilegedComputers `
            -IncludePrivilegedGroups:$IncludeAclPrivilegedGroups `
            -IncludeAllObjects:$IncludeAclAllObjects `
            -SearchBase $AclSearchBase `
            -LogPath $LogPath)
        $aclDiscoveryElapsed = [int]((Get-Date) - $aclDiscoveryStarted).TotalSeconds
        $aclCollectionMessage = "ACL target discovery complete in ${aclDiscoveryElapsed}s: $(@($aclTargets).Count) targets. Starting ACL reads."
        Write-Host $aclCollectionMessage
        Write-ADPostureLog -Message $aclCollectionMessage -Path $LogPath
        $aclRiskModel = Get-ADPostureAclPosture -Targets @($aclTargets) -Domain $domain.DNSRoot -DomainParams $domainParams -LogPath $LogPath -ReadDelayMilliseconds $AclReadDelayMilliseconds -EffectiveTrusteeLimit $AclEffectiveTrusteeLimit
        $aclRiskModel.AclFindings = @(Add-ADPostureApprovedFindingExceptions -Findings @($aclRiskModel.AclFindings) -Catalog $ApprovedExceptionCatalog)
    }
    $gpoRiskModel = [pscustomobject]@{ Gpos = @(); GpoLinks = @(); GpoFindings = @() }
    if ($IncludeGpoPosture) {
        $gpoRiskModel = Get-ADPostureGpoPosture -Domain $domain -DomainParams $domainParams -SearchBase $GpoSearchBase -LogPath $LogPath
        if (($IncludeAclPosture -and @($aclRiskModel.AclFindings).Count) -or $IncludeGpoSysvolAcl) {
            $gpoRiskModel = ConvertTo-ADPostureGpoRiskModel -Domain $domain.DNSRoot -Gpos @($gpoRiskModel.Gpos) -Links @($gpoRiskModel.GpoLinks) -AclFindings @($aclRiskModel.AclFindings) -IncludeSysvolAcl:$IncludeGpoSysvolAcl
        }
        $gpoRiskModel.GpoFindings = @(Add-ADPostureApprovedFindingExceptions -Findings @($gpoRiskModel.GpoFindings) -Catalog $ApprovedExceptionCatalog)
    }
    $adcsRiskModel = [pscustomobject]@{ AdcsTemplates = @(); AdcsCas = @(); AdcsNtAuth = $null; AdcsFindings = @() }
    if ($IncludeAdcsPosture) {
        $adcsRiskModel = Get-ADPostureAdcsPosture -Domain $domain -DomainParams $domainParams -LogPath $LogPath
        $adcsRiskModel.AdcsFindings = @(Add-ADPostureApprovedFindingExceptions -Findings @($adcsRiskModel.AdcsFindings) -Catalog $ApprovedExceptionCatalog)
    }
    $kerberosAuthRiskModel = [pscustomobject]@{ KerberosAuthPrincipals = @(); KerberosAuthPolicy = $null; KerberosAuthFindings = @() }
    if ($IncludeKerberosAuthPosture) {
        $kerberosAuthRiskModel = Get-ADPostureKerberosAuthPosture -Domain $domain -DomainParams $domainParams -LogPath $LogPath
        $kerberosAuthRiskModel.KerberosAuthFindings = @(Add-ADPostureApprovedFindingExceptions -Findings @($kerberosAuthRiskModel.KerberosAuthFindings) -Catalog $ApprovedExceptionCatalog)
    }
    $trustRiskModel = [pscustomobject]@{ Trusts = @(); TrustFindings = @() }
    if ($IncludeTrustPosture) {
        $trustRiskModel = Get-ADPostureTrustPosture -Domain $domain -DomainParams $domainParams -LogPath $LogPath
        $trustRiskModel.TrustFindings = @(Add-ADPostureApprovedFindingExceptions -Findings @($trustRiskModel.TrustFindings) -Catalog $ApprovedExceptionCatalog)
    }
    $dnsRiskModel = [pscustomobject]@{ DnsZones = @(); DnsRecords = @(); DnsAdmins = @(); DnsFindings = @() }
    if ($IncludeDnsPosture) {
        $dnsRiskModel = Get-ADPostureDnsPosture -Domain $domain -DomainParams $domainParams -AclFindings @($aclRiskModel.AclFindings) -LogPath $LogPath
        $dnsRiskModel.DnsFindings = @(Add-ADPostureApprovedFindingExceptions -Findings @($dnsRiskModel.DnsFindings) -Catalog $ApprovedExceptionCatalog)
    }
    $identityRiskModel = Get-ADPostureIdentityRiskPosture -Domain $domain -DomainParams $domainParams -LogPath $LogPath
    $identityRiskModel.IdentityRiskFindings = @(Add-ADPostureApprovedFindingExceptions -Findings @($identityRiskModel.IdentityRiskFindings) -Catalog $ApprovedExceptionCatalog)

    $objectRiskModel = ConvertTo-ADObjectRiskModel -Findings @($findings) -AclFindings @($aclRiskModel.AclFindings) -KerberosAuthFindings @($kerberosAuthRiskModel.KerberosAuthFindings) -TrustFindings @($trustRiskModel.TrustFindings) -DnsFindings @($dnsRiskModel.DnsFindings) -IdentityRiskFindings @($identityRiskModel.IdentityRiskFindings) -Domain $domain.DNSRoot
    $approvedExceptions = @(
        @($findings) + @($aclRiskModel.AclFindings) + @($gpoRiskModel.GpoFindings) + @($adcsRiskModel.AdcsFindings) + @($kerberosAuthRiskModel.KerberosAuthFindings) + @($trustRiskModel.TrustFindings) + @($dnsRiskModel.DnsFindings) + @($identityRiskModel.IdentityRiskFindings) |
            Where-Object { $_.IsApprovedException -and $_.ApprovedExceptionStatus -eq 'Active' }
    )
    $expiredExceptions = @(
        @($findings) + @($aclRiskModel.AclFindings) + @($gpoRiskModel.GpoFindings) + @($adcsRiskModel.AdcsFindings) + @($kerberosAuthRiskModel.KerberosAuthFindings) + @($trustRiskModel.TrustFindings) + @($dnsRiskModel.DnsFindings) + @($identityRiskModel.IdentityRiskFindings) |
            Where-Object { $_.IsApprovedException -and $_.ApprovedExceptionStatus -eq 'Expired' }
    )
    $allPostureFindings = @($findings) + @($aclRiskModel.AclFindings) + @($gpoRiskModel.GpoFindings) + @($adcsRiskModel.AdcsFindings) + @($kerberosAuthRiskModel.KerberosAuthFindings) + @($trustRiskModel.TrustFindings) + @($dnsRiskModel.DnsFindings) + @($identityRiskModel.IdentityRiskFindings)
    $allActivePostureFindings = @($allPostureFindings | Where-Object { -not $_.IsExcluded -and [double]$_.RiskScore -gt 0 })
    $overall = if ($allActivePostureFindings.Count) { [Math]::Round(($allActivePostureFindings | Measure-Object -Property RiskScore -Sum).Sum, 2) } else { 0.0 }
    $byDifficulty = @{
        Low    = @($allActivePostureFindings | Where-Object { $_.RemediationDifficulty -eq 'Low' -or $_.Severity -eq 'Low' }).Count
        Medium = @($allActivePostureFindings | Where-Object { $_.RemediationDifficulty -eq 'Medium' -or $_.Severity -eq 'Medium' }).Count
        High   = @($allActivePostureFindings | Where-Object { $_.RemediationDifficulty -eq 'High' -or $_.Severity -in @('Critical', 'High') -or [double]$_.RiskScore -ge 5 }).Count
    }
    $byPrivilegeTier = @{
        'Tier 0' = @($allActivePostureFindings | Where-Object { $_.PrivilegeTier -eq 'Tier 0' -or $_.ScopeTier -eq 'Tier 0' -or $_.TargetPrivilegeTier -eq 'Tier 0' }).Count
        'Tier 1' = @($allActivePostureFindings | Where-Object { $_.PrivilegeTier -eq 'Tier 1' -or $_.ScopeTier -eq 'Tier 1' -or $_.TargetPrivilegeTier -eq 'Tier 1' }).Count
        'Tier 2' = @($allActivePostureFindings | Where-Object { $_.PrivilegeTier -eq 'Tier 2' -or $_.ScopeTier -eq 'Tier 2' -or $_.TargetPrivilegeTier -eq 'Tier 2' }).Count
    }
    $readiness = Get-ADPostureReadinessScorecard -Findings @($findings) -KerberosAuthFindings @($kerberosAuthRiskModel.KerberosAuthFindings) -TrustFindings @($trustRiskModel.TrustFindings) -DnsFindings @($dnsRiskModel.DnsFindings) -OverallRiskScore $overall -ExpiredExceptionCount @($expiredExceptions).Count

    $snapshot = [PSCustomObject]@{
        SchemaVersion        = '1.1'
        Sensitivity          = 'Sensitive - contains AD posture topology, DNs, SIDs, account metadata, and remediation context'
        AuditId              = [guid]::NewGuid().ToString()
        Timestamp            = (Get-Date).ToString('o')
        Domain               = $domain.DNSRoot
        Forest               = $forest.Name
        DomainMode           = $domain.DomainMode
        ForestMode           = $forest.ForestMode
        OverallRiskScore     = $overall
        TargetScore          = 0
        GroupsScanned        = $groupsScanned
        GroupsMissing        = @($groupsMissing)
        FindingsCount        = $findings.Count
        ActionableCount      = @($activeFindings).Count
        ApprovedExceptionCount = @($approvedExceptions).Count
        ExpiredExceptionCount = @($expiredExceptions).Count
        ReadinessScorecard = $readiness
        RemediationBreakdown = $byDifficulty
        TierBreakdown        = $byPrivilegeTier
        GroupSummaries       = @($groupSummaries)
        Findings             = @($findings)
        AclFindings          = @($aclRiskModel.AclFindings)
        Gpos                 = @($gpoRiskModel.Gpos)
        GpoLinks             = @($gpoRiskModel.GpoLinks)
        GpoFindings          = @($gpoRiskModel.GpoFindings)
        AdcsTemplates        = @($adcsRiskModel.AdcsTemplates)
        AdcsCas              = @($adcsRiskModel.AdcsCas)
        AdcsNtAuth           = $adcsRiskModel.AdcsNtAuth
        AdcsFindings         = @($adcsRiskModel.AdcsFindings)
        KerberosAuthPrincipals = @($kerberosAuthRiskModel.KerberosAuthPrincipals)
        KerberosAuthPolicy   = $kerberosAuthRiskModel.KerberosAuthPolicy
        KerberosAuthFindings = @($kerberosAuthRiskModel.KerberosAuthFindings)
        Trusts               = @($trustRiskModel.Trusts)
        TrustFindings        = @($trustRiskModel.TrustFindings)
        DnsZones             = @($dnsRiskModel.DnsZones)
        DnsRecords           = @($dnsRiskModel.DnsRecords)
        DnsAdmins            = @($dnsRiskModel.DnsAdmins)
        DnsFindings          = @($dnsRiskModel.DnsFindings)
        IdentityRiskFindings = @($identityRiskModel.IdentityRiskFindings)
        Objects              = @($objectRiskModel.Objects)
        ObjectEvidence       = @($objectRiskModel.ObjectEvidence)
        ObjectRelationships  = @($objectRiskModel.ObjectRelationships)
    }

    $dataDir = $Config.DataPath
    if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir -Force -ErrorAction Stop | Out-Null }

    $jsonPath = Join-Path $dataDir "snapshot-$timestamp.json"
    $latestSnapshotPath = Join-Path $dataDir 'latest-snapshot.json'
    try {
        $outputProgressId = 7400
        $outputStarted = Get-Date
        Write-Progress -Id $outputProgressId -Activity 'Writing AD Posture outputs' -Status 'Step 1/3: converting primary snapshot to JSON.' -PercentComplete 0
        Write-Host 'Writing primary snapshot JSON...'
        $snapshotJson = $snapshot | ConvertTo-Json -Depth 8
        Write-ADPostureAtomicTextFile -Path $jsonPath -Value $snapshotJson
        Write-ADPostureAtomicTextFile -Path $latestSnapshotPath -Value $snapshotJson
        Write-Progress -Id $outputProgressId -Activity 'Writing AD Posture outputs' -Status 'Step 2/3: applying file protection and integrity sidecar.' -PercentComplete 33
        Write-Host 'Protecting snapshot and writing SHA-256 sidecar...'
        Protect-ADPostureSensitiveFile -Path $jsonPath
        [void](Write-ADPostureFileHashSidecar -Path $jsonPath)
        Protect-ADPostureSensitiveFile -Path $latestSnapshotPath
        [void](Write-ADPostureFileHashSidecar -Path $latestSnapshotPath)

        $reportBase = Join-Path $OutputDirectory "audit-$timestamp"
        $elapsed = [int]((Get-Date) - $outputStarted).TotalSeconds
        Write-Progress -Id $outputProgressId -Activity 'Writing AD Posture outputs' -Status "Step 3/3: exporting report files. Elapsed ${elapsed}s." -PercentComplete 66
        Write-Host 'Exporting report files...'
        Export-ADPostureReport -Snapshot $snapshot -OutputBasePath $reportBase
        Write-Progress -Id $outputProgressId -Activity 'Writing AD Posture outputs' -Completed
    }
    catch {
        Write-ADPostureLog -Message "Failed to write audit outputs for $($domain.DNSRoot). $($_.Exception.Message)" -Level Error -Path $LogPath
        throw
    }

    Write-ADPostureLog -Message "Audit completed for $($domain.DNSRoot). Exposure score: $overall. Actionable findings: $($snapshot.ActionableCount)." -Path $LogPath
    Write-Host "Audit completed." -ForegroundColor Green
    Write-Host "  Domain: $($domain.DNSRoot)"
    Write-Host "  Exposure score (0=ideal): $overall"
    Write-Host "  Actionable findings: $($snapshot.ActionableCount)"
    Write-Host "  Snapshot: $jsonPath"
    Write-Host "  Latest snapshot: $latestSnapshotPath"
    Write-Host "  Reports: $reportBase.*"

    return $snapshot
}
